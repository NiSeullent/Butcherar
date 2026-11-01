/*
 * 고깃ZIP - ARJ reader (ARJ 0.x .. ARJ32 3.x)
 *
 *   main header + file headers (60 EA, basic header CRC-32, extended headers),
 *   methods 0 (store), 1-3 (LZH, 26 KiB window), 4 (fastest), data CRC-32,
 *   DOS or Unix times/attributes by host OS, OEM or ANSI names, UNIX special
 *   files (symlinks), SFX stubs, multi-volume sets (name.arj, .a01, .a02 ...)
 *   with files split across volumes, and "garbled" (password) files using the
 *   standard XOR scheme. GOST encryption is reported as unsupported.
 */
#include "arc.h"
#include "crc32.h"
#include "lzh.h"

#define ARJ_HDR_MAX   2600u
#define ARJ_FIRST_MIN 30u
#define ARJ_MAX_VOLS  1000u

enum { F_GARBLED = 1, F_ANSICP = 2, F_VOLUME = 4, F_EXTFILE = 8 };
enum { T_BINARY = 0, T_TEXT = 1, T_COMMENT = 2, T_DIR = 3, T_LABEL = 4, T_CHAPTER = 5, T_UXSPEC = 6 };
enum { OS_DOS = 0, OS_UNIX = 2, OS_NEXT = 8, OS_WIN95 = 10, OS_WIN32 = 11 };

typedef struct {
    u64 off, csize, usize;
    u32 crc;
    u16 vol;                   /* 0 = the archive itself, k = a->vols[k-1] */
    u8 method;
    u8 garbled;
    u8 modifier;               /* garble password modifier */
    u8 more;                   /* continued on the next volume */
} arj_part;

typedef struct {
    arj_part *p;
    u32 n, cap;
    int enc_ver;               /* main header encryption version */
} arj_priv;

/* ---------------- header parsing ---------------- */

typedef struct {
    u8 h[ARJ_HDR_MAX + 8];
    u32 size;                  /* basic header size */
    u64 data;                  /* offset after the extended headers */
    u8 link[512];              /* UXSPECIAL symlink target */
    u32 link_len;
} arj_hdr;

/* Read the header at off. Returns GZ_OK, 1 at the end marker, or an error. */
static int read_header(gz_src *s, u64 off, arj_hdr *hd)
{
    u8 b[4];
    int r = gz_src_read_exact(s, off, b, 4);
    if (r) return r;
    if (b[0] != 0x60 || b[1] != 0xEA) return GZ_E_FORMAT;
    u32 size = rd16(b + 2);
    if (size == 0) return 1;
    if (size > ARJ_HDR_MAX || size < ARJ_FIRST_MIN) return GZ_E_FORMAT;
    r = gz_src_read_exact(s, off + 4, hd->h, size + 4);
    if (r) return r;
    if (gz_crc32(0, hd->h, size) != rd32(hd->h + size)) return GZ_E_FORMAT;
    if (hd->h[0] < ARJ_FIRST_MIN || hd->h[0] > size) return GZ_E_FORMAT;
    hd->size = size;
    hd->link_len = 0;
    /* extended headers: size16, data, CRC-32 ... size16 = 0 */
    u64 p = off + 4 + size + 4;
    for (u32 k = 0; k < 64; k++) {
        if (gz_src_read_exact(s, p, b, 2)) return GZ_E_TRUNC;
        u32 es = rd16(b);
        p += 2;
        if (!es) { hd->data = p; return GZ_OK; }
        /* 'U' UXSPECIAL: tag, continuation flag, block: id<<5 | size (31 = 16-bit size
         * follows); only symlink targets (id 2) are used, larger blocks are skipped */
        u8 x[3 + 2 + 512 + 4];
        if (es + 4 <= sizeof x && !hd->link_len) {
            if (gz_src_read_exact(s, p, x, es + 4)) return GZ_E_TRUNC;
            if (x[0] == 'U' && es >= 3 && (x[2] >> 5) == 2 && gz_crc32(0, x, es) == rd32(x + es)) {
                u32 bl = x[2] & 31, st = 3;
                if (bl == 31 && es >= 5) { bl = rd16(x + 3); st = 5; }
                if (bl < sizeof hd->link && st + bl <= es) {
                    __builtin_memcpy(hd->link, x + st, bl);
                    hd->link_len = bl;
                }
            }
        }
        p += (u64)es + 4;
        if (p > s->size) return GZ_E_TRUNC;
    }
    return GZ_E_FORMAT;
}

static u32 cstrlen(const u8 *p, u32 max)
{
    u32 n = 0;
    while (n < max && p[n]) n++;
    return n;
}

static int is_main_header(const u8 *b, u32 n)
{
    if (n < 4 + ARJ_FIRST_MIN + 4 || b[0] != 0x60 || b[1] != 0xEA) return 0;
    u32 size = rd16(b + 2);
    if (size < ARJ_FIRST_MIN || size > ARJ_HDR_MAX || 4 + size + 4 > n) return 0;
    if (b[4 + 6] != T_COMMENT || b[4] < ARJ_FIRST_MIN || b[4] > size) return 0;
    return gz_crc32(0, b + 4, size) == rd32(b + 4 + size);
}

#define SFX_SCAN (256u << 10)            /* stub sizes searched (ARJ32 SFX stubs exceed 64 KiB) */

/* SFX: the archive follows an executable stub; find the first main header with
 * a valid CRC that starts in the first SFX_SCAN bytes. 1 and *pos, 0, or GZ_E_NOMEM. */
static int sfx_find(gz_src *s, u64 *pos)
{
    u32 max = s->size < SFX_SCAN + ARJ_HDR_MAX + 8 ? (u32)s->size : SFX_SCAN + ARJ_HDR_MAX + 8;
    if (max < 4 + ARJ_FIRST_MIN + 4) return 0;
    u8 *b = (u8 *)gz_alloc(max);
    if (!b) return GZ_E_NOMEM;
    int found = 0;
    if (!gz_src_read_exact(s, 0, b, max) && b[0] == 'M' && b[1] == 'Z') {
        for (u32 i = 2; i < SFX_SCAN && i + 4 + ARJ_FIRST_MIN + 4 <= max; i++)
            if (b[i] == 0x60 && b[i + 1] == 0xEA && is_main_header(b + i, max - i)) { *pos = i; found = 1; break; }
    }
    gz_free(b);
    return found;
}

static int arj_probe(gz_src *s, const u8 *h, u32 n)
{
    if (is_main_header(h, n)) return 95;
    u64 pos;
    return n >= 2 && h[0] == 'M' && h[1] == 'Z' && sfx_find(s, &pos) == 1 ? 70 : 0;
}

static int part_add(arj_priv *pv, const arj_part *p)
{
    if (pv->n == pv->cap) {
        if (pv->cap >= (1u << 24)) return GZ_E_LIMIT;
        u32 nc = pv->cap ? pv->cap * 2 : 64;
        arj_part *np = (arj_part *)gz_realloc(pv->p, (size_t)nc * sizeof(arj_part));
        if (!np) return GZ_E_NOMEM;
        pv->p = np;
        pv->cap = nc;
    }
    pv->p[pv->n++] = *p;
    return GZ_OK;
}

/* name of volume k (1, 2, ...): base.arj -> base.a01 ... base.a99, base.100 ... */
static gzch *volume_name(const gzch *fn, u32 k)
{
    size_t n = gz_wcslen(fn);
    const gzch *dot = gz_wcsrchr(fn, '.');
    const gzch *s1 = gz_wcsrchr(fn, '/'), *s2 = gz_wcsrchr(fn, '\\');
    if (!dot || (s1 && dot < s1) || (s2 && dot < s2)) dot = fn + n;
    size_t bl = (size_t)(dot - fn);
    gzch *v = (gzch *)gz_alloc((bl + 6) * sizeof(gzch));
    if (!v) return 0;
    __builtin_memcpy(v, fn, bl * sizeof(gzch));
    gzch *p = v + bl;
    *p++ = '.';
    int upper = dot[0] && dot[1] >= 'A' && dot[1] <= 'Z';
    if (k < 100) { *p++ = upper ? 'A' : 'a'; *p++ = (gzch)('0' + k / 10); *p++ = (gzch)('0' + k % 10); }
    else { *p++ = (gzch)('0' + k / 100 % 10); *p++ = (gzch)('0' + k / 10 % 10); *p++ = (gzch)('0' + k % 10); }
    *p = 0;
    return v;
}

/* volume number of an opened name: .a01 -> 1, .123 -> 123, anything else 0 */
static u32 volume_index(const gzch *fn)
{
    size_t n = gz_wcslen(fn);
    if (n < 4 || fn[n - 4] != '.') return 0;
    const gzch *e = fn + n - 3;
    if (e[1] < '0' || e[1] > '9' || e[2] < '0' || e[2] > '9') return 0;
    u32 v = (u32)(e[1] - '0') * 10 + (u32)(e[2] - '0');
    if (e[0] == 'a' || e[0] == 'A') return v;
    return e[0] >= '0' && e[0] <= '9' ? (u32)(e[0] - '0') * 100 + v : 0;
}

static int arj_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    u8 head[4096];
    u32 hn = s->size < sizeof head ? (u32)s->size : (u32)sizeof head;
    int r = gz_src_read_exact(s, 0, head, hn);
    if (r) return r;
    u64 start = 0;
    if (!is_main_header(head, hn)) {
        r = sfx_find(s, &start);
        if (r != 1) return r ? r : GZ_E_FORMAT;
        a->sfx_shift = start;
    }
    arj_priv *pv = (arj_priv *)gz_alloc(sizeof(arj_priv));
    if (!pv) return GZ_E_NOMEM;
    a->priv = pv;
    arj_hdr *hd = (arj_hdr *)gz_alloc(sizeof(arj_hdr));
    if (!hd) return GZ_E_NOMEM;

    gz_src *vs = s;
    u32 vol = 0;
    u64 pos = start;
    i32 cont = -1;               /* entry continued on the next volume */
    int first_vol_ok = 0;
    for (;;) {
        /* main header of this volume */
        r = read_header(vs, pos, hd);
        if (r) { if (r == 1) r = GZ_E_FORMAT; break; }
        const u8 *m = hd->h;
        int host = m[3];
        u32 mflags = m[4];
        if (!vol) {
            pv->enc_ver = m[28] & 15;
            u32 nl = cstrlen(m + m[0], hd->size - m[0]);
            u32 cl = m[0] + nl + 1 < hd->size ? cstrlen(m + m[0] + nl + 1, hd->size - m[0] - nl - 1) : 0;
            if (cl) {
                a->comment_raw = (u8 *)gz_alloc(cl);
                if (a->comment_raw) {
                    __builtin_memcpy(a->comment_raw, m + m[0] + nl + 1, cl);
                    a->comment_len = cl;
                    a->comment_enc = (host == OS_DOS || host == OS_WIN95 || host == OS_WIN32) &&
                                     !(mflags & F_ANSICP) ? GZ_NE_OEM : GZ_NE_LEGACY;
                }
            }
        }
        int ansi = (mflags & F_ANSICP) != 0;
        pos = hd->data;
        int more_vols = (mflags & F_VOLUME) != 0;
        /* file headers */
        for (;;) {
            if (gz_cancelled(c)) { gz_free(hd); return GZ_E_CANCEL; }
            r = read_header(vs, pos, hd);
            if (r == 1) { r = GZ_OK; break; }
            if (r) break;
            const u8 *h = hd->h;
            u32 fhs = h[0];
            u32 nl = cstrlen(h + fhs, hd->size - fhs);
            host = h[3];
            u32 fl = h[4], method = h[5], type = h[6];
            u64 csize = rd32(h + 12), usize = rd32(h + 16);
            u64 data = hd->data;
            pos = data + csize;
            if (data + csize > vs->size) { r = GZ_E_TRUNC; break; }
            if (type == T_COMMENT || type == T_LABEL || type == T_CHAPTER) continue;
            arj_part pt = { data, csize, usize, rd32(h + 20), (u16)vol, (u8)method,
                            (u8)((fl & F_GARBLED) != 0), h[7], (u8)((fl & F_VOLUME) != 0) };
            if ((fl & F_EXTFILE) && cont >= 0 && a->e[cont].aux32 + a->e[cont].flags == pv->n &&
                a->e[cont].flags < 0xffff) {
                /* continuation of a file split across volumes (its parts stay contiguous) */
                if ((r = part_add(pv, &pt))) break;
                gz_entry *ce = &a->e[cont];
                ce->usize += usize;
                ce->csize += csize;
                ce->flags++;
                if (!(fl & F_VOLUME)) cont = -1;
                continue;
            }
            if (fl & F_EXTFILE) continue;        /* tail of a file whose start is missing */
            int ne = (host == OS_DOS || host == OS_WIN95 || host == OS_WIN32) && !ansi ? GZ_NE_OEM : GZ_NE_LEGACY;
            gz_entry *e;
            if ((r = gz_arc_add_named(a, h + fhs, nl, ne, &e))) break;
            e->usize = usize;
            e->csize = csize;
            e->off = data;
            e->aux32 = pv->n;                    /* first part */
            e->flags = 1;                        /* number of parts */
            e->method = (u16)method;
            e->crc = pt.crc;
            e->has_crc = 1;
            e->enc = (fl & F_GARBLED) ? GZ_ENC_OTHER : GZ_ENC_NONE;
            u32 mode = rd16(h + 26);
            if (host == OS_UNIX || host == OS_NEXT) {
                e->mtime = gz_unix_to_filetime((i64)rd32(h + 8));
                e->mtime_kind = GZ_MT_FILETIME;
                u32 kind = mode >> 12 & 15;
                e->unix_mode = (mode & 07777) | (kind == 2 ? 0040000u : kind == 4 ? 0120000u : 0100000u);
                if (!(mode & 0200)) e->attr |= 1;
                if (kind == 2) e->is_dir = 1;
            } else {
                e->mtime = rd32(h + 8);
                e->mtime_kind = GZ_MT_DOS;
                e->attr = mode & 0x27;
                if (mode & 0x10) e->is_dir = 1;
            }
            if (type == T_DIR) e->is_dir = 1;
            if (type == T_UXSPEC) {
                if (hd->link_len) {
                    u32 lo;
                    if ((r = gz_arc_raw_append(a, hd->link, hd->link_len, &lo))) break;
                    e = &a->e[a->n - 1];
                    e->link_off = lo;
                    e->link_len = hd->link_len;
                    e->is_link = 1;
                    e->unix_mode = (e->unix_mode & 07777) | 0120000u;
                } else {
                    e->is_aux = 1;               /* fifo / device: nothing to extract */
                }
            }
            if (e->is_dir) { e->attr |= 0x10; e->usize = e->csize = 0; e->has_crc = 0; }
            if ((r = part_add(pv, &pt))) break;
            cont = (fl & F_VOLUME) ? (i32)(a->n - 1) : -1;
        }
        if (r) break;
        if (!vol) first_vol_ok = 1;
        if (!more_vols || !o->open_volume || !o->file_name) break;
        /* next volume */
        /* opened at a later volume (name.a05): continue from its number */
        u32 vnum = volume_index(o->file_name) + vol + 1;
        if (vnum >= ARJ_MAX_VOLS) break;
        gzch *vn = volume_name(o->file_name, vnum);
        if (!vn) { r = GZ_E_NOMEM; break; }
        gz_src *nv = 0;
        int vr = o->open_volume(o->user, vn, &nv);
        gz_free(vn);
        if (vr || !nv) break;                     /* missing volume: listed parts stay */
        gz_src **nvs = (gz_src **)gz_realloc(a->vols, (size_t)(a->nvols + 1) * sizeof(gz_src *));
        if (!nvs) { gz_src_free(nv); r = GZ_E_NOMEM; break; }
        a->vols = nvs;
        a->vols[a->nvols++] = nv;
        vs = nv;
        vol++;
        /* volumes may be SFX too, but normally start with the main header */
        u8 vb[4096];
        u32 vn2 = nv->size < sizeof vb ? (u32)nv->size : (u32)sizeof vb;
        pos = 0;
        if (gz_src_read_exact(nv, 0, vb, vn2) || !is_main_header(vb, vn2)) break;
    }
    gz_free(hd);
    if (!first_vol_ok && a->n == 0) return r ? r : GZ_E_FORMAT;
    if (r == GZ_E_NOMEM || r == GZ_E_CANCEL) return r;
    a->win_names = 1;
    return GZ_OK;    /* a damaged tail keeps the entries found so far */
}

static void arj_close(gz_archive *a)
{
    arj_priv *pv = (arj_priv *)a->priv;
    if (pv) gz_free(pv->p);
    gz_free(pv);
    a->priv = 0;
}

/* ---------------- extraction ---------------- */

typedef struct {
    gz_range_reader rd;          /* first: gz_range_read casts the ctx */
    const u8 *pw;
    u32 pwn, pwi;
    u8 mod;
    gz_out *out;
    u32 crc;
    u64 n;
} arj_io;

static int aio_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    arj_io *x = (arj_io *)ctx;
    int r = gz_range_read(&x->rd, buf, cap, got);
    if (r || !x->pw) return r;
    /* garble: XOR with (password byte + modifier), password repeats */
    u32 i = x->pwi;
    for (u32 k = 0; k < *got; k++) {
        buf[k] ^= (u8)(x->pw[i] + x->mod);
        if (++i == x->pwn) i = 0;
    }
    x->pwi = i;
    return GZ_OK;
}

static int aio_write(void *ctx, const u8 *p, size_t n)
{
    arj_io *x = (arj_io *)ctx;
    x->crc = gz_crc32(x->crc, p, n);
    x->n += n;
    return x->out ? x->out->write(x->out, p, n) : GZ_OK;
}


/* decode one part into out (NULL = only check the CRC) */
static int part_decode(gz_archive *a, gz_src *s, const arj_part *p, const u8 *pw, u32 pwn,
                       gz_out *out, gz_ctx *c)
{
    gz_src *src = p->vol ? (p->vol <= a->nvols ? a->vols[p->vol - 1] : 0) : s;
    if (!src) return GZ_E_VOLUME;
    if (p->off + p->csize > src->size) return GZ_E_TRUNC;
    arj_io x;
    __builtin_memset(&x, 0, sizeof x);
    x.rd.src = src;
    x.rd.pos = p->off;
    x.rd.end = p->off + p->csize;
    x.rd.cancel = c->cancel;
    if (p->garbled) { x.pw = pw; x.pwn = pwn; x.mod = p->modifier; }
    x.out = out;
    gz_stream_io io = { aio_read, aio_write, &x };
    int st;
    switch (p->method) {
    case 0: {
        u8 *buf = gz_ctx_buffer(c, 256u << 10);
        if (!buf) return GZ_E_NOMEM;
        st = GZ_OK;
        for (;;) {
            u32 got = 0;
            st = aio_read(&x, buf, 256u << 10, &got);
            if (st || !got) break;
            if ((st = aio_write(&x, buf, got))) break;
        }
        if (!st && x.n != p->usize) st = GZ_E_TRUNC;
        break;
    }
    case 1: case 2: case 3: case 4: {
        gz_lzh_dec *d = (gz_lzh_dec *)gz_ctx_slot(c, GZ_SLOT_MISC4, gz_lzh_slot_new, gz_lzh_slot_free);
        if (!d) return GZ_E_NOMEM;
        st = gz_lzh_decode(d, &io, p->usize, p->method == 4 ? GZ_LZH_ARJ4 : GZ_LZH_ARJ);
        break;
    }
    case 8: case 9:              /* no data */
        st = GZ_OK;
        break;
    default:
        return GZ_E_METHOD;
    }
    if (!st && p->method < 8 && x.crc != p->crc) st = GZ_E_CRC;
    /* garbled data has no password check: a wrong one shows up as bad data */
    if (p->garbled && (st == GZ_E_CRC || st == GZ_E_DATA || st == GZ_E_TRUNC)) st = GZ_E_PASSWORD;
    return st;
}

/* password byte strings to try: OEM (DOS ARJ), ANSI (ARJ32 -hy), UTF-8 (ARJ for Unix) */
typedef struct { u8 b[3][512]; u32 n[3]; int count; } arj_pw;

static void pw_candidates(const gzch *pw, arj_pw *ps)
{
    ps->count = 0;
    if (!pw) return;
    size_t wn = gz_wcslen(pw);
    if (wn > 160) wn = 160;
    int cps[2] = { gz_plat_oemcp(), gz_plat_acp() };
    for (int k = 0; k < 3; k++) {
        int n = k < 2 ? gz_plat_wc2mb(cps[k], pw, (int)wn, ps->b[ps->count], 480)
                      : gz_utf16_to_utf8(pw, wn, ps->b[ps->count]);
        if (n <= 0) continue;
        int dup = 0;
        for (int j = 0; j < ps->count; j++)
            if (ps->n[j] == (u32)n && !__builtin_memcmp(ps->b[j], ps->b[ps->count], (size_t)n)) dup = 1;
        if (!dup) ps->n[ps->count++] = (u32)n;
    }
}

static int null_open(gz_out *o, u32 idx) { (void)o; (void)idx; return GZ_OK; }
static int null_write(gz_out *o, const u8 *p, size_t n) { (void)o; (void)p; (void)n; return GZ_OK; }
static int null_close(gz_out *o, u32 idx, int st) { (void)o; (void)idx; (void)st; return GZ_OK; }

/* pick the password encoding that decodes the first part (garbled entries) */
static int find_password(gz_archive *a, gz_src *s, const gz_entry *e, gz_ctx *c, arj_pw *ps, int *pick)
{
    arj_priv *pv = (arj_priv *)a->priv;
    if (pv->enc_ver > 1) return GZ_E_METHOD;          /* GOST */
    pw_candidates(c->password, ps);
    if (!ps->count) return GZ_E_PASSWORD;
    *pick = 0;
    if (ps->count == 1) return GZ_OK;
    gz_out nul = { null_open, null_write, null_close, 0 };
    for (int k = 0; k < ps->count; k++) {
        int r = part_decode(a, s, &pv->p[e->aux32], ps->b[k], ps->n[k], &nul, c);
        if (r == GZ_OK) { *pick = k; return GZ_OK; }
        if (r != GZ_E_PASSWORD && r != GZ_E_DATA && r != GZ_E_TRUNC) return r;
    }
    return GZ_E_PASSWORD;
}

static int arj_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    arj_priv *pv = (arj_priv *)a->priv;
    gz_entry *e = &a->e[idx];
    arj_pw *ps = 0;
    int pick = 0;
    if (e->enc && !e->is_dir && !e->is_link && e->usize) {
        ps = (arj_pw *)gz_alloc(sizeof(arj_pw));
        if (!ps) return GZ_E_NOMEM;
        int r = find_password(a, s, e, c, ps, &pick);
        if (r) { gz_free(ps); return r; }
    }
    int r = out->open(out, idx);
    if (r) { gz_free(ps); return r; }
    int st = GZ_OK;
    if (!e->is_dir && !e->is_link && !e->is_aux) {
        for (u32 k = 0; k < e->flags && !st; k++) {
            if (gz_cancelled(c)) { st = GZ_E_CANCEL; break; }
            st = part_decode(a, s, &pv->p[e->aux32 + k], ps ? ps->b[pick] : 0, ps ? ps->n[pick] : 0, out, c);
        }
        /* the last part says the file goes on, but the next volume was not found */
        if (!st && e->flags && pv->p[e->aux32 + e->flags - 1].more) st = GZ_E_VOLUME;
    }
    gz_free(ps);
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static int arj_check_password(gz_archive *a, gz_src *s, u32 idx, gz_ctx *c)
{
    gz_entry *e = &a->e[idx];
    if (!e->enc || e->is_dir || e->is_link || !e->usize) return GZ_OK;
    arj_pw *ps = (arj_pw *)gz_alloc(sizeof(arj_pw));
    if (!ps) return GZ_E_NOMEM;
    int pick = 0, r = find_password(a, s, e, c, ps, &pick);
    if (!r && ps->count == 1) {
        /* single candidate: verify it on the first part */
        gz_out nul = { null_open, null_write, null_close, 0 };
        r = part_decode(a, s, &((arj_priv *)a->priv)->p[e->aux32], ps->b[0], ps->n[0], &nul, c);
        if (r == GZ_E_DATA || r == GZ_E_TRUNC || r == GZ_E_CRC) r = GZ_E_PASSWORD;
    }
    gz_free(ps);
    return r;
}

static void arj_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    const char *m;
    switch (e->method) {
    case 0: m = "Store"; break;
    case 1: m = "ARJ:1"; break;
    case 2: m = "ARJ:2"; break;
    case 3: m = "ARJ:3"; break;
    case 4: m = "ARJ:4"; break;
    default: m = "?"; break;
    }
    const char *enc = !e->enc ? "" : ((arj_priv *)a->priv)->enc_ver > 1 ? " GOST" : " Garble";
    u32 i = 0;
    for (; *m && i + 1 < cap; m++) buf[i++] = *m;
    for (; *enc && i + 1 < cap; enc++) buf[i++] = *enc;
    if (cap) buf[i] = 0;
}

/* stored, unencrypted, single-part files can be read in place */
static gz_src *arj_view(gz_archive *a, gz_src *s, u32 idx)
{
    gz_entry *e = &a->e[idx];
    if (e->is_dir || e->enc || e->method != 0 || e->flags != 1) return 0;
    const arj_part *p = &((arj_priv *)a->priv)->p[e->aux32];
    if (p->vol || p->off + p->usize > s->size) return 0;
    return gz_src_sub(s, p->off, p->usize);
}

GZ_FORMAT(gz_fmt_arj)
const gz_format gz_fmt_arj = {
    "ARJ", "arj",
    0, arj_probe, arj_open, arj_close, arj_extract, 0, arj_check_password, arj_method, arj_view, 0
};
