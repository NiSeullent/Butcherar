/*
 * 고깃ZIP - Microsoft Cabinet (CAB) reader
 *
 *   Header reserve fields, folders of type None / MSZIP / Quantum / LZX,
 *   CFDATA checksums, files continued across cabinets
 *   (multi-cabinet sets are followed through o->open_volume with the previous /
 *   next cabinet names; folders split between cabinets are merged), CABs inside
 *   executables (IExpress / SFX installers: "MSCF" found in the first 16 MiB).
 *
 * CAB has no per-file checksum; integrity comes from the CFDATA checksums and
 * the exact block sizes. Folders are solid streams: a->solid = 1 and
 * extract_solid decodes each folder holding selected files once, in order.
 */
#include "arc.h"
#include "lzx.h"
#include "quantum.h"

#define CAB_SIG      0x4643534du      /* "MSCF" */
#define CAB_HDR      36u
#define SCAN_LIMIT   (16u << 20)      /* SFX: search the signature this far */
#define MAX_CABS     1024u
#define CF_PREV      1u
#define CF_NEXT      2u
#define CF_RESERVE   4u
#define IF_CONT_PREV 0xFFFDu
#define IF_CONT_NEXT 0xFFFEu
#define IF_CONT_BOTH 0xFFFFu
#define FOLD_MISSING 0xFFFFFFFFu      /* data starts in a cabinet we do not have */
#define FOLD_BAD     0xFFFFFFFEu      /* folder index out of range               */

enum { M_NONE = 0, M_MSZIP = 1, M_QUANTUM = 2, M_LZX = 3 };

typedef struct {
    u32 vol;          /* 0 = the archive's own source, else a->vols[vol - 1] */
    u64 base;         /* offset of the cabinet in that source                */
    u8 res_data;      /* per-CFDATA reserve bytes                            */
} cab_cab;

typedef struct {
    u32 cab;          /* index in cab_priv.cabs */
    u64 data;         /* absolute offset of the first CFDATA                 */
    u32 nblocks;
} cab_seg;

typedef struct {
    u16 type;         /* typeCompress                                        */
    u8 missing_next;  /* continues in a cabinet that could not be opened     */
    u32 seg0, nseg;
    u64 csize;        /* compressed span (statistics)                        */
} cab_fold;

typedef struct {
    cab_cab *cabs;  u32 ncab;
    cab_fold *fold; u32 nfold, capfold;
    cab_seg *seg;   u32 nseg, capseg;
    u32 *order;     /* entry indices sorted by (folder, offset)               */
} cab_priv;

typedef struct {
    u32 size, coff_files;
    u16 nfold, nfiles, flags, setid, icab;
    u8 res_fold, res_data;
    u32 fold_off;     /* first CFFOLDER, relative to the cabinet start         */
    u8 prev[257], next[257];
} cab_hdr;

static gz_src *cab_src(gz_archive *a, gz_src *s, const cab_cab *cb)
{
    return cb->vol ? a->vols[cb->vol - 1] : s;
}

/* NUL-terminated string of at most 255 bytes at p[0..n): length+1 or 0 */
static u32 cstr(const u8 *p, u32 n, u8 *out)
{
    for (u32 i = 0; i < n && i < 256; i++) {
        out[i] = p[i];
        if (!p[i]) return i + 1;
    }
    out[0] = 0;
    return 0;
}

/* Fixed header checks shared by probe and open. h = 36 bytes. */
static int hdr_sane(const u8 *h, u64 avail, int strict)
{
    if (rd32(h) != CAB_SIG || rd32(h + 4) != 0) return 0;
    u32 size = rd32(h + 8), coff = rd32(h + 16);
    if (h[25] != 1 || (rd16(h + 30) & ~7u)) return 0;
    if (coff < CAB_HDR || (size && coff >= size)) return 0;
    if (strict) {
        /* an "MSCF" found inside other data must look like a whole cabinet */
        if (rd32(h + 12) || rd32(h + 20) || size < CAB_HDR + 8 || size > avail) return 0;
        if (!rd16(h + 26) || !rd16(h + 28)) return 0;
    }
    return 1;
}

static int read_hdr(gz_src *s, u64 base, cab_hdr *H)
{
    u8 h[CAB_HDR + 4 + 2 * 2 * 257];
    __builtin_memset(H, 0, sizeof *H);
    if (base >= s->size) return GZ_E_TRUNC;
    u64 avail = s->size - base;
    u32 n = avail < sizeof h ? (u32)avail : (u32)sizeof h;
    if (n < CAB_HDR) return GZ_E_FORMAT;
    int r = gz_src_read_exact(s, base, h, n);
    if (r) return r;
    if (!hdr_sane(h, avail, 0)) return GZ_E_FORMAT;
    H->size = rd32(h + 8);
    H->coff_files = rd32(h + 16);
    H->nfold = rd16(h + 26);
    H->nfiles = rd16(h + 28);
    H->flags = rd16(h + 30);
    H->setid = rd16(h + 32);
    H->icab = rd16(h + 34);
    u64 p = CAB_HDR;
    if (H->flags & CF_RESERVE) {
        if (n < CAB_HDR + 4) return GZ_E_TRUNC;
        u32 rh = rd16(h + 36);
        H->res_fold = h[38];
        H->res_data = h[39];
        if (rh > 60000) return GZ_E_FORMAT;
        p += 4 + rh;
    }
    if (H->flags & (CF_PREV | CF_NEXT)) {
        /* the names follow the reserve area: read them separately */
        u8 nb[4 * 257];
        u64 left = avail > p ? avail - p : 0;
        u32 m = left < sizeof nb ? (u32)left : (u32)sizeof nb;
        if ((r = gz_src_read_exact(s, base + p, nb, m))) return r;
        u32 q = 0, k;
        u8 skip[257];
        if (H->flags & CF_PREV) {
            if (!(k = cstr(nb + q, m - q, H->prev))) return GZ_E_FORMAT;
            q += k;
            if (!(k = cstr(nb + q, m - q, skip))) return GZ_E_FORMAT;
            q += k;
        }
        if (H->flags & CF_NEXT) {
            if (!(k = cstr(nb + q, m - q, H->next))) return GZ_E_FORMAT;
            q += k;
            if (!(k = cstr(nb + q, m - q, skip))) return GZ_E_FORMAT;
            q += k;
        }
        p += q;
    }
    if (p > 0xffff0000u) return GZ_E_FORMAT;
    H->fold_off = (u32)p;
    return GZ_OK;
}

/* Find a cabinet: at offset 0, or (executables) the first sane "MSCF\0\0\0\0" in the
 * first SCAN_LIMIT bytes. Returns 95 / 70 / 0 and the offset. */
static int find_cab(gz_src *s, const u8 *head, u32 n, u64 *base)
{
    if (n >= CAB_HDR && hdr_sane(head, s->size, 0)) { *base = 0; return 95; }
    if (n < 64 || head[0] != 'M' || head[1] != 'Z') return 0;
    u32 lim = s->size < SCAN_LIMIT ? (u32)s->size : SCAN_LIMIT;
    enum { CH = 256u << 10 };
    u8 *buf = (u8 *)gz_alloc(CH + CAB_HDR);
    if (!buf) return 0;
    int score = 0;
    for (u32 off = 0; off < lim && !score; off += CH) {
        u32 want = lim - off < CH ? lim - off : CH;
        u64 rd = (u64)want + CAB_HDR <= s->size - off ? want + CAB_HDR : s->size - off;
        if (gz_src_read_exact(s, off, buf, (u32)rd)) break;
        for (u32 i = 0; i < want && i + CAB_HDR <= rd; i++) {
            if (buf[i] != 'M' || rd32(buf + i) != CAB_SIG) continue;
            if (hdr_sane(buf + i, s->size - off - i, 1)) { *base = off + i; score = 70; break; }
        }
    }
    gz_free(buf);
    return score;
}

static int cab_probe(gz_src *s, const u8 *head, u32 n)
{
    u64 base;
    return find_cab(s, head, n, &base);
}

/* ---------------- multi-cabinet sets ---------------- */

/* full path of a sibling cabinet: directory of o->file_name + name */
static gzch *sibling_name(const gz_open_opts *o, const u8 *name, int variant)
{
    if (!o->file_name) return 0;
    u32 nl = 0;
    while (name[nl]) nl++;
    if (!nl) return 0;
    size_t dl = gz_wcslen(o->file_name);
    while (dl && o->file_name[dl - 1] != '/' && o->file_name[dl - 1] != '\\') dl--;
    gzch *w = (gzch *)gz_alloc((dl + 2 * (size_t)nl + 4) * sizeof(gzch));
    if (!w) return 0;
    __builtin_memcpy(w, o->file_name, dl * sizeof(gzch));
    int k;
    if (gz_utf8_valid(name, nl)) k = gz_utf8_to_utf16(name, nl, w + dl);
    else k = gz_plat_mb2wc(gz_plat_acp(), name, (int)nl, w + dl, (int)(2 * nl + 2));
    if (k <= 0) { gz_free(w); return 0; }
    for (int i = 0; i < k; i++) {
        gzch ch = w[dl + i];
        if (ch == '/' || ch == '\\') { gz_free(w); return 0; }    /* plain file names only */
        if (variant == 1 && ch >= 'A' && ch <= 'Z') w[dl + i] = (gzch)(ch + 32);
        if (variant == 2 && ch >= 'a' && ch <= 'z') w[dl + i] = (gzch)(ch - 32);
    }
    w[dl + (size_t)k] = 0;
    return w;
}

static int open_sibling(gz_archive *a, const gz_open_opts *o, const u8 *name, gz_src **out)
{
    *out = 0;
    if (!o->open_volume) return GZ_E_VOLUME;
    for (int v = 0; v < 3; v++) {
        gzch *w = sibling_name(o, name, v);
        if (!w) return GZ_E_VOLUME;
        gz_src *s = 0;
        int r = o->open_volume(o->user, w, &s);
        gz_free(w);
        if (!r && s) {
            gz_src **nv = (gz_src **)gz_realloc(a->vols, (a->nvols + 1) * sizeof(gz_src *));
            if (!nv) { gz_src_free(s); return GZ_E_NOMEM; }
            a->vols = nv;
            a->vols[a->nvols++] = s;
            *out = s;
            return GZ_OK;
        }
        if (r == GZ_E_CANCEL) return r;
    }
    return GZ_E_VOLUME;
}

/* ---------------- open ---------------- */

static int add_fold(cab_priv *p, u16 type)
{
    if (p->nfold == p->capfold) {
        u32 nc = p->capfold ? p->capfold * 2 : 16;
        cab_fold *nf = (cab_fold *)gz_realloc(p->fold, nc * sizeof(cab_fold));
        if (!nf) return GZ_E_NOMEM;
        p->fold = nf;
        p->capfold = nc;
    }
    cab_fold *f = &p->fold[p->nfold++];
    __builtin_memset(f, 0, sizeof *f);
    f->type = type;
    f->seg0 = p->nseg;
    return GZ_OK;
}

static int add_seg(cab_priv *p, u32 cab, u64 data, u32 nblocks)
{
    if (p->nseg == p->capseg) {
        u32 nc = p->capseg ? p->capseg * 2 : 16;
        cab_seg *ns = (cab_seg *)gz_realloc(p->seg, nc * sizeof(cab_seg));
        if (!ns) return GZ_E_NOMEM;
        p->seg = ns;
        p->capseg = nc;
    }
    cab_seg *g = &p->seg[p->nseg++];
    g->cab = cab;
    g->data = data;
    g->nblocks = nblocks;
    p->fold[p->nfold - 1].nseg++;
    return GZ_OK;
}

/* Parse folders and files of cabinet ci and merge them into the archive. */
static int parse_cab(gz_archive *a, cab_priv *p, gz_src *s, u32 ci, const cab_hdr *H, int *last_cont)
{
    u64 base = p->cabs[ci].base;
    u64 avail = s->size - base;
    if (H->nfold && (u64)H->fold_off + (u64)H->nfold * (8u + H->res_fold) > avail) return GZ_E_TRUNC;
    u32 fsz = 8u + H->res_fold;
    u8 *fb = (u8 *)gz_alloc((size_t)H->nfold * fsz + 1);
    if (!fb) return GZ_E_NOMEM;
    int r = H->nfold ? gz_src_read_exact(s, base + H->fold_off, fb, H->nfold * fsz) : GZ_OK;
    if (r) { gz_free(fb); return r; }

    /* files */
    u64 fend = H->size && H->size <= avail ? H->size : avail;
    if (H->coff_files >= fend) { gz_free(fb); return H->nfiles ? GZ_E_TRUNC : GZ_OK; }
    u64 flen = fend - H->coff_files;
    u64 fmax = (u64)H->nfiles * (16 + 257);
    if (flen > fmax) flen = fmax;
    u8 *fl = (u8 *)gz_alloc((size_t)flen + 1);
    if (!fl) { gz_free(fb); return GZ_E_NOMEM; }
    if ((r = gz_src_read_exact(s, base + H->coff_files, fl, (u32)flen))) { gz_free(fb); gz_free(fl); return r; }

    /* does folder 0 continue the previous cabinet's last folder? */
    int cont_prev = 0;
    {
        u32 q = 0;
        for (u32 i = 0; i < H->nfiles && q + 16 < flen; i++) {
            u32 ifold = rd16(fl + q + 8);
            if (ifold == IF_CONT_PREV || ifold == IF_CONT_BOTH) cont_prev = 1;
            u32 k = 0;
            while (q + 16 + k < flen && fl[q + 16 + k]) k++;
            q += 16 + k + 1;
        }
    }
    u32 map0 = p->nfold;              /* logical index of folder 0 */
    int merged = 0;
    if (cont_prev && ci > 0 && *last_cont && p->nfold && H->nfold &&
        p->fold[p->nfold - 1].type == rd16(fb + 6)) {
        merged = 1;
        map0 = p->nfold - 1;
    }
    for (u32 j = 0; j < H->nfold; j++) {
        const u8 *f = fb + (size_t)j * fsz;
        u64 data = base + rd32(f);
        if (!(j == 0 && merged) && (r = add_fold(p, rd16(f + 6)))) break;
        if ((r = add_seg(p, ci, data, rd16(f + 4)))) break;
        /* compressed span up to the next folder or the cabinet end (statistics) */
        u64 nx = j + 1 < H->nfold ? base + rd32(f + fsz) : base + fend;
        if (nx > data) p->fold[p->nfold - 1].csize += nx - data;
    }
    if (r) { gz_free(fb); gz_free(fl); return r; }
    u32 lastf = H->nfold ? p->nfold - 1 : FOLD_BAD;

    int any_next = 0;
    u32 q = 0;
    for (u32 i = 0; i < H->nfiles; i++) {
        if (q + 16 >= flen) { r = GZ_E_TRUNC; break; }
        const u8 *x = fl + q;
        u32 k = 0;
        while (q + 16 + k < flen && x[16 + k]) k++;
        if (q + 16 + k >= flen || k > 256) { r = GZ_E_FORMAT; break; }
        q += 16 + k + 1;
        u32 ifold = rd16(x + 8), at = rd16(x + 14);
        u32 lf;
        if (ifold == IF_CONT_PREV || ifold == IF_CONT_BOTH) {
            if (ifold == IF_CONT_BOTH) any_next = 1;
            if (merged) continue;                  /* listed with the previous cabinet */
            lf = FOLD_MISSING;
        } else if (ifold == IF_CONT_NEXT) {
            any_next = 1;
            lf = lastf;
        } else {
            lf = ifold < H->nfold ? (ifold == 0 ? map0 : p->nfold - H->nfold + ifold) : FOLD_BAD;
        }
        gz_entry *e;
        if ((r = gz_arc_add_named(a, x + 16, k, (at & 0x80) ? GZ_NE_UTF8 : GZ_NE_LEGACY, &e))) break;
        e->usize = rd32(x);
        e->off = rd32(x + 4);
        e->csize = 0;
        e->aux32 = lf;
        e->method = lf < p->nfold ? p->fold[lf].type : 0xffff;
        e->flags = (u16)at;
        e->mtime = ((u64)rd16(x + 10) << 16) | rd16(x + 12);
        e->mtime_kind = GZ_MT_DOS;
        e->attr = at & 0x27;
        if (at & 0x40) e->unix_mode = (at & 1) ? 0100555 : 0100755;
        if (!(at & 0x80)) a->win_names = 1;
    }
    gz_free(fb);
    gz_free(fl);
    *last_cont = (H->flags & CF_NEXT) && any_next;
    if (merged) p->fold[map0].missing_next = 0;
    if (*last_cont && lastf != FOLD_BAD) p->fold[lastf].missing_next = 1;   /* cleared when merged */
    return r;
}

static void sort_order(gz_archive *a, cab_priv *p)
{
    /* bottom-up merge sort by (folder, offset, index) */
    u32 n = a->n;
    u32 *v = p->order, *t = (u32 *)gz_alloc((size_t)n * sizeof(u32) + 4);
    for (u32 i = 0; i < n; i++) v[i] = i;
    if (!t) return;
    for (u32 w = 1; w < n; w *= 2) {
        for (u32 i = 0; i < n; i += 2 * w) {
            u32 lo = i, mid = i + w < n ? i + w : n, hi = i + 2 * w < n ? i + 2 * w : n;
            u32 x = lo, y = mid, k = lo;
            while (x < mid && y < hi) {
                const gz_entry *ex = &a->e[v[x]], *ey = &a->e[v[y]];
                int ylt = ey->aux32 != ex->aux32 ? ey->aux32 < ex->aux32 : ey->off < ex->off;
                t[k++] = ylt ? v[y++] : v[x++];
            }
            while (x < mid) t[k++] = v[x++];
            while (y < hi) t[k++] = v[y++];
        }
        __builtin_memcpy(v, t, (size_t)n * sizeof(u32));
    }
    gz_free(t);
}

static void cab_close(gz_archive *a)
{
    cab_priv *p = (cab_priv *)a->priv;
    if (!p) return;
    gz_free(p->cabs);
    gz_free(p->fold);
    gz_free(p->seg);
    gz_free(p->order);
    gz_free(p);
    a->priv = 0;
}

static int cab_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    u8 head[CAB_HDR];
    u64 base = 0;
    if (s->size < CAB_HDR) return GZ_E_FORMAT;
    int r = gz_src_read_exact(s, 0, head, CAB_HDR);
    if (r) return r;
    if (!hdr_sane(head, s->size, 0)) {
        u8 *h = (u8 *)gz_alloc(4096);
        if (!h) return GZ_E_NOMEM;
        u32 n = s->size < 4096 ? (u32)s->size : 4096;
        r = gz_src_read_exact(s, 0, h, n);
        int sc = r ? 0 : find_cab(s, h, n, &base);
        gz_free(h);
        if (!sc) return GZ_E_FORMAT;
    }
    cab_priv *p = (cab_priv *)gz_alloc(sizeof(cab_priv));
    if (!p) return GZ_E_NOMEM;
    a->priv = p;
    a->solid = 1;
    a->sfx_shift = base;

    /* collect the cabinet chain: walk back to the first one, then forward */
    gz_src **chain = (gz_src **)gz_alloc(sizeof(gz_src *) * (MAX_CABS + 1));
    cab_hdr *hd = (cab_hdr *)gz_alloc(sizeof(cab_hdr) * 2);
    p->cabs = (cab_cab *)gz_alloc(sizeof(cab_cab) * MAX_CABS);
    if (!chain || !hd || !p->cabs) { r = GZ_E_NOMEM; goto out; }
    if ((r = read_hdr(s, base, &hd[0]))) goto out;
    u32 nback = 0, ncab;
    hd[1] = hd[0];
    while ((hd[1].flags & CF_PREV) && nback < MAX_CABS / 2) {
        gz_src *v;
        cab_hdr pv;
        if (open_sibling(a, o, hd[1].prev, &v)) break;
        if (read_hdr(v, 0, &pv) || pv.setid != hd[1].setid || pv.icab + 1 != hd[1].icab) break;
        chain[MAX_CABS - 1 - nback++] = v;       /* collected backwards at the end */
        hd[1] = pv;
    }
    for (u32 i = 0; i < nback; i++) chain[i] = chain[MAX_CABS - nback + i];
    ncab = nback;
    chain[ncab++] = s;
    hd[1] = hd[0];
    while ((hd[1].flags & CF_NEXT) && ncab < MAX_CABS) {
        gz_src *v;
        cab_hdr nx;
        if (open_sibling(a, o, hd[1].next, &v)) break;
        if (read_hdr(v, 0, &nx) || nx.setid != hd[1].setid || nx.icab != hd[1].icab + 1) break;
        chain[ncab++] = v;
        hd[1] = nx;
    }

    /* parse in order */
    int last_cont = 0;
    for (u32 ci = 0; ci < ncab; ci++) {
        gz_src *v = chain[ci];
        cab_cab *cb = &p->cabs[ci];
        cb->base = v == s ? base : 0;
        cb->vol = 0;
        if (v != s)
            for (u32 k = 0; k < a->nvols; k++) if (a->vols[k] == v) cb->vol = k + 1;
        cab_hdr *H = &hd[1];
        if ((r = read_hdr(v, cb->base, H))) { if (v == s) goto out; r = GZ_OK; break; }
        cb->res_data = H->res_data;
        p->ncab = ci + 1;
        r = parse_cab(a, p, v, ci, H, &last_cont);
        if (r) {
            if (v == s || r == GZ_E_NOMEM) goto out;
            r = GZ_OK;
            break;                                 /* broken later volume: keep what we have */
        }
        if (c && c->progress) c->progress(c->progress_user, ci + 1, ncab);
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; goto out; }
    }
out:
    gz_free(chain);
    gz_free(hd);
    if (r) return r;

    /* fix folder indices of entries, method, statistics */
    p->order = (u32 *)gz_alloc((size_t)a->n * sizeof(u32) + 4);
    if (!p->order) return GZ_E_NOMEM;
    for (u32 i = 0; i < a->n; i++) {
        gz_entry *e = &a->e[i];
        if (e->aux32 < p->nfold) e->method = p->fold[e->aux32].type;
    }
    sort_order(a, p);
    u32 lastf = FOLD_BAD;
    for (u32 i = 0; i < a->n; i++) {
        gz_entry *e = &a->e[p->order[i]];
        if (e->aux32 < p->nfold && e->aux32 != lastf) {
            e->csize = p->fold[e->aux32].csize;     /* first file of a folder carries it */
            lastf = e->aux32;
        }
    }
    return GZ_OK;
}

/* ---------------- folder decoding ---------------- */

static u32 cab_csum(const u8 *p, u32 n, u32 seed)
{
    u32 s = seed, i = 0;
    for (; i + 4 <= n; i += 4) s ^= rd32(p + i);
    u32 ul = 0;
    switch (n & 3) {
    case 3: ul = (u32)p[i] << 16 | (u32)p[i + 1] << 8 | p[i + 2]; break;
    case 2: ul = (u32)p[i] << 8 | p[i + 1]; break;
    case 1: ul = p[i]; break;
    }
    return s ^ ul;
}

#define IN_CAP   (2u * 65535u + 16u)
#define OUT_CAP  (65536u + 64u)
#define HIST     32768u

typedef struct {
    gz_archive *a;
    cab_priv *p;
    gz_src *s;
    gz_ctx *c;
    const cab_fold *f;
    u32 seg, blk;        /* next block: segment index within the folder, block in it */
    u64 off;             /* its file offset                                        */
    u8 *in, *out, *hist;
    u32 hist_n;
    gz_lzx_dec *lzx;
    gz_qtm_dec *qtm;     /* owned: allocated per extraction (Quantum is rare)        */
    u64 start, n;        /* folder offset and size of the block in out             */
    /* MSZIP output sink */
    u32 o_n, o_cap;
    const u8 *i_p;
    u32 i_n;
} frd;

static int fr_init(frd *fr, gz_archive *a, gz_src *s, u32 fi, gz_ctx *c)
{
    cab_priv *p = (cab_priv *)a->priv;
    gz_qtm_dec *qtm = fr->qtm;           /* kept across restarts of the folder */
    __builtin_memset(fr, 0, sizeof *fr);
    fr->qtm = qtm;
    fr->a = a;
    fr->p = p;
    fr->s = s;
    fr->c = c;
    fr->f = &p->fold[fi];
    u8 *buf = gz_ctx_buffer(c, IN_CAP + OUT_CAP + HIST + 64);
    if (!buf) return GZ_E_NOMEM;
    fr->in = buf;
    fr->out = buf + IN_CAP;
    fr->hist = fr->out + OUT_CAP;
    u32 type = fr->f->type & 15;
    if (type == M_LZX) {
        fr->lzx = (gz_lzx_dec *)gz_ctx_slot(c, GZ_SLOT_LZX, gz_lzx_slot_new, gz_lzx_slot_free);
        if (!fr->lzx) return GZ_E_NOMEM;
        int r = gz_lzx_init(fr->lzx, (fr->f->type >> 8) & 0x1f, 0);
        if (r) return r == GZ_E_NOMEM ? r : GZ_E_METHOD;
    } else if (type == M_MSZIP) {
        if (!gz_ctx_inflater(c)) return GZ_E_NOMEM;
    } else if (type == M_QUANTUM) {
        u32 wb = (fr->f->type >> 8) & 0x1f;
        if (wb < 10 || wb > 21) return GZ_E_METHOD;
        if (!fr->qtm) fr->qtm = gz_qtm_new(wb);
        else if (gz_qtm_init(fr->qtm, wb)) return GZ_E_NOMEM;
        if (!fr->qtm) return GZ_E_NOMEM;
    } else if (type != M_NONE) {
        return GZ_E_METHOD;
    }
    if (!fr->f->nseg) return GZ_E_FORMAT;
    fr->off = p->seg[fr->f->seg0].data;
    return GZ_OK;
}

/* read one CFDATA block's header + data at fr->off, appending data to fr->in + have */
static int read_cfdata(frd *fr, u32 have, u32 *cb_data, u32 *cb_unc)
{
    const cab_seg *g = &fr->p->seg[fr->f->seg0 + fr->seg];
    const cab_cab *cb = &fr->p->cabs[g->cab];
    gz_src *src = cab_src(fr->a, fr->s, cb);
    u8 h[8 + 255];
    u32 hn = 8u + cb->res_data;
    int r = gz_src_read_exact(src, fr->off, h, hn);
    if (r) return r == GZ_E_TRUNC ? GZ_E_DATA : r;
    u32 n = rd16(h + 4), u = rd16(h + 6);
    if (have + n > IN_CAP - 16) return GZ_E_DATA;
    r = gz_src_read_exact(src, fr->off + hn, fr->in + have, n);
    if (r) return r == GZ_E_TRUNC ? GZ_E_DATA : r;
    u32 sum = rd32(h);
    if (sum) {
        u32 d = cab_csum(fr->in + have, n, 0);
        /* the reserve area is covered by the spec (7-Zip); libmspack skips it */
        if (cab_csum(h + 4, hn - 4, d) != sum && cab_csum(h + 4, 4, d) != sum) return GZ_E_CRC;
    }
    fr->off += hn + n;
    fr->blk++;
    *cb_data = n;
    *cb_unc = u;
    return GZ_OK;
}

/* advance to the next segment of the folder (multi-cabinet) */
static int next_seg(frd *fr)
{
    fr->seg++;
    fr->blk = 0;
    if (fr->seg >= fr->f->nseg) return fr->f->missing_next ? GZ_E_VOLUME : GZ_E_DATA;
    fr->off = fr->p->seg[fr->f->seg0 + fr->seg].data;
    return GZ_OK;
}

static int mz_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    frd *fr = (frd *)ctx;
    u32 k = fr->i_n < cap ? fr->i_n : cap;
    __builtin_memcpy(buf, fr->i_p, k);
    fr->i_p += k;
    fr->i_n -= k;
    *got = k;
    return GZ_OK;
}

static int mz_write(void *ctx, const u8 *p, size_t n)
{
    frd *fr = (frd *)ctx;
    if (n > fr->o_cap - fr->o_n) return GZ_E_DATA;
    __builtin_memcpy(fr->out + fr->o_n, p, n);
    fr->o_n += (u32)n;
    return GZ_OK;
}

/* Decode the next block into fr->out: fr->start/fr->n. *end = 1 at the folder end. */
static int fr_next(frd *fr, int *end)
{
    *end = 0;
    fr->start += fr->n;
    fr->n = 0;
    for (;;) {
        if (gz_cancelled(fr->c)) return GZ_E_CANCEL;
        const cab_seg *g = &fr->p->seg[fr->f->seg0 + fr->seg];
        if (fr->blk < g->nblocks) break;
        if (fr->seg + 1 >= fr->f->nseg) {
            if (fr->f->missing_next) return GZ_E_VOLUME;
            *end = 1;
            return GZ_OK;
        }
        int r = next_seg(fr);
        if (r) return r;
    }
    u32 n, u;
    int r = read_cfdata(fr, 0, &n, &u);
    if (r) return r;
    while (!u) {
        /* block split across cabinets: it continues with the first block of the next
         * one (a small block may span several cabinets) */
        const cab_seg *g = &fr->p->seg[fr->f->seg0 + fr->seg];
        if (fr->blk != g->nblocks) return GZ_E_DATA;
        if ((r = next_seg(fr))) return r;
        if (!fr->p->seg[fr->f->seg0 + fr->seg].nblocks) return GZ_E_DATA;
        u32 n2;
        if ((r = read_cfdata(fr, n, &n2, &u))) return r;
        n += n2;
    }
    switch (fr->f->type & 15) {
    case M_NONE:
        if (n != u) return GZ_E_DATA;
        __builtin_memcpy(fr->out, fr->in, n);
        break;
    case M_MSZIP: {
        if (n < 2 || fr->in[0] != 'C' || fr->in[1] != 'K' || u > HIST) return GZ_E_DATA;
        gz_inflater *z = gz_ctx_inflater(fr->c);
        fr->i_p = fr->in + 2;
        fr->i_n = n - 2;
        fr->o_n = 0;
        fr->o_cap = u;
        gz_stream_io io = { mz_read, mz_write, fr };
        r = gz_inflate_run_dict(z, &io, fr->hist, fr->hist_n);
        if (r) return r == GZ_E_CANCEL ? r : GZ_E_DATA;
        if (fr->o_n != u) return GZ_E_DATA;
        /* the window continues into the next block */
        if (u >= HIST) {
            __builtin_memcpy(fr->hist, fr->out + u - HIST, HIST);
            fr->hist_n = HIST;
        } else {
            u32 keep = fr->hist_n + u > HIST ? HIST - u : fr->hist_n;
            __builtin_memmove(fr->hist, fr->hist + fr->hist_n - keep, keep);
            __builtin_memcpy(fr->hist + keep, fr->out, u);
            fr->hist_n = keep + u;
        }
        break;
    }
    case M_LZX:
        if (u > GZ_LZX_FRAME) return GZ_E_DATA;
        r = gz_lzx_decode_frame(fr->lzx, fr->in, n, 0, fr->out, u);
        if (r) return GZ_E_DATA;
        break;
    case M_QUANTUM:
        if (u > GZ_QTM_FRAME) return GZ_E_DATA;
        r = gz_qtm_decode_frame(fr->qtm, fr->in, n, fr->out, u);
        if (r) return GZ_E_DATA;
        break;
    default:
        return GZ_E_METHOD;
    }
    fr->n = u;
    return GZ_OK;
}

/* Extract the selected entries of one folder, list sorted by offset. */
static int extract_folder(gz_archive *a, gz_src *s, u32 fi, const u32 *list, u32 nl, gz_out *out, gz_ctx *c,
                          int *last_st)
{
    frd fr;
    fr.qtm = 0;
    int ferr = fr_init(&fr, a, s, fi, c), started = 0, ret = GZ_OK;
    for (u32 k = 0; k < nl; k++) {
        u32 idx = list[k];
        gz_entry *e = &a->e[idx];
        if (gz_cancelled(c)) { ret = GZ_E_CANCEL; break; }
        int r = out->open(out, idx);
        if (r == GZ_E_SKIP) continue;
        if (r) { ret = r; break; }
        int st = e->usize ? ferr : GZ_OK;
        if (!st && e->usize) {
            if (e->off < fr.start || !started) {
                /* first file, or overlapping / out of order entries: restart the folder */
                if (started && (st = fr_init(&fr, a, s, fi, c))) goto done;
                if (fr.lzx) gz_lzx_reset(fr.lzx);
                if (fr.qtm) gz_qtm_reset(fr.qtm);
                fr.hist_n = 0;
                started = 1;
            }
            u64 pos = e->off, left = e->usize;
            while (left) {
                if (pos >= fr.start + fr.n) {
                    int end;
                    if ((st = fr_next(&fr, &end))) break;
                    if (end) { st = GZ_E_DATA; break; }
                    continue;
                }
                u64 k2 = fr.start + fr.n - pos;
                if (k2 > left) k2 = left;
                if ((st = out->write(out, fr.out + (pos - fr.start), (size_t)k2))) goto done;
                pos += k2;
                left -= k2;
            }
            if (st) ferr = st;                    /* the folder stream is broken from here */
        }
done:
        r = out->close(out, idx, st);
        if (last_st) *last_st = st ? st : r;
        if (st == GZ_E_CANCEL || r == GZ_E_CANCEL) { ret = GZ_E_CANCEL; break; }
    }
    gz_qtm_free(fr.qtm);
    return ret;
}

static int fail_entry(gz_out *out, u32 idx, int st)
{
    int r = out->open(out, idx);
    if (r) return r == GZ_E_SKIP ? GZ_OK : r;
    r = out->close(out, idx, st);
    return r == GZ_E_CANCEL ? r : GZ_OK;
}

static int cab_extract_solid(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_ctx *c)
{
    cab_priv *p = (cab_priv *)a->priv;
    u32 *list = (u32 *)gz_alloc((size_t)a->n * sizeof(u32) + 4);
    if (!list) return GZ_E_NOMEM;
    int r = GZ_OK;
    u32 i = 0;
    while (i < a->n && !r) {
        u32 fi = a->e[p->order[i]].aux32, nl = 0;
        for (; i < a->n && a->e[p->order[i]].aux32 == fi; i++)
            if (sel[p->order[i]]) list[nl++] = p->order[i];
        if (!nl) continue;
        if (fi >= p->nfold) {
            int st = fi == FOLD_MISSING ? GZ_E_VOLUME : GZ_E_FORMAT;
            for (u32 k = 0; k < nl && !r; k++) r = fail_entry(out, list[k], a->e[list[k]].usize ? st : GZ_OK);
        } else {
            r = extract_folder(a, s, fi, list, nl, out, c, 0);
        }
        if (gz_cancelled(c)) r = GZ_E_CANCEL;
    }
    gz_free(list);
    return r;
}

static int cab_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    cab_priv *p = (cab_priv *)a->priv;
    u32 fi = a->e[idx].aux32;
    if (fi >= p->nfold) {
        int st = !a->e[idx].usize ? GZ_OK : fi == FOLD_MISSING ? GZ_E_VOLUME : GZ_E_FORMAT;
        int r = out->open(out, idx);
        if (r) return r;
        r = out->close(out, idx, st);
        return st ? st : r;
    }
    int st = GZ_OK;
    int r = extract_folder(a, s, fi, &idx, 1, out, c, &st);
    return r ? r : st;
}

static void cab_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    const char *n;
    u32 t = e->method, bits = (t >> 8) & 0x1f;
    switch (t & 15) {
    case M_NONE: n = "None"; break;
    case M_MSZIP: n = "MSZIP"; break;
    case M_QUANTUM: n = "Quantum:"; break;
    case M_LZX: n = "LZX:"; break;
    default: n = "?"; break;
    }
    if (t == 0xffff) n = "?";
    u32 i = 0;
    for (; *n && i + 1 < cap; n++) buf[i++] = *n;
    if (t != 0xffff && ((t & 15) == M_QUANTUM || (t & 15) == M_LZX)) {
        if (bits >= 10 && i + 1 < cap) buf[i++] = (char)('0' + bits / 10);
        if (i + 1 < cap) buf[i++] = (char)('0' + bits % 10);
    }
    if (cap) buf[i] = 0;
}

GZ_FORMAT(gz_fmt_cab)
const gz_format gz_fmt_cab = {
    "CAB", "cab",
    0, cab_probe, cab_open, cab_close, cab_extract, cab_extract_solid, 0, cab_method, 0, 0
};
