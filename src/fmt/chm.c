/*
 * 고깃ZIP - Microsoft Compiled HTML Help (CHM / ITSF) reader
 *
 *   ITSF header, ITSP directory with PMGL listing chunks (ENCINT entries),
 *   section 0 (stored) and section 1 "MSCompressed" (LZXC: LZX with resets
 *   every N 32 KiB frames and a reset table for random access).
 *
 * Listing: like 7-Zip, every user entry (names starting with '/') is shown,
 * directories included; the "::DataSpace/..." storage internals (compressed
 * stream, control data, reset table) are not listed. HTML Help system files in
 * the root ("#SYSTEM", "#TOPICS", "$FIftiMain", "$WWKeywordLinks/...") are listed
 * with is_aux = 1 so front ends may hide them.
 *
 * CHM has no checksums. Extraction is solid per reset interval: a->solid = 1,
 * extract_solid decodes section 1 once in offset order; extract() of a single
 * entry starts at the reset point before it.
 */
#include "arc.h"
#include "lzx.h"

#define ITSF_SIG 0x46535449u   /* "ITSF" */
#define ITSP_SIG 0x50535449u   /* "ITSP" */
#define PMGL_SIG 0x4C474D50u   /* "PMGL" */
#define LZXC_SIG 0x43585A4Cu   /* "LZXC" */
#define FRAME    32768u
#define ICAP     (320u << 10)  /* input window of the compressed stream */
#define ILOOK    (192u << 10)  /* bytes kept available after the read position */

typedef struct {
    u64 content;          /* absolute offset of section 0 data                 */
    int lzx_err;          /* GZ_OK when section 1 can be decoded               */
    u32 wbits, fpr;       /* window bits, frames per reset interval            */
    u64 c_off, c_len;     /* compressed stream (absolute offset, length)       */
    u64 u_len;            /* uncompressed length of section 1                  */
    u64 rt_pos;           /* absolute offset of reset table entry 0, 0 = none  */
    u32 rt_n, rt_es;      /* entries, entry size (4 or 8)                      */
} chm_priv;

static int chm_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 0x58 || rd32(h) != ITSF_SIG) return 0;
    u32 ver = rd32(h + 4);
    return (ver == 2 || ver == 3) ? 95 : 60;
}

/* ENCINT: big-endian base-128, high bit = more bytes. 0 on overrun. */
static int encint(const u8 *p, u32 end, u32 *pos, u64 *v)
{
    u64 x = 0;
    for (u32 k = 0; k < 9; k++) {
        if (*pos >= end) return 0;
        u8 c = p[(*pos)++];
        x = (x << 7) | (c & 0x7f);
        if (!(c & 0x80)) { *v = x; return 1; }
    }
    return 0;
}

typedef struct { u64 off, len; int found; } sec0_ref;

static int name_is(const u8 *n, u32 len, const char *want)
{
    u32 i = 0;
    for (; i < len; i++) if (!want[i] || want[i] != (char)n[i]) return 0;
    return !want[i];
}

/* Read up to cap bytes of a section 0 entry (metadata). */
static int read_sec0(gz_src *s, const chm_priv *p, const sec0_ref *r, u8 *buf, u32 cap, u32 *got)
{
    *got = 0;
    if (!r->found) return GZ_E_FORMAT;
    u64 off = p->content + r->off;
    if (off < p->content || off > s->size || r->len > s->size - off) return GZ_E_TRUNC;
    u32 n = r->len < cap ? (u32)r->len : cap;
    int e = gz_src_read_exact(s, off, buf, n);
    if (!e) *got = n;
    return e;
}

/* Set up section 1 (MSCompressed) from its control data and reset table. */
static int setup_lzx(gz_src *s, chm_priv *p, const sec0_ref *content, const sec0_ref *ctrl,
                     const sec0_ref *rtab, const sec0_ref *span)
{
    u8 b[64];
    u32 got;
    if (!content->found || !ctrl->found) return GZ_E_FORMAT;
    int r = read_sec0(s, p, ctrl, b, sizeof b, &got);
    if (r) return r;
    if (got < 24 || rd32(b + 4) != LZXC_SIG) return GZ_E_METHOD;
    u32 ver = rd32(b + 8);
    u64 ri = rd32(b + 12), ws = rd32(b + 16);
    if (ver == 2) { ri *= FRAME; ws *= FRAME; }
    else if (ver != 1) return GZ_E_METHOD;
    u32 wb = 15;
    while (wb <= 21 && ((u64)1 << wb) != ws) wb++;
    if (wb > 21 || !ri || ri % FRAME || ri / FRAME > 0xffffffu) return GZ_E_METHOD;
    p->wbits = wb;
    p->fpr = (u32)(ri / FRAME);
    p->c_off = p->content + content->off;
    p->c_len = content->len;
    if (p->c_off < p->content || p->c_off > s->size || p->c_len > s->size - p->c_off) return GZ_E_TRUNC;
    p->u_len = GZ_SIZE_UNKNOWN;
    if (rtab->found && !read_sec0(s, p, rtab, b, 0x28, &got) && got == 0x28) {
        u32 n = rd32(b + 4), es = rd32(b + 8), to = rd32(b + 12);
        u64 ul = rd64(b + 16), bs = rd64(b + 32);
        if (ul) p->u_len = ul;
        if ((es == 4 || es == 8) && bs == FRAME && to <= rtab->len && n <= (rtab->len - to) / es) {
            p->rt_pos = p->content + rtab->off + to;
            p->rt_n = n;
            p->rt_es = es;
        }
    }
    if (p->u_len == GZ_SIZE_UNKNOWN && span->found && !read_sec0(s, p, span, b, 8, &got) && got == 8)
        p->u_len = rd64(b);
    if (p->u_len == GZ_SIZE_UNKNOWN || p->u_len > ((u64)1 << 46)) return GZ_E_FORMAT;
    return GZ_OK;
}

static int chm_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    u8 h[0x60];
    if (s->size < 0x58) return GZ_E_FORMAT;
    int r = gz_src_read_exact(s, 0, h, s->size < 0x60 ? 0x58 : 0x60);
    if (r) return r;
    if (rd32(h) != ITSF_SIG) return GZ_E_FORMAT;
    u32 ver = rd32(h + 4);
    if (ver < 2 || ver > 3 || (ver == 3 && s->size < 0x60)) return GZ_E_FORMAT;
    u64 dir = rd64(h + 0x48), dlen = rd64(h + 0x50);
    u64 content = ver == 3 ? rd64(h + 0x58) : dir + dlen;
    if (dir > s->size || dlen > s->size - dir || dlen < 0x54) return GZ_E_TRUNC;

    u8 ih[0x54];
    if ((r = gz_src_read_exact(s, dir, ih, 0x54))) return r;
    if (rd32(ih) != ITSP_SIG) return GZ_E_FORMAT;
    /* The listing chunks are taken from the whole directory (index chunks skipped)
     * instead of the first/last PMGL numbers: chmcmd stores a wrong first one. */
    u32 ihl = rd32(ih + 8), csz = rd32(ih + 0x10), nch = rd32(ih + 0x2C);
    if (ihl < 0x54 || ihl > dlen || csz < 0x20 || csz > (1u << 20)) return GZ_E_FORMAT;
    if (nch > (dlen - ihl) / csz) nch = (u32)((dlen - ihl) / csz);
    if (!nch) return GZ_E_FORMAT;

    chm_priv *p = (chm_priv *)gz_alloc(sizeof(chm_priv));
    if (!p) return GZ_E_NOMEM;
    a->priv = p;
    a->solid = 1;
    p->content = content;
    /* read the directory in batches of whole chunks (few reads even for tiny chunks) */
    u32 per = csz >= (256u << 10) ? 1 : (256u << 10) / csz;
    u8 *batch = (u8 *)gz_alloc((size_t)per * csz);
    if (!batch) return GZ_E_NOMEM;
    sec0_ref rc = { 0, 0, 0 }, rctl = { 0, 0, 0 }, rrt = { 0, 0, 0 }, rspan = { 0, 0, 0 };
    int damaged = 0;
    for (u32 ci = 0; ci < nch && !r; ci++) {
        u32 bi = ci % per;
        if (!bi) {
            u32 k = nch - ci < per ? nch - ci : per;
            if ((r = gz_src_read_exact(s, dir + ihl + (u64)ci * csz, batch, k * csz))) break;
        }
        const u8 *chunk = batch + (size_t)bi * csz;
        if (rd32(chunk) != PMGL_SIG) continue;
        u32 fr = rd32(chunk + 4);
        if (fr > csz - 0x14) { damaged = 1; continue; }
        u32 end = csz - fr, pos = 0x14;
        while (pos < end) {
            /* a damaged chunk ends the listing of that chunk only */
            u64 nl, sec, off, len;
            if (!encint(chunk, end, &pos, &nl) || nl > end - pos) { damaged = 1; break; }
            const u8 *nm = chunk + pos;
            pos += (u32)nl;
            if (!encint(chunk, end, &pos, &sec) || !encint(chunk, end, &pos, &off) ||
                !encint(chunk, end, &pos, &len)) { damaged = 1; break; }
            u32 n = (u32)nl;
            if (n >= 2 && nm[0] == ':' && nm[1] == ':') {
                /* storage internals: remember the ones section 1 needs */
                sec0_ref *t = 0;
                if (name_is(nm, n, "::DataSpace/Storage/MSCompressed/Content")) t = &rc;
                else if (name_is(nm, n, "::DataSpace/Storage/MSCompressed/ControlData")) t = &rctl;
                else if (name_is(nm, n, "::DataSpace/Storage/MSCompressed/SpanInfo")) t = &rspan;
                else if (name_is(nm, n, "::DataSpace/Storage/MSCompressed/Transform/"
                                        "{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable")) t = &rrt;
                if (t && sec == 0) { t->off = off; t->len = len; t->found = 1; }
                continue;
            }
            if (n < 2 || nm[0] != '/') continue;           /* "/" itself, odd names */
            gz_entry *e;
            if ((r = gz_arc_add_named(a, nm + 1, n - 1, GZ_NE_UTF8, &e))) break;
            e->is_dir = nm[n - 1] == '/';
            e->aux32 = sec > 0xfffffffeu ? 0xffffffffu : (u32)sec;
            e->off = off;
            e->usize = e->is_dir ? 0 : len;
            e->csize = sec == 0 ? e->usize : 0;
            e->attr = e->is_dir ? 0x10 : 0x20;
            e->is_aux = nm[1] == '#' || nm[1] == '$';
        }
        if (!bi) {
            if (c && c->progress) c->progress(c->progress_user, ci + 1, nch);
            if (gz_cancelled(c)) r = GZ_E_CANCEL;
        }
    }
    gz_free(batch);
    if (r) return r;
    if (damaged && !a->n) return GZ_E_FORMAT;
    p->lzx_err = setup_lzx(s, p, &rc, &rctl, &rrt, &rspan);
    return GZ_OK;
}

static void chm_close(gz_archive *a)
{
    gz_free(a->priv);
    a->priv = 0;
}

/* ---------------- section 1 decoding ---------------- */

typedef struct {
    gz_src *s;
    const chm_priv *p;
    gz_ctx *c;
    gz_lzx_dec *d;
    u8 *ibuf, *obuf;
    u64 ib_off;           /* stream offset of ibuf[0]                      */
    u32 ib_n;
    int started;
    u64 frame, cpos;      /* next frame and its compressed offset          */
    u64 have;             /* frame held in obuf, ~0 = none                 */
    u32 have_n;
} chm_dec;

static int rt_entry(const chm_dec *x, u64 f, u64 *off)
{
    const chm_priv *p = x->p;
    if (!p->rt_pos || f >= p->rt_n) return 0;
    u8 b[8];
    if (gz_src_read_exact(x->s, p->rt_pos + f * p->rt_es, b, p->rt_es)) return 0;
    *off = p->rt_es == 8 ? rd64(b) : rd32(b);
    return *off <= p->c_len;
}

static int fill_input(chm_dec *x)
{
    const chm_priv *p = x->p;
    if (x->cpos >= x->ib_off && x->cpos - x->ib_off <= x->ib_n &&
        (x->ib_off + x->ib_n == p->c_len || x->ib_n - (x->cpos - x->ib_off) >= ILOOK))
        return GZ_OK;
    u64 n = p->c_len - x->cpos;
    if (n > ICAP) n = ICAP;
    x->ib_off = x->cpos;
    x->ib_n = 0;
    int r = gz_src_read_exact(x->s, p->c_off + x->cpos, x->ibuf, (u32)n);
    if (r) return r == GZ_E_TRUNC ? GZ_E_DATA : r;
    x->ib_n = (u32)n;
    return GZ_OK;
}

/* decode frame x->frame; out = obuf when keep, else nothing is copied */
static int decode_next(chm_dec *x, int keep)
{
    const chm_priv *p = x->p;
    if (gz_cancelled(x->c)) return GZ_E_CANCEL;
    u64 f = x->frame;
    if (f * FRAME >= p->u_len) return GZ_E_DATA;
    if (f % p->fpr == 0) {
        gz_lzx_reset(x->d);
        u64 o;
        if (rt_entry(x, f, &o)) x->cpos = o;   /* reset points start where the table says */
    }
    if (x->cpos > p->c_len) return GZ_E_DATA;
    int r = fill_input(x);
    if (r) return r;
    u64 rem = p->u_len - f * FRAME;
    u32 on = rem < FRAME ? (u32)rem : FRAME, used = 0;
    u32 at = (u32)(x->cpos - x->ib_off);
    r = gz_lzx_decode_frame(x->d, x->ibuf + at, x->ib_n - at, &used, keep ? x->obuf : 0, on);
    if (r) return GZ_E_DATA;
    x->cpos += used;
    x->frame = f + 1;
    x->have = keep ? f : ~(u64)0;
    x->have_n = on;
    return GZ_OK;
}

/* make frame f available in obuf */
static int get_frame(chm_dec *x, u64 f)
{
    if (x->have == f) return GZ_OK;
    u64 rs = f - f % x->p->fpr;
    if (!x->started || x->frame > f || x->frame < rs) {
        u64 o = 0;
        if (rs && !rt_entry(x, rs, &o)) rs = 0;     /* no usable table: from the start */
        x->frame = rs;
        x->cpos = o;
        x->started = 1;
    }
    while (x->frame < f) {
        int r = decode_next(x, 0);
        if (r) { x->started = 0; return r; }
    }
    int r = decode_next(x, 1);
    if (r) x->started = 0;
    return r;
}

static int dec_init(chm_dec *x, gz_archive *a, gz_src *s, gz_ctx *c)
{
    const chm_priv *p = (const chm_priv *)a->priv;
    __builtin_memset(x, 0, sizeof *x);
    x->s = s;
    x->p = p;
    x->c = c;
    x->have = ~(u64)0;
    if (p->lzx_err) return p->lzx_err;
    x->d = (gz_lzx_dec *)gz_ctx_slot(c, GZ_SLOT_LZX, gz_lzx_slot_new, gz_lzx_slot_free);
    if (!x->d) return GZ_E_NOMEM;
    int r = gz_lzx_init(x->d, p->wbits, 0);
    if (r) return r;
    x->ibuf = gz_ctx_buffer(c, ICAP + FRAME + 64);
    if (!x->ibuf) return GZ_E_NOMEM;
    x->obuf = x->ibuf + ICAP;
    return GZ_OK;
}

static int write_sec1(chm_dec *x, const gz_entry *e, gz_out *out)
{
    u64 pos = e->off, left = e->usize;
    if (pos > x->p->u_len || left > x->p->u_len - pos) return GZ_E_DATA;
    while (left) {
        u64 f = pos / FRAME;
        int r = get_frame(x, f);
        if (r) return r;
        u32 at = (u32)(pos - f * FRAME);
        if (at >= x->have_n) return GZ_E_DATA;
        u32 k = x->have_n - at;
        if (k > left) k = (u32)left;
        if ((r = out->write(out, x->obuf + at, k))) return r;
        pos += k;
        left -= k;
    }
    return GZ_OK;
}

static int extract_one(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c, chm_dec *x, int xerr)
{
    gz_entry *e = &a->e[idx];
    const chm_priv *p = (const chm_priv *)a->priv;
    int r = out->open(out, idx);
    if (r) return r;
    int st = GZ_OK;
    if (!e->is_dir && e->usize) {
        if (e->aux32 == 0) {
            u64 off = p->content + e->off;
            if (off < p->content || off > s->size || e->usize > s->size - off) st = GZ_E_TRUNC;
            else st = gz_copy_range(s, off, e->usize, out, c, 0);
        } else if (e->aux32 == 1) {
            st = xerr ? xerr : write_sec1(x, e, out);
        } else {
            st = GZ_E_METHOD;
        }
    }
    r = out->close(out, idx, st);
    return st ? st : r;
}

static int chm_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    chm_dec x;
    __builtin_memset(&x, 0, sizeof x);
    int xerr = a->e[idx].aux32 == 1 ? dec_init(&x, a, s, c) : GZ_OK;
    return extract_one(a, s, idx, out, c, &x, xerr);
}

static int chm_extract_solid(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_ctx *c)
{
    chm_dec x;
    __builtin_memset(&x, 0, sizeof x);
    int xerr, r;
    u32 n1 = 0;
    /* stored entries and directories in listing order */
    for (u32 i = 0; i < a->n; i++) {
        if (!sel[i]) continue;
        if (a->e[i].aux32 == 1 && !a->e[i].is_dir && a->e[i].usize) { n1++; continue; }
        r = extract_one(a, s, i, out, c, &x, GZ_OK);
        if (r == GZ_E_CANCEL || gz_cancelled(c)) return GZ_E_CANCEL;
    }
    if (!n1) return GZ_OK;
    /* compressed entries sorted by offset: one pass over section 1 */
    u32 *v = (u32 *)gz_alloc((size_t)n1 * 2 * sizeof(u32) + 8);
    if (!v) return GZ_E_NOMEM;
    u32 *t = v + n1, k = 0;
    for (u32 i = 0; i < a->n; i++)
        if (sel[i] && a->e[i].aux32 == 1 && !a->e[i].is_dir && a->e[i].usize) v[k++] = i;
    for (u32 w = 1; w < n1; w *= 2) {
        for (u32 i = 0; i < n1; i += 2 * w) {
            u32 lo = i, mid = i + w < n1 ? i + w : n1, hi = i + 2 * w < n1 ? i + 2 * w : n1;
            u32 p1 = lo, p2 = mid, q = lo;
            while (p1 < mid && p2 < hi) t[q++] = a->e[v[p2]].off < a->e[v[p1]].off ? v[p2++] : v[p1++];
            while (p1 < mid) t[q++] = v[p1++];
            while (p2 < hi) t[q++] = v[p2++];
        }
        __builtin_memcpy(v, t, (size_t)n1 * sizeof(u32));
    }
    xerr = dec_init(&x, a, s, c);
    r = GZ_OK;
    for (u32 i = 0; i < n1; i++) {
        int st = extract_one(a, s, v[i], out, c, &x, xerr);
        if (st == GZ_E_CANCEL || gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
    }
    gz_free(v);
    return r;
}

static void chm_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    const chm_priv *p = (const chm_priv *)a->priv;
    char tmp[16];
    const char *n = "?";
    if (e->aux32 == 0) n = "Copy";
    else if (e->aux32 == 1) {
        if (p->lzx_err) n = "LZX";
        else {
            tmp[0] = 'L'; tmp[1] = 'Z'; tmp[2] = 'X'; tmp[3] = ':';
            tmp[4] = (char)('0' + p->wbits / 10);
            tmp[5] = (char)('0' + p->wbits % 10);
            tmp[6] = 0;
            n = tmp;
        }
    }
    u32 i = 0;
    for (; n[i] && i + 1 < cap; i++) buf[i] = n[i];
    if (cap) buf[i] = 0;
}

/* stored entries can be read in place */
static gz_src *chm_view(gz_archive *a, gz_src *s, u32 idx)
{
    const gz_entry *e = &a->e[idx];
    const chm_priv *p = (const chm_priv *)a->priv;
    if (e->is_dir || e->aux32 != 0) return 0;
    u64 off = p->content + e->off;
    if (off < p->content || off > s->size || e->usize > s->size - off) return 0;
    return gz_src_sub(s, off, e->usize);
}

GZ_FORMAT(gz_fmt_chm)
const gz_format gz_fmt_chm = {
    "CHM", "chm chi chq chw",
    0, chm_probe, chm_open, chm_close, chm_extract, chm_extract_solid, 0, chm_method, chm_view, 0
};
