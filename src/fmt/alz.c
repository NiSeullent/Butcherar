/*
 * 고깃ZIP - ALZ reader (ESTsoft ALZip 4.x - 7.x, .alz)
 *
 * Layout (no official document; cross-checked against unalz 0.65, The
 * Unarchiver and the ALZ reader in ESTsoft's unegg 0.5):
 *   "ALZ\1" version u16 (10) volume u16
 *   local entries "BLZ\1": name length u16, attribute u8 (DOS bits), DOS time u32,
 *     descriptor u8 (bit 0 encrypted, bit 3 comment / "data descriptor", high
 *     nibble = width of the size fields: 1, 2, 4 or 8 bytes, 0 = no size block),
 *     u8; if width: method u8 (0 store, 1 bzip2, 2 deflate, 3 obfuscated deflate),
 *     u8, CRC-32, packed size, unpacked size; name (CP949 by default);
 *     encrypted: 12-byte ZipCrypto header (not counted in the packed size), data
 *   "CLZ\1" central record ... the last 16 bytes are "CLZ\1", comment section
 *     size u32, u32, "CLZ\2"; the comment section "ELZ\1" + (index u32, length
 *     u16, text) records sits before them (index 0xFFFFFFFF = archive comment).
 * Split sets: name.alz, name.a00 .. a99, b00 ...; each volume starts with the
 * 8-byte header (volume number = its index), every volume but the last ends with
 * 16 bytes whose last 4 are "CLZ\3". The entry stream continues across volumes.
 *
 * Methods: store, deflate, deflate with a size-keyed code length order (method 3,
 * see The Unarchiver), bzip2 in ALZip's headerless "DLZ" framing or standard
 * "BZh". ZipCrypto: check byte = CRC >> 24 (or DOS time >> 8 with bit 3, as
 * unalz), password tried as CP949, ANSI and UTF-8.
 */
#include "arc.h"
#include "crc32.h"
#include "bzip2.h"

#define SIG_ALZ   0x015A4C41u          /* "ALZ\1" */
#define SIG_LOCAL 0x015A4C42u          /* "BLZ\1" */
#define SIG_CDIR  0x015A4C43u          /* "CLZ\1" */
#define SIG_END   0x025A4C43u          /* "CLZ\2" */
#define SIG_SPLIT 0x035A4C43u          /* "CLZ\3" */
#define SIG_CMT   0x015A4C45u          /* "ELZ\1" */

#define ALZ_MAX_VOLS 2601u             /* .alz + a00 .. z99 */
#define ALZ_TAIL     16u               /* end of every volume but the last */
#define ALZ_VHDR     8u                /* header of every volume */

enum { AF_TRUNC = 1, AF_VOLUME = 2 }; /* entry aux32: data runs past the end / into a missing volume */

typedef struct {
    u32 nv;                            /* volumes present (a gap ends the set) */
    u32 self;                          /* volume the archive was opened from */
    int incomplete;                    /* a later volume is missing */
    u64 lsize;                         /* size of the joined entry stream */
    u64 *lstart, *poff, *plen;         /* per volume: logical start, data offset, length */
} alz_priv;

/* ---------------- joined volumes ---------------- */

typedef struct {
    gz_src s;
    const alz_priv *pv;
    gz_src *self;
    gz_src **vols;
} join_src;

static gz_src *vol_src(const alz_priv *pv, gz_src *self, gz_src **vols, u32 k)
{
    return k == pv->self ? self : vols[k];
}

static int join_read(gz_src *s, u64 off, void *buf, u32 n, u32 *got)
{
    join_src *j = (join_src *)s;
    const alz_priv *pv = j->pv;
    u8 *p = (u8 *)buf;
    *got = 0;
    if (off >= pv->lsize) return n && pv->incomplete ? GZ_E_VOLUME : GZ_OK;
    u32 lo = 0, hi = pv->nv - 1;                 /* last volume starting at or before off */
    while (lo < hi) {
        u32 mid = lo + (hi - lo + 1) / 2;
        if (pv->lstart[mid] <= off) lo = mid; else hi = mid - 1;
    }
    for (u32 k = lo; n && k < pv->nv; k++) {
        u64 o = off - pv->lstart[k];
        if (o >= pv->plen[k]) continue;
        u32 take = pv->plen[k] - o < n ? (u32)(pv->plen[k] - o) : n, g = 0;
        gz_src *v = vol_src(pv, j->self, j->vols, k);
        int r = v->read_at(v, pv->poff[k] + o, p, take, &g);
        if (r) return r;
        *got += g;
        if (g < take) return GZ_OK;
        p += g; off += g; n -= g;
    }
    if (n && pv->incomplete) return GZ_E_VOLUME;
    return GZ_OK;
}

static void join_free(gz_src *s) { gz_free(s); }

/* the entry stream: s itself for a single file, else a view over the volumes */
static gz_src *stream_src(gz_archive *a, gz_src *s)
{
    alz_priv *pv = (alz_priv *)a->priv;
    if (pv->nv == 1 && !pv->incomplete && pv->self == 0) return s;
    join_src *j = (join_src *)gz_alloc(sizeof(join_src));
    if (!j) return 0;
    j->s.read_at = join_read;
    j->s.size = pv->lsize;
    j->s.free = join_free;
    j->pv = pv;
    j->self = s;
    j->vols = a->vols;
    return &j->s;
}

static void stream_done(gz_src *js, gz_src *s) { if (js && js != s) gz_src_free(js); }

/* ---------------- volume names ---------------- */

/* base length (without the extension) and whether the extension is upper case */
static size_t name_base(const gzch *fn, int *up)
{
    size_t n = gz_wcslen(fn), dot = n;
    for (size_t i = n; i-- > 0;) {
        if (fn[i] == '/' || fn[i] == '\\') break;
        if (fn[i] == '.') { dot = i; break; }
    }
    *up = dot + 1 < n && fn[dot + 1] >= 'A' && fn[dot + 1] <= 'Z';
    return dot;
}

/* volume k: .alz, then .a00 .. .a99, .b00 ... */
static gzch *vol_name(const gzch *fn, size_t base, u32 k, int up)
{
    gzch *v = (gzch *)gz_alloc((base + 6) * sizeof(gzch));
    if (!v) return 0;
    __builtin_memcpy(v, fn, base * sizeof(gzch));
    gzch *p = v + base;
    *p++ = '.';
    if (!k) {
        *p++ = up ? 'A' : 'a'; *p++ = up ? 'L' : 'l'; *p++ = up ? 'Z' : 'z';
    } else {
        k--;
        *p++ = (gzch)((up ? 'A' : 'a') + k / 100);
        *p++ = (gzch)('0' + k / 10 % 10);
        *p++ = (gzch)('0' + k % 10);
    }
    *p = 0;
    return v;
}

static gz_src *open_vol(const gz_open_opts *o, size_t base, u32 k, int up)
{
    for (int t = 0; t < 2; t++) {               /* matching case first */
        gzch *nm = vol_name(o->file_name, base, k, t ? !up : up);
        if (!nm) return 0;
        gz_src *v = 0;
        int r = o->open_volume(o->user, nm, &v);
        gz_free(nm);
        if (!r && v) return v;
    }
    return 0;
}

/* header check of volume k; returns 1 when another volume follows (tail "CLZ\3") */
static int vol_check(gz_src *v, u32 k, int *more)
{
    u8 h[8], t[4];
    if (v->size < ALZ_VHDR + 4 || gz_src_read_exact(v, 0, h, 8) || rd32(h) != SIG_ALZ || rd16(h + 6) != (k & 0xFFFF))
        return 0;
    if (gz_src_read_exact(v, v->size - 4, t, 4)) return 0;
    *more = rd32(t) == SIG_SPLIT && v->size >= ALZ_VHDR + ALZ_TAIL;
    return 1;
}

static int add_vol(alz_priv *pv, u32 k, gz_src *v, int more, u64 *pos)
{
    u64 off = k ? ALZ_VHDR : 0;
    u64 end = v->size - (more ? ALZ_TAIL : 0);
    if (end < off) end = off;
    pv->lstart[k] = *pos;
    pv->poff[k] = off;
    pv->plen[k] = end - off;
    *pos += end - off;
    pv->nv = k + 1;
    return GZ_OK;
}

/* Build the volume table. s: the opened file, volume self (from its header). */
static int open_volumes(gz_archive *a, gz_src *s, const gz_open_opts *o, u32 self, int more_self)
{
    alz_priv *pv = (alz_priv *)a->priv;
    int multi = self != 0 || more_self;
    u32 cap = multi ? ALZ_MAX_VOLS : 1;
    pv->lstart = (u64 *)gz_alloc((size_t)cap * sizeof(u64));
    pv->poff = (u64 *)gz_alloc((size_t)cap * sizeof(u64));
    pv->plen = (u64 *)gz_alloc((size_t)cap * sizeof(u64));
    if (!pv->lstart || !pv->poff || !pv->plen) return GZ_E_NOMEM;
    pv->self = self;
    u64 pos = 0;
    if (!multi) {
        add_vol(pv, 0, s, 0, &pos);
        pv->lsize = pos;
        return GZ_OK;
    }
    int can = o && o->file_name && o->open_volume && !a->parent;
    if (!can && self) return GZ_E_VOLUME;      /* the first volume is needed */
    a->vols = (gz_src **)gz_alloc((size_t)cap * sizeof(gz_src *));
    if (!a->vols) return GZ_E_NOMEM;
    a->nvols = cap;                            /* entries stay NULL where nothing is open */
    int up = 0;
    size_t base = can ? name_base(o->file_name, &up) : 0;
    for (u32 k = 0; k < cap; k++) {
        gz_src *v = k == self ? s : can ? open_vol(o, base, k, up) : 0;
        int more = 0;
        if (!v || !vol_check(v, k, &more)) {
            if (v && v != s) gz_src_free(v);
            if (k == self) return GZ_E_FORMAT;
            if (k < self) return GZ_E_VOLUME;   /* a volume before the opened one is missing */
            pv->incomplete = 1;
            break;
        }
        if (v != s) a->vols[k] = v;
        add_vol(pv, k, v, more, &pos);
        if (!more) break;
        if (k + 1 == cap) pv->incomplete = 1;
    }
    pv->lsize = pos;
    return GZ_OK;
}

static void alz_close(gz_archive *a)
{
    alz_priv *pv = (alz_priv *)a->priv;
    if (pv) {
        gz_free(pv->lstart);
        gz_free(pv->poff);
        gz_free(pv->plen);
        gz_free(pv);
    }
    a->priv = 0;
}

/* ---------------- listing ---------------- */

/* buffered sequential reads of the entry stream */
typedef struct {
    gz_src *s;
    u64 base;
    u32 n;
    u8 b[32768];
} rbuf;

/* n <= 4096 bytes at off; GZ_E_TRUNC when the stream ends first */
static int rb_get(rbuf *rb, u64 off, void *dst, u32 n)
{
    if (off < rb->base || off - rb->base + n > rb->n) {
        if (off >= rb->s->size || n > rb->s->size - off) return GZ_E_TRUNC;
        u32 want = sizeof rb->b, got = 0;
        if (want > rb->s->size - off) want = (u32)(rb->s->size - off);
        rb->n = 0;
        int r = rb->s->read_at(rb->s, off, rb->b, want, &got);
        if (r) return r;
        rb->base = off;
        rb->n = got;
        if (got < n) return GZ_E_TRUNC;
    }
    __builtin_memcpy(dst, rb->b + (off - rb->base), n);
    return GZ_OK;
}

static u64 rd_width(const u8 *p, u32 w)
{
    switch (w) {
    case 1: return p[0];
    case 2: return rd16(p);
    case 4: return rd32(p);
    default: return rd64(p);
    }
}

/* archive comment from the end record (index 0xFFFFFFFF in the "ELZ\1" section) */
static void read_comment(gz_archive *a, rbuf *rb, u64 lsize)
{
    u8 t[16], h[6];
    if (lsize < 16 + 8 || rb_get(rb, lsize - 16, t, 16)) return;
    if (rd32(t) != SIG_CDIR || rd32(t + 12) != SIG_END) return;
    u64 size = rd32(t + 4);
    if (size < 4 + 6 || size > lsize - 16 - 8 || size > (16u << 20)) return;
    u64 p = lsize - 16 - size, end = lsize - 16;
    if (rb_get(rb, p, h, 4) || rd32(h) != SIG_CMT) return;
    p += 4;
    while (p + 6 <= end) {
        if (rb_get(rb, p, h, 6)) return;
        u32 idx = rd32(h), len = rd16(h + 4);
        p += 6;
        if (p + len > end) return;
        if (idx == 0xFFFFFFFFu && len && !a->comment_raw) {
            u8 *c = (u8 *)gz_alloc(len);
            if (!c) return;
            u32 k = 0;
            while (k < len) {
                u32 m = len - k > 4096 ? 4096 : len - k;
                if (rb_get(rb, p + k, c + k, m)) { gz_free(c); return; }
                k += m;
            }
            a->comment_raw = c;
            a->comment_len = len;
            a->comment_enc = GZ_NE_LEGACY;
        }
        p += len;
    }
}

static int alz_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    u8 h[16];
    if (s->size < 12 || gz_src_read_exact(s, 0, h, 8) || rd32(h) != SIG_ALZ) return GZ_E_FORMAT;
    u32 self = rd16(h + 6);
    if (self >= ALZ_MAX_VOLS) return GZ_E_FORMAT;
    int more = 0;
    if (gz_src_read_exact(s, s->size - 4, h + 8, 4)) return GZ_E_FORMAT;
    more = rd32(h + 8) == SIG_SPLIT && s->size >= ALZ_VHDR + ALZ_TAIL;
    alz_priv *pv = (alz_priv *)gz_alloc(sizeof(alz_priv));
    if (!pv) return GZ_E_NOMEM;
    a->priv = pv;
    int r = open_volumes(a, s, o, self, more);
    if (r) return r;
    gz_src *js = stream_src(a, s);
    rbuf *rb = (rbuf *)gz_alloc(sizeof(rbuf));
    if (!js || !rb) { stream_done(js, s); gz_free(rb); return GZ_E_NOMEM; }
    rb->s = js;
    a->win_names = 1;
    u64 pos = 8, lsize = pv->lsize;
    int bad = 0;
    r = GZ_OK;
    for (;;) {
        if ((a->n & 1023) == 1023) {
            if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
            if (c && c->progress) c->progress(c->progress_user, pos, lsize);
        }
        if (rb_get(rb, pos, h, 4)) break;               /* end of the stream (or a missing volume) */
        u32 sig = rd32(h);
        if (sig != SIG_LOCAL) {
            if (sig != SIG_CDIR && sig != SIG_CMT && sig != SIG_END && sig != SIG_SPLIT) bad = 1;
            break;
        }
        if (rb_get(rb, pos + 4, h, 9)) break;
        u32 nlen = rd16(h), attr = h[2], dt = rd32(h + 3), desc = h[7];
        u32 w = desc >> 4;
        if (w != 0 && w != 1 && w != 2 && w != 4 && w != 8) { bad = 1; break; }
        u64 p = pos + 13, csize = 0, usize = 0;
        u32 method = 0, crc = 0;
        if (w) {
            u8 x[22];
            if (rb_get(rb, p, x, 6 + 2 * w)) break;
            method = x[0];
            crc = rd32(x + 2);
            csize = rd_width(x + 6, w);
            usize = rd_width(x + 6 + w, w);
            p += 6 + 2 * w;
        }
        u8 nm[4096];
        u32 rn = nlen < sizeof nm ? nlen : (u32)sizeof nm;     /* longer names are cut */
        if (nlen && rb_get(rb, p, nm, rn)) break;
        p += nlen;
        u64 hdr = 0;
        if (desc & 1) { hdr = p; p += 12; }
        gz_entry *e;
        if ((r = gz_arc_add_named(a, nm, rn, GZ_NE_LEGACY, &e))) break;
        e->off = p;
        e->aux = hdr;
        e->csize = csize;
        e->usize = usize;
        e->crc = crc;
        e->has_crc = w != 0;
        e->method = (u16)method;
        e->flags = (u16)desc;
        e->mtime = dt;
        e->mtime_kind = GZ_MT_DOS;
        e->dos_time = (u16)dt;
        e->attr = attr & 0x27;
        if ((attr & 0x10) || (rn && (nm[rn - 1] == '/' || nm[rn - 1] == '\\'))) e->is_dir = 1;
        if (e->is_dir) { e->attr |= 0x10; e->has_crc = 0; }
        if (desc & 1) e->enc = GZ_ENC_ZIPCRYPTO;
        if (p > lsize || csize > lsize - p) {
            /* data runs past the end: a missing volume or a cut file */
            e->aux32 = pv->incomplete ? AF_VOLUME : AF_TRUNC;
            break;
        }
        pos = p + csize;
    }
    if (r == GZ_OK) read_comment(a, rb, lsize);
    gz_free(rb);
    stream_done(js, s);
    if (r) return r;
    if (!a->n && bad) return GZ_E_FORMAT;
    return GZ_OK;
}

/* ---------------- extraction ---------------- */

typedef struct {
    gz_src *src;
    u64 pos, end;
    volatile long *cancel;
    int enc;
    gz_zipcrypto zc;
    u8 pre[4];                 /* bytes already read (method sniffing), handed out first */
    u32 pre_n, pre_i;
    gz_out *out;
    u64 written, limit;
    int do_crc;
    u32 crc;
} ax;

static int ax_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    ax *x = (ax *)ctx;
    *got = 0;
    if (x->cancel && *x->cancel) return GZ_E_CANCEL;
    if (x->pre_i < x->pre_n) {
        u32 k = x->pre_n - x->pre_i;
        if (k > cap) k = cap;
        __builtin_memcpy(buf, x->pre + x->pre_i, k);
        x->pre_i += k;
        *got = k;
        return GZ_OK;
    }
    u64 left = x->end - x->pos;
    if (!left || !cap) return GZ_OK;
    u32 n = left < cap ? (u32)left : cap, g = 0;
    int r = x->src->read_at(x->src, x->pos, buf, n, &g);
    if (r) return r;
    if (!g) return GZ_E_TRUNC;
    x->pos += g;
    if (x->enc) gz_zc_decrypt(&x->zc, buf, g);
    *got = g;
    return GZ_OK;
}

static int ax_write(void *ctx, const u8 *p, size_t n)
{
    ax *x = (ax *)ctx;
    if (n > x->limit - x->written) return GZ_E_DATA;      /* more than declared */
    x->written += n;
    if (x->do_crc) x->crc = gz_crc32(x->crc, p, n);
    return x->out ? x->out->write(x->out, p, n) : GZ_OK;
}

static void *bz_new(void) { return gz_bzip2_dec_new(); }
static void bz_free(void *p) { gz_bzip2_dec_free((gz_bzip2_dec *)p); }

/* code length order of method 3: The Unarchiver's CalculateSillyTable(param) */
static void obf_order(u32 param, u8 ord[19])
{
    for (u32 i = 0; i < 19; i++) ord[i] = (u8)i;
    for (u32 i = 0; i < 19; i++) {
        u32 j = (i % 6) * 3 + param;
        if (j > 18) j %= 18;
        if (j != i) { u8 t = ord[i]; ord[i] = ord[j]; ord[j] = t; }
    }
}

/* ZipCrypto header check for one password encoding; fills zc on success */
static int pw_check(gz_src *js, const gz_entry *e, const u8 *pw, size_t pwn, gz_zipcrypto *zc)
{
    u8 h[12];
    int r = gz_src_read_exact(js, e->aux, h, 12);
    if (r) return r == GZ_E_TRUNC && (e->aux32 & AF_VOLUME) ? GZ_E_VOLUME : r;
    gz_zc_init(zc, pw, pwn);
    gz_zc_decrypt(zc, h, 12);
    if (h[11] == (u8)(e->crc >> 24)) return GZ_OK;
    if ((e->flags & 8) && h[11] == (u8)(e->dos_time >> 8)) return GZ_OK;
    return GZ_E_PASSWORD;
}

/* decode one entry into out (NULL: CRC check only); zc: decryption state or NULL */
static int decode_entry(const gz_entry *e, gz_src *js, const gz_zipcrypto *zc, gz_out *out, gz_ctx *c)
{
    if (e->aux32) return e->aux32 & AF_VOLUME ? GZ_E_VOLUME : GZ_E_TRUNC;
    ax x;
    __builtin_memset(&x, 0, sizeof x);
    x.src = js;
    x.pos = e->off;
    x.end = e->off + e->csize;
    x.cancel = c->cancel;
    if (zc) { x.enc = 1; x.zc = *zc; }
    x.out = out;
    x.limit = e->usize;
    gz_stream_io io = { ax_read, ax_write, &x };
    int st;
    u64 total;
    u32 crc;
    switch (e->method) {
    case 0: {                                     /* store: the packed bytes are the file */
        u8 *buf = gz_ctx_buffer(c, 256u << 10);
        if (!buf) return GZ_E_NOMEM;
        x.do_crc = 1;
        st = GZ_OK;
        for (;;) {
            u32 got = 0;
            if ((st = ax_read(&x, buf, 256u << 10, &got)) || !got) break;
            if ((st = ax_write(&x, buf, got))) break;
        }
        total = x.written;
        crc = x.crc;
        break;
    }
    case 1: {                                     /* bzip2: "DLZ\1" blocks or a standard stream */
        u8 t[4];
        u32 tn = 0, got = 1;
        st = GZ_OK;
        while (tn < 4 && got && !(st = ax_read(&x, t + tn, 4 - tn, &got))) tn += got;
        __builtin_memcpy(x.pre, t, tn);
        x.pre_n = tn;
        if (st || tn < 4) { if (!st) st = GZ_E_DATA; total = 0; crc = 0; break; }
        gz_bzip2_dec *d = (gz_bzip2_dec *)gz_ctx_slot(c, GZ_SLOT_BZIP2, bz_new, bz_free);
        if (!d) return GZ_E_NOMEM;
        x.do_crc = 1;
        if (rd32(x.pre) == 0x015A4C44u) st = gz_bzip2_decode_alz(d, &io, e->usize, 0);
        else st = gz_bzip2_decode(d, &io, e->usize, 0, 0);
        if (st == GZ_E_FORMAT) st = GZ_E_DATA;
        total = x.written;
        crc = x.crc;
        break;
    }
    case 2: case 3: {
        gz_inflater *z = gz_ctx_inflater(c);
        if (!z) return GZ_E_NOMEM;
        if (e->method == 2) st = gz_inflate_run(z, &io, 0);
        else {
            u8 ord[19];
            obf_order((u32)(e->usize & 15), ord);
            st = gz_inflate_run_order(z, &io, ord);
        }
        total = z->total_out;
        crc = z->crc;
        break;
    }
    default:
        return GZ_E_METHOD;
    }
    if (!st && total != e->usize) st = GZ_E_DATA;
    if (!st && e->has_crc && crc != e->crc) st = zc ? GZ_E_PASSWORD : GZ_E_CRC;
    return st;
}

/* password encodings: CP949 (ALZip's), the ANSI code page, UTF-8 */
typedef struct { u8 b[3][768]; size_t n[3]; int count; } pw_set;

static void pw_candidates(const gzch *pw, pw_set *ps)
{
    ps->count = 0;
    if (!pw) return;
    size_t wn = gz_wcslen(pw);
    if (wn > 250) wn = 250;
    int cps[2] = { 949, gz_plat_acp() };
    for (int k = 0; k < 3; k++) {
        int n = k < 2 ? (gz_plat_cp_valid(cps[k]) ? gz_plat_wc2mb(cps[k], pw, (int)wn, ps->b[ps->count], 760) : 0)
                      : gz_utf16_to_utf8(pw, wn, ps->b[ps->count]);
        if (n <= 0 && !(n == 0 && wn == 0)) continue;
        int dup = 0;
        for (int j = 0; j < ps->count; j++)
            if (ps->n[j] == (size_t)n && !__builtin_memcmp(ps->b[j], ps->b[ps->count], (size_t)n)) dup = 1;
        if (!dup) ps->n[ps->count++] = (size_t)n;
    }
}

static int null_open(gz_out *o, u32 idx) { (void)o; (void)idx; return GZ_OK; }
static int null_write(gz_out *o, const u8 *p, size_t n) { (void)o; (void)p; (void)n; return GZ_OK; }
static int null_close(gz_out *o, u32 idx, int st) { (void)o; (void)idx; (void)st; return GZ_OK; }

/* find the ZipCrypto state for an encrypted entry: GZ_OK and *zc, or an error */
static int find_key(const gz_entry *e, gz_src *js, gz_ctx *c, gz_zipcrypto *zc)
{
    pw_set *ps = (pw_set *)gz_alloc(sizeof(pw_set));
    if (!ps) return GZ_E_NOMEM;
    pw_candidates(c->password, ps);
    gz_zipcrypto ok[3];
    int np = 0, err = GZ_E_PASSWORD;
    for (int k = 0; k < ps->count; k++) {
        int r = pw_check(js, e, ps->b[k], ps->n[k], &ok[np]);
        if (!r) np++;
        else if (r != GZ_E_PASSWORD) err = r;
    }
    gz_free(ps);
    if (!np) return err;
    *zc = ok[0];
    if (np > 1) {
        /* several encodings pass the 1-byte check: take the one that decodes */
        gz_out nul = { null_open, null_write, null_close, 0 };
        for (int k = 0; k < np; k++)
            if (!decode_entry(e, js, &ok[k], &nul, c)) { *zc = ok[k]; break; }
    }
    return GZ_OK;
}

static int alz_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    gz_entry *e = &a->e[idx];
    if (e->is_dir) {
        int r = out->open(out, idx);
        return r ? r : out->close(out, idx, GZ_OK);
    }
    gz_src *js = stream_src(a, s);
    if (!js) return GZ_E_NOMEM;
    gz_zipcrypto zc;
    int r = GZ_OK;
    if (e->enc && (r = find_key(e, js, c, &zc))) { stream_done(js, s); return r; }
    if ((r = out->open(out, idx))) { stream_done(js, s); return r; }
    int st = decode_entry(e, js, e->enc ? &zc : 0, out, c);
    stream_done(js, s);
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static int alz_check_password(gz_archive *a, gz_src *s, u32 idx, gz_ctx *c)
{
    gz_entry *e = &a->e[idx];
    if (!e->enc || e->is_dir) return GZ_OK;
    gz_src *js = stream_src(a, s);
    if (!js) return GZ_E_NOMEM;
    gz_zipcrypto zc;
    int r = find_key(e, js, c, &zc);
    stream_done(js, s);
    return r;
}

static void alz_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    const char *m;
    switch (e->method) {
    case 0: m = "Store"; break;
    case 1: m = "BZip2"; break;
    case 2: m = "Deflate"; break;
    case 3: m = "Obfuscated Deflate"; break;
    default: m = "?"; break;
    }
    const char *enc = e->enc ? " ZipCrypto" : "";
    u32 i = 0;
    for (; *m && i + 1 < cap; m++) buf[i++] = *m;
    for (; *enc && i + 1 < cap; enc++) buf[i++] = *enc;
    if (cap) buf[i] = 0;
}

/* stored, unencrypted entries inside one volume can be read in place */
static gz_src *alz_view(gz_archive *a, gz_src *s, u32 idx)
{
    gz_entry *e = &a->e[idx];
    alz_priv *pv = (alz_priv *)a->priv;
    if (e->is_dir || e->enc || e->method != 0 || e->aux32 || e->csize != e->usize) return 0;
    for (u32 k = 0; k < pv->nv; k++) {
        if (e->off < pv->lstart[k] || e->off - pv->lstart[k] >= pv->plen[k]) continue;
        u64 o = e->off - pv->lstart[k];
        if (e->usize > pv->plen[k] - o) return 0;              /* spans volumes */
        gz_src *v = vol_src(pv, s, a->vols, k);
        return v ? gz_src_sub(v, pv->poff[k] + o, e->usize) : 0;
    }
    return 0;
}

static int alz_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 8 || rd32(h) != SIG_ALZ) return 0;
    return rd16(h + 4) == 10 ? 95 : 80;
}

GZ_FORMAT(gz_fmt_alz)
const gz_format gz_fmt_alz = {
    "ALZ", "alz a00",
    0, alz_probe, alz_open, alz_close, alz_extract, 0, alz_check_password, alz_method, alz_view, 0
};
