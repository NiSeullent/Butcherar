/*
 * 고깃ZIP - EGG reader (ESTsoft ALZip 8 and later, .egg)
 *
 * Follows the EGG Format Specification 1.0 (ESTsoft, 2009-2016) and the reader
 * in ESTsoft's unegg 0.5:
 *   EGG header "EGGA" version u16, header id u32, reserved u32; extra fields
 *   (split: prev id, next id; solid; global encryption) up to END 0x08E28222
 *   files: FILE id u32, length u64; fields (filename, comment, Windows info:
 *     FILETIME + attribute, POSIX info: mode uid gid time_t, encryption) up to END;
 *     blocks: BLOCK method u8, hint u8, unpacked u32, packed u32, CRC-32, fields
 *     up to END, then the packed data (files > 4 GiB use several blocks)
 *   solid archives: the files carry no blocks; the blocks after the last file
 *     (each one an independent stream) are cut into the files by their lengths
 *   archive comment after the files, END at the very end
 * Every field: signature u32, flags u8 (bit 0: 32-bit size), size u16/u32, data.
 * Unknown fields, Dummy (0x07463307) and Skip (0xFFFF0000) fields are skipped.
 * Split sets (name.vol1.egg, name.vol2.egg ...): every volume repeats the EGG
 * header with a split field; the data continues after the volume's END, headers
 * and fields are never cut. Volumes are chained by header id (prev/next).
 *
 * Methods: 0 store, 1 deflate, 2 bzip2, 3 AZO (azo.c), 4 LZMA (9-byte header:
 * 4 bytes, then the 5 LZMA properties). Encryption (per file): 0 ZipCrypto
 * (12-byte header + CRC-32 in the field, check byte = CRC >> 24), 1/2 AES-128/256
 * and 5/6 LEA-128/256 (salt + 2-byte check from PBKDF2-HMAC-SHA1 x1000, WinZip
 * style AES-CTR resp. LEA-CTR with a big-endian counter from 0, 10-byte
 * HMAC-SHA1 of the encrypted data in the field). Names: UTF-8, or a code page
 * (locale 949, 932 ...) when flag bit 3 is set; relative names name their parent
 * by file id. Passwords are tried as UTF-8, CP949 and the ANSI code page.
 */
#include "arc.h"
#include "crc32.h"
#include "bzip2.h"
#include "xz.h"
#include "azo.h"
#include "lea.h"

#define SIG_EGG     0x41474745u
#define SIG_FILE    0x0A8590E3u
#define SIG_BLOCK   0x02B50C13u
#define SIG_ENCRYPT 0x08D1470Fu
#define SIG_WINFO   0x2C86950Bu
#define SIG_PINFO   0x1EE922E5u
#define SIG_NAME    0x0A8591ACu
#define SIG_COMMENT 0x04C63672u
#define SIG_SPLIT   0x24F5A262u
#define SIG_SOLID   0x24E5A060u
#define SIG_DUMMY   0x07463307u
#define SIG_END     0x08E28222u
#define SIG_SKIP    0xFFFF0000u
#define SIG_GENC    0x08D144A8u

#define EGG_MAX_VOLS   10000u
#define EGG_MAX_FIELDS 65536u          /* fields in one list */
#define EGG_NAME_MAX   8192u           /* longer names are cut */
#define EGG_ENC_MAX    40u

enum { M_STORE = 0, M_DEFLATE = 1, M_BZIP2 = 2, M_AZO = 3, M_LZMA = 4 };
enum { C_ZIP = 0, C_AES128 = 1, C_AES256 = 2, C_LEA128 = 5, C_LEA256 = 6 };
enum { T_OK = 0, T_TRUNC = 1, T_VOLUME = 2 };

typedef struct {
    u64 off;                           /* data in the joined stream */
    u64 ustart;                        /* solid: position in the solid output */
    u32 csize, usize, crc;
    u8 method, trunc;
} egg_blk;

typedef struct {
    u8 method, len;                    /* len: payload bytes after the method byte */
    u8 d[EGG_ENC_MAX];
} egg_enc;

typedef struct {
    u32 blk0, nblk;                    /* blocks (non-solid archives) */
    u32 enc;                           /* encryption field index + 1, 0 = none */
    u32 id, parent;
    u8 rel;                            /* name relative to the parent's path */
} egg_ent;

typedef struct {
    /* volumes */
    u32 nv, self;
    int incomplete;
    u64 lsize;
    u64 *lstart, *poff, *plen;
    /* directory */
    egg_blk *blk; u32 nblk, cblk;
    egg_enc *enc; u32 nenc, cenc;
    egg_ent *ent; u32 cent;
    int solid;
    u32 senc;                          /* solid stream encryption (index + 1) */
    u64 stotal;                        /* solid output size */
} egg_priv;

/* ---------------- joined volumes ---------------- */

typedef struct {
    gz_src s;
    const egg_priv *pv;
    gz_src *self;
    gz_src **vols;
} join_src;

static gz_src *vol_src(const egg_priv *pv, gz_src *self, gz_src **vols, u32 k)
{
    return k == pv->self ? self : vols[k];
}

static int join_read(gz_src *s, u64 off, void *buf, u32 n, u32 *got)
{
    join_src *j = (join_src *)s;
    const egg_priv *pv = j->pv;
    u8 *p = (u8 *)buf;
    *got = 0;
    if (off >= pv->lsize) return n && pv->incomplete ? GZ_E_VOLUME : GZ_OK;
    u32 lo = 0, hi = pv->nv - 1;
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

static gz_src *stream_src(gz_archive *a, gz_src *s)
{
    egg_priv *pv = (egg_priv *)a->priv;
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

/* ---------------- buffered reads and fields ---------------- */

typedef struct {
    gz_src *s;
    u64 base;
    u32 n;
    u8 b[32768];
} rbuf;

/* n <= 8192 bytes at off; GZ_E_TRUNC when the stream ends first */
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

static int rb_u32(rbuf *rb, u64 off, u32 *v)
{
    u8 b[4];
    int r = rb_get(rb, off, b, 4);
    if (!r) *v = rd32(b);
    return r;
}

typedef struct { u32 sig, flags; u64 size, data, next; } egg_field;

/* field at pos (signature already known not to be END) */
static int rd_field(rbuf *rb, u64 pos, egg_field *f)
{
    u8 h[9];
    int r = rb_get(rb, pos, h, 7);
    if (r) return r;
    f->sig = rd32(h);
    f->flags = h[4];
    if (f->flags & 1) {
        if ((r = rb_get(rb, pos, h, 9))) return r;
        f->size = rd32(h + 5);
        f->data = pos + 9;
    } else {
        f->size = rd16(h + 5);
        f->data = pos + 7;
    }
    if (f->data > rb->s->size || f->size > rb->s->size - f->data) return GZ_E_TRUNC;
    f->next = f->data + f->size;
    return GZ_OK;
}

/* known signature of something that may follow a field */
static int known_sig(u32 s)
{
    switch (s) {
    case SIG_FILE: case SIG_BLOCK: case SIG_ENCRYPT: case SIG_WINFO: case SIG_PINFO: case SIG_NAME:
    case SIG_COMMENT: case SIG_SPLIT: case SIG_SOLID: case SIG_DUMMY: case SIG_END: case SIG_SKIP: case SIG_GENC:
        return 1;
    }
    return 0;
}

/* ---------------- volumes ---------------- */

typedef struct {
    u32 id, prev, next;
    int split, solid;
    u64 end;                           /* offset after the END of the prefix */
    egg_enc genc;
    int has_genc;
} egg_prefix;

static int read_prefix(gz_src *s, egg_prefix *pf)
{
    rbuf *rb = (rbuf *)gz_alloc(sizeof(rbuf));
    if (!rb) return GZ_E_NOMEM;
    rb->s = s;
    __builtin_memset(pf, 0, sizeof *pf);
    u8 h[14];
    int r = rb_get(rb, 0, h, 14);
    if (!r && rd32(h) != SIG_EGG) r = GZ_E_FORMAT;
    u64 pos = 14;
    if (!r) pf->id = rd32(h + 6);
    for (u32 k = 0; !r; k++) {
        u32 sig;
        if (k == EGG_MAX_FIELDS || (r = rb_u32(rb, pos, &sig))) { r = GZ_E_FORMAT; break; }
        if (sig == SIG_END) { pf->end = pos + 4; break; }
        egg_field f;
        if ((r = rd_field(rb, pos, &f))) { r = GZ_E_FORMAT; break; }
        if (f.sig == SIG_SPLIT && f.size >= 8) {
            u8 d[8];
            if ((r = rb_get(rb, f.data, d, 8))) break;
            pf->split = 1;
            pf->prev = rd32(d);
            pf->next = rd32(d + 4);
        } else if (f.sig == SIG_SOLID) {
            pf->solid = 1;
        } else if (f.sig == SIG_GENC && f.size >= 1 && !pf->has_genc) {
            u32 n = f.size - 1 < EGG_ENC_MAX ? (u32)f.size - 1 : EGG_ENC_MAX;
            u8 d[EGG_ENC_MAX + 1];
            if ((r = rb_get(rb, f.data, d, n + 1))) break;
            pf->genc.method = d[0];
            pf->genc.len = (u8)n;
            __builtin_memcpy(pf->genc.d, d + 1, n);
            pf->has_genc = 1;
        }
        pos = f.next;
    }
    gz_free(rb);
    return r;
}

/* "name.volN.egg": base length (up to ".vol") and N, else 0 */
static u32 vol_number(const gzch *fn, size_t *base)
{
    size_t n = gz_wcslen(fn), i = n;
    while (i > 0 && fn[i - 1] != '.' && fn[i - 1] != '/' && fn[i - 1] != '\\') i--;
    if (!i || fn[i - 1] != '.') return 0;
    size_t dot = i - 1;                        /* the extension's dot */
    size_t d = dot;
    while (d > 0 && fn[d - 1] >= '0' && fn[d - 1] <= '9') d--;
    if (d == dot || dot - d > 6 || d < 4) return 0;
    if (fn[d - 4] != '.' || (fn[d - 3] | 0x20) != 'v' || (fn[d - 2] | 0x20) != 'o' || (fn[d - 1] | 0x20) != 'l') return 0;
    u32 v = 0;
    for (size_t k = d; k < dot; k++) v = v * 10 + (u32)(fn[k] - '0');
    *base = d - 4;
    return v;
}

/* base + ".volK.egg" */
static gzch *vol_name(const gzch *fn, size_t base, u32 k, int up)
{
    gzch *v = (gzch *)gz_alloc((base + 24) * sizeof(gzch));
    if (!v) return 0;
    __builtin_memcpy(v, fn, base * sizeof(gzch));
    gzch *p = v + base;
    const char *a = up ? ".VOL" : ".vol", *b = up ? ".EGG" : ".egg";
    while (*a) *p++ = (gzch)*a++;
    char d[12];
    int nd = 0;
    do { d[nd++] = (char)('0' + k % 10); k /= 10; } while (k);
    while (nd) *p++ = (gzch)d[--nd];
    while (*b) *p++ = (gzch)*b++;
    *p = 0;
    return v;
}

static gz_src *open_vol(const gz_open_opts *o, size_t base, u32 k, int up)
{
    for (int t = 0; t < 2; t++) {
        gzch *nm = vol_name(o->file_name, base, k, t ? !up : up);
        if (!nm) return 0;
        gz_src *v = 0;
        int r = o->open_volume(o->user, nm, &v);
        gz_free(nm);
        if (!r && v) return v;
    }
    return 0;
}

static int open_volumes(gz_archive *a, gz_src *s, const gz_open_opts *o, const egg_prefix *pf)
{
    egg_priv *pv = (egg_priv *)a->priv;
    int multi = pf->split && (pf->prev || pf->next);
    u32 cap = multi ? 64 : 1;
    pv->lstart = (u64 *)gz_alloc(cap * sizeof(u64));
    pv->poff = (u64 *)gz_alloc(cap * sizeof(u64));
    pv->plen = (u64 *)gz_alloc(cap * sizeof(u64));
    if (!pv->lstart || !pv->poff || !pv->plen) return GZ_E_NOMEM;
    if (!multi) {
        pv->nv = 1;
        pv->plen[0] = pv->lsize = s->size;
        return GZ_OK;
    }
    size_t base = 0;
    int up = 0;
    int can = o && o->file_name && o->open_volume && !a->parent;
    u32 num = can ? vol_number(o->file_name, &base) : 0;
    if (pf->prev == 0) pv->self = 0;
    else if (num >= 2) pv->self = num - 1;
    else return GZ_E_VOLUME;                   /* a later volume without the usual name */
    if (can && !num) {                         /* first volume named "name.egg" */
        size_t n = gz_wcslen(o->file_name), b = n;
        for (size_t i = n; i-- > 0;) {
            if (o->file_name[i] == '/' || o->file_name[i] == '\\') break;
            if (o->file_name[i] == '.') { b = i; break; }
        }
        base = b;
    }
    if (can) {
        size_t n = gz_wcslen(o->file_name);
        up = n >= 3 && o->file_name[n - 3] >= 'A' && o->file_name[n - 3] <= 'Z';
    }
    u32 nvcap = cap;
    a->vols = (gz_src **)gz_alloc(nvcap * sizeof(gz_src *));
    if (!a->vols) return GZ_E_NOMEM;
    a->nvols = nvcap;
    u64 pos = 0;
    u32 want = 0;                              /* header id the next volume must have */
    for (u32 k = 0;; k++) {
        if (k == EGG_MAX_VOLS) { pv->incomplete = 1; break; }
        if (k == nvcap) {
            u32 nc = nvcap * 2;
            u64 *l1 = (u64 *)gz_realloc(pv->lstart, nc * sizeof(u64));
            if (l1) pv->lstart = l1;
            u64 *l2 = (u64 *)gz_realloc(pv->poff, nc * sizeof(u64));
            if (l2) pv->poff = l2;
            u64 *l3 = (u64 *)gz_realloc(pv->plen, nc * sizeof(u64));
            if (l3) pv->plen = l3;
            gz_src **vv = (gz_src **)gz_realloc(a->vols, nc * sizeof(gz_src *));
            if (vv) a->vols = vv;
            if (!l1 || !l2 || !l3 || !vv) return GZ_E_NOMEM;
            for (u32 i = nvcap; i < nc; i++) a->vols[i] = 0;
            a->nvols = nvcap = nc;
        }
        gz_src *v = k == pv->self ? s : can ? open_vol(o, base, k + 1, up) : 0;
        egg_prefix q;
        int ok = v && !read_prefix(v, &q) && q.split && (k ? q.id == want : q.prev == 0);
        if (!ok) {
            if (v && v != s) gz_src_free(v);
            if (k == pv->self) return GZ_E_FORMAT;
            if (k < pv->self) return GZ_E_VOLUME;
            pv->incomplete = 1;
            break;
        }
        if (v != s) a->vols[k] = v;
        u64 off = k ? q.end : 0;
        if (off > v->size) off = v->size;
        pv->lstart[k] = pos;
        pv->poff[k] = off;
        pv->plen[k] = v->size - off;
        pos += v->size - off;
        pv->nv = k + 1;
        if (!q.next) break;
        want = q.next;
    }
    pv->lsize = pos;
    return GZ_OK;
}

static void egg_close(gz_archive *a)
{
    egg_priv *pv = (egg_priv *)a->priv;
    if (pv) {
        gz_free(pv->lstart);
        gz_free(pv->poff);
        gz_free(pv->plen);
        gz_free(pv->blk);
        gz_free(pv->enc);
        gz_free(pv->ent);
        gz_free(pv);
    }
    a->priv = 0;
}

/* ---------------- listing ---------------- */

static int add_blk(egg_priv *pv, const egg_blk *b)
{
    if (pv->nblk == pv->cblk) {
        if (pv->cblk >= (1u << 26)) return GZ_E_LIMIT;
        u32 nc = pv->cblk ? pv->cblk * 2 : 64;
        egg_blk *n = (egg_blk *)gz_realloc(pv->blk, (size_t)nc * sizeof(egg_blk));
        if (!n) return GZ_E_NOMEM;
        pv->blk = n;
        pv->cblk = nc;
    }
    pv->blk[pv->nblk++] = *b;
    return GZ_OK;
}

static int add_enc(egg_priv *pv, const egg_enc *x, u32 *idx)
{
    if (pv->nenc == pv->cenc) {
        if (pv->cenc >= (1u << 26)) return GZ_E_LIMIT;
        u32 nc = pv->cenc ? pv->cenc * 2 : 16;
        egg_enc *n = (egg_enc *)gz_realloc(pv->enc, (size_t)nc * sizeof(egg_enc));
        if (!n) return GZ_E_NOMEM;
        pv->enc = n;
        pv->cenc = nc;
    }
    pv->enc[pv->nenc++] = *x;
    *idx = pv->nenc;
    return GZ_OK;
}

/* payload size of an encryption field without the footer (with it: + 10) */
static u32 enc_need(u32 m)
{
    switch (m) {
    case C_ZIP: return 16;
    case C_AES128: case C_LEA128: return 10;
    case C_AES256: case C_LEA256: return 18;
    }
    return 0;
}

/* decode a name in code page cp to UTF-8 into out (cap >= 3 * n); length or -1 */
static int cp_to_utf8(int cp, const u8 *s, u32 n, u8 *out)
{
    if (!n) return 0;
    if (!gz_plat_cp_valid(cp)) return -1;
    gzch *w = (gzch *)gz_alloc(((size_t)n + 2) * sizeof(gzch));
    if (!w) return -1;
    int m = gz_plat_mb2wc(cp, s, (int)n, w, (int)n + 1);
    int k = m > 0 ? gz_utf16_to_utf8(w, (size_t)m, out) : -1;
    gz_free(w);
    return k;
}

typedef struct {
    u8 name[EGG_NAME_MAX];
    u8 conv[EGG_NAME_MAX * 3];
} name_buf;

/* parse one file (FILE signature at pos): its fields; *pos moves past the END */
static int parse_file(gz_archive *a, rbuf *rb, u64 *ppos, name_buf *nb, u32 *cur)
{
    egg_priv *pv = (egg_priv *)a->priv;
    u8 h[12];
    u64 pos = *ppos + 4;
    int r = rb_get(rb, pos, h, 12);
    if (r) return r;
    u32 id = rd32(h);
    u64 length = rd64(h + 4);
    pos += 12;
    u32 nlen = 0, nflags = 0, locale = 0, parent = 0, enc = 0;
    int have_name = 0, have_mt = 0, is_dir = 0, is_link = 0;
    u64 mtime = 0;
    u32 wattr = 0, mode = 0;
    for (u32 k = 0;; k++) {
        u32 sig;
        if (k == EGG_MAX_FIELDS) return GZ_E_FORMAT;
        if ((r = rb_u32(rb, pos, &sig))) return r;
        if (sig == SIG_END) { pos += 4; break; }
        if (sig == SIG_FILE || sig == SIG_BLOCK) break;        /* END missing: tolerated */
        egg_field f;
        if ((r = rd_field(rb, pos, &f))) return r;
        if (f.sig == SIG_NAME && !have_name) {
            u64 p = f.data, left = f.size;
            nflags = f.flags;
            if (nflags & 8) {                                  /* code page instead of UTF-8 */
                u8 d[2];
                if (left < 2 || (r = rb_get(rb, p, d, 2))) return r ? r : GZ_E_FORMAT;
                locale = rd16(d);
                p += 2; left -= 2;
            }
            if (nflags & 16) {                                 /* relative to the parent's path */
                u8 d[4];
                if (left < 4 || (r = rb_get(rb, p, d, 4))) return r ? r : GZ_E_FORMAT;
                parent = rd32(d);
                p += 4; left -= 4;
            }
            nlen = left < EGG_NAME_MAX ? (u32)left : EGG_NAME_MAX;
            if (nlen && (r = rb_get(rb, p, nb->name, nlen))) return r;
            while (nlen && !nb->name[nlen - 1]) nlen--;        /* a stray terminator */
            have_name = 1;
        } else if (f.sig == SIG_WINFO && f.size >= 9) {
            u8 d[9];
            if ((r = rb_get(rb, f.data, d, 9))) return r;
            if (rd64(d)) { mtime = rd64(d); have_mt = 1; }
            wattr = d[8];
            if (wattr & 0x80) is_dir = 1;
        } else if (f.sig == SIG_PINFO && f.size >= 20) {
            u8 d[20];
            if ((r = rb_get(rb, f.data, d, 20))) return r;
            mode = rd32(d);
            if ((mode & 0170000u) == 0040000u) is_dir = 1;
            if ((mode & 0170000u) == 0120000u) is_link = 1;
            if (!have_mt) { mtime = gz_unix_to_filetime((i64)rd64(d + 12)); have_mt = 1; }
        } else if (f.sig == SIG_ENCRYPT && f.size >= 1 && !enc) {
            egg_enc x;
            u8 d[EGG_ENC_MAX + 1];
            u32 n = f.size - 1 < EGG_ENC_MAX ? (u32)f.size - 1 : EGG_ENC_MAX;
            if ((r = rb_get(rb, f.data, d, n + 1))) return r;
            x.method = d[0];
            x.len = (u8)n;
            __builtin_memcpy(x.d, d + 1, n);
            if ((r = add_enc(pv, &x, &enc))) return r;
            /* some writers overstate the field size: when nothing known follows,
             * end the field after the payload the method defines */
            u32 nx;
            if (rb_u32(rb, f.next, &nx) || !known_sig(nx)) {
                u32 need = enc_need(x.method);
                for (u32 t = 0; need && t < 2; t++) {
                    u64 alt = f.data + 1 + need + (t ? 0 : 10);
                    if (alt < f.next && !rb_u32(rb, alt, &nx) && known_sig(nx)) { f.next = alt; break; }
                }
            }
        }
        pos = f.next;
    }
    /* the name: UTF-8, or a code page converted to UTF-8 here (the archive says which) */
    const u8 *nm = nb->name;
    int ne = GZ_NE_UTF8;
    char idname[12];
    if (!have_name || !nlen) {
        u32 v = id, nd = 0;
        char t[12];
        do { t[nd++] = (char)('0' + v % 10); v /= 10; } while (v);
        for (u32 i = 0; i < nd; i++) idname[i] = t[nd - 1 - i];
        nm = (const u8 *)idname;
        nlen = nd;
    } else if (nflags & 8) {
        int k2 = locale == 65001 ? -2 : locale ? cp_to_utf8((int)locale, nb->name, nlen, nb->conv) : -1;
        if (k2 >= 0) { nm = nb->conv; nlen = (u32)k2; }
        else if (k2 == -1) ne = GZ_NE_LEGACY;                  /* system locale or unknown code page */
    }
    gz_entry *e;
    if ((r = gz_arc_add_named(a, nm, nlen, ne, &e))) return r;
    u32 idx = a->n - 1;
    egg_ent *t = &pv->ent[idx];
    t->blk0 = pv->nblk;
    t->nblk = 0;
    t->enc = enc;
    t->id = id;
    t->parent = parent;
    t->rel = (nflags & 16) != 0;
    e->usize = length;
    e->csize = 0;
    if (have_mt) { e->mtime = mtime; e->mtime_kind = GZ_MT_FILETIME; }
    e->attr = wattr & 0x07;
    e->unix_mode = mode;
    if (mode && !(wattr & 1) && !(mode & 0200)) e->attr |= 1;
    e->is_dir = (u8)is_dir;
    if (is_dir) { e->attr |= 0x10; e->usize = 0; }
    e->is_link = (u8)(is_link && !is_dir);
    if (enc) {
        u32 m = pv->enc[enc - 1].method;
        e->enc = m == C_ZIP ? GZ_ENC_ZIPCRYPTO : (m == C_AES128 || m == C_AES256) ? GZ_ENC_AES : GZ_ENC_OTHER;
        e->aes_strength = (u8)(m == C_AES128 || m == C_LEA128 ? 1 : m == C_AES256 || m == C_LEA256 ? 3 : 0);
    }
    *cur = idx;
    *ppos = pos;
    return GZ_OK;
}

/* BLOCK at pos: header, its fields, the data */
static int parse_block(rbuf *rb, u64 *ppos, egg_blk *b)
{
    u8 h[14];
    u64 pos = *ppos + 4;
    int r = rb_get(rb, pos, h, 14);
    if (r) return r;
    b->method = h[0];
    b->usize = rd32(h + 2);
    b->csize = rd32(h + 6);
    b->crc = rd32(h + 10);
    b->trunc = T_OK;
    b->ustart = 0;
    pos += 14;
    for (u32 k = 0;; k++) {
        u32 sig;
        if (k == EGG_MAX_FIELDS) return GZ_E_FORMAT;
        if ((r = rb_u32(rb, pos, &sig))) return r;
        if (sig == SIG_END) { pos += 4; break; }
        egg_field f;
        if ((r = rd_field(rb, pos, &f))) return r;
        pos = f.next;
    }
    b->off = pos;
    *ppos = pos + b->csize;
    return GZ_OK;
}

/* hash table id -> entry index (first one wins) */
static u32 *id_table(gz_archive *a, egg_priv *pv, u32 *mask)
{
    u32 cap = 16;
    while (cap < 2 * a->n + 2) cap *= 2;
    u32 *t = (u32 *)gz_alloc((size_t)cap * sizeof(u32));
    if (!t) return 0;
    for (u32 i = 0; i < cap; i++) t[i] = ~0u;
    for (u32 i = 0; i < a->n; i++) {
        u32 h = (pv->ent[i].id * 0x9E3779B1u) & (cap - 1);
        while (t[h] != ~0u && pv->ent[t[h]].id != pv->ent[i].id) h = (h + 1) & (cap - 1);
        if (t[h] == ~0u) t[h] = i;
    }
    *mask = cap - 1;
    return t;
}

static u32 id_find(const u32 *t, u32 mask, const egg_priv *pv, u32 id)
{
    u32 h = (id * 0x9E3779B1u) & mask;
    while (t[h] != ~0u) {
        if (pv->ent[t[h]].id == id) return t[h];
        h = (h + 1) & mask;
    }
    return ~0u;
}

/* append the name of entry i (as UTF-8 when its encoding differs from ne) */
static int name_part(gz_archive *a, u32 i, int ne, u8 *out, u32 *n, u32 cap)
{
    const gz_entry *e = &a->e[i];
    const u8 *r = a->raw + e->raw_off;
    u32 rn = e->raw_len;
    if (e->name_enc == ne || ne == GZ_NE_LEGACY) {
        if (*n + rn > cap) return GZ_E_LIMIT;
        __builtin_memcpy(out + *n, r, rn);
        *n += rn;
        return GZ_OK;
    }
    if (*n + 3 * rn > cap) return GZ_E_LIMIT;
    int k = cp_to_utf8(gz_plat_acp(), r, rn, out + *n);
    if (k < 0) { __builtin_memcpy(out + *n, r, rn); k = (int)rn; }
    *n += (u32)k;
    return GZ_OK;
}

/* names relative to a parent (filename flag bit 4): prefix the parent's full path */
static int resolve_names(gz_archive *a, egg_priv *pv)
{
    u32 any = 0;
    for (u32 i = 0; i < a->n; i++) any |= pv->ent[i].rel;
    if (!any) return GZ_OK;
    u32 mask;
    u32 *t = id_table(a, pv, &mask);
    u8 *done = (u8 *)gz_alloc(a->n);
    u32 *chain = (u32 *)gz_alloc(65 * sizeof(u32));
    u8 *buf = (u8 *)gz_alloc(65536);
    int r = (!t || !done || !chain || !buf) ? GZ_E_NOMEM : GZ_OK;
    for (u32 i = 0; i < a->n && !r; i++) {
        if (!pv->ent[i].rel || done[i]) continue;
        /* walk up to an absolute or already resolved ancestor (bounded, no cycles) */
        u32 nc = 0, x = i;
        while (nc < 64 && pv->ent[x].rel && !done[x]) {
            u32 p = id_find(t, mask, pv, pv->ent[x].parent);
            chain[nc++] = x;
            if (p == ~0u || p == x) break;
            int loop = 0;
            for (u32 k = 0; k < nc; k++) if (chain[k] == p) loop = 1;
            if (loop) break;
            x = p;
        }
        /* resolve from the top: each name = parent name + '/' + own name */
        for (u32 k = nc; k-- > 0;) {
            u32 c = chain[k];
            u32 p = id_find(t, mask, pv, pv->ent[c].parent);
            done[c] = 1;
            if (p == ~0u || p == c || (pv->ent[p].rel && !done[p])) continue;
            gz_entry *e = &a->e[c];
            int ne = a->e[p].name_enc == GZ_NE_UTF8 || e->name_enc == GZ_NE_UTF8 ? GZ_NE_UTF8 : GZ_NE_LEGACY;
            u32 n = 0;
            if ((r = name_part(a, p, ne, buf, &n, 65536 - 1))) { r = GZ_OK; continue; }
            buf[n++] = '/';
            if ((r = name_part(a, c, ne, buf, &n, 65536))) { r = GZ_OK; continue; }
            u32 off;
            if ((r = gz_arc_raw_append(a, buf, n, &off))) break;
            e = &a->e[c];
            e->raw_off = off;
            e->raw_len = n;
            e->name_enc = (u8)ne;
        }
    }
    gz_free(t);
    gz_free(done);
    gz_free(chain);
    gz_free(buf);
    return r;
}

static int egg_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    egg_prefix pf;
    int r = read_prefix(s, &pf);
    if (r) return r == GZ_E_NOMEM ? r : GZ_E_FORMAT;
    egg_priv *pv = (egg_priv *)gz_alloc(sizeof(egg_priv));
    if (!pv) return GZ_E_NOMEM;
    a->priv = pv;
    if ((r = open_volumes(a, s, o, &pf))) return r;
    gz_src *js = stream_src(a, s);
    rbuf *rb = (rbuf *)gz_alloc(sizeof(rbuf));
    name_buf *nb = (name_buf *)gz_alloc(sizeof(name_buf));
    if (!js || !rb || !nb) { stream_done(js, s); gz_free(rb); gz_free(nb); return GZ_E_NOMEM; }
    rb->s = js;
    /* the first volume's prefix decides solid / global encryption */
    egg_prefix p0 = pf;
    if (pv->self != 0) {
        gz_src *v0 = a->vols[0];
        if (v0 && (r = read_prefix(v0, &p0))) goto out;
    }
    pv->solid = p0.solid;
    a->solid = pv->solid;
    if (p0.has_genc && (r = add_enc(pv, &p0.genc, &pv->senc))) goto out;
    u64 pos = p0.end;
    u32 cur = ~0u;
    int bad = 0;
    for (u32 iter = 0;; iter++) {
        if ((iter & 1023) == 1023) {
            if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
            if (c && c->progress) c->progress(c->progress_user, pos, pv->lsize);
        }
        u32 sig;
        if (rb_u32(rb, pos, &sig)) break;                       /* end of the data */
        if (sig == SIG_END) break;                              /* end of the archive */
        if (sig == SIG_FILE) {
            if (a->n >= pv->cent) {
                if (a->n >= (1u << 24)) { r = GZ_E_LIMIT; break; }
                u32 nc = pv->cent ? pv->cent * 2 : 64;
                egg_ent *ne = (egg_ent *)gz_realloc(pv->ent, (size_t)nc * sizeof(egg_ent));
                if (!ne) { r = GZ_E_NOMEM; break; }
                pv->ent = ne;
                pv->cent = nc;
            }
            r = parse_file(a, rb, &pos, nb, &cur);
            if (r) { if (r == GZ_E_TRUNC || r == GZ_E_FORMAT || r == GZ_E_VOLUME) { bad = 1; r = GZ_OK; } break; }
            continue;
        }
        if (sig == SIG_BLOCK) {
            egg_blk b;
            r = parse_block(rb, &pos, &b);
            if (r) { if (r == GZ_E_TRUNC || r == GZ_E_FORMAT || r == GZ_E_VOLUME) { bad = 1; r = GZ_OK; } break; }
            if (b.off > pv->lsize || b.csize > pv->lsize - b.off) b.trunc = pv->incomplete ? T_VOLUME : T_TRUNC;
            if (pv->solid) {
                if (!pv->nblk && cur != ~0u && pv->ent[cur].enc) pv->senc = pv->ent[cur].enc;
                if ((r = add_blk(pv, &b))) break;
            } else if (cur != ~0u && pv->ent[cur].blk0 + pv->ent[cur].nblk == pv->nblk) {
                if ((r = add_blk(pv, &b))) break;
                pv->ent[cur].nblk++;
            }
            if (b.trunc) break;
            continue;
        }
        /* archive comment, dummy, skip or unknown fields */
        egg_field f;
        if (rd_field(rb, pos, &f)) { bad = 1; break; }
        if (f.sig == SIG_COMMENT && !a->comment_raw && f.size) {
            u64 p = f.data, left = f.size;
            int legacy = 0;
            if ((f.flags & 8) && left >= 2) {
                u8 d[2];
                if (!rb_get(rb, p, d, 2)) {
                    u32 lc = rd16(d);
                    if (lc == 0 || lc == 932 || lc == 936 || lc == 949 || lc == 950 || (lc >= 1250 && lc <= 1258)) {
                        p += 2; left -= 2; legacy = 1;
                    }
                }
            }
            u32 n = left < 65536 ? (u32)left : 65536;
            u8 *cm = n ? (u8 *)gz_alloc(n) : 0;
            if (cm) {
                u32 k = 0;
                while (k < n) {
                    u32 m = n - k > 8192 ? 8192 : n - k;
                    if (rb_get(rb, p + k, cm + k, m)) break;
                    k += m;
                }
                a->comment_raw = cm;
                a->comment_len = k;
                a->comment_enc = legacy ? GZ_NE_LEGACY : GZ_NE_UTF8;
            }
        }
        pos = f.next;
    }
    if (r) goto out;
    if (!a->n && bad) { r = GZ_E_FORMAT; goto out; }
    r = resolve_names(a, pv);
    if (r) goto out;
    /* sizes, CRCs, solid offsets */
    u64 so = 0;
    for (u32 i = 0; i < pv->nblk && pv->solid; i++) { pv->blk[i].ustart = so; so += pv->blk[i].usize; }
    pv->stotal = so;
    so = 0;
    for (u32 i = 0; i < a->n; i++) {
        gz_entry *e = &a->e[i];
        egg_ent *t = &pv->ent[i];
        if (pv->solid) {
            e->off = so;
            if (!e->is_dir) so += e->usize;
            e->csize = GZ_SIZE_UNKNOWN;
            if (pv->nblk) e->method = pv->blk[0].method;
            if (!t->enc && pv->senc && !e->is_dir) {
                /* the solid stream's encryption (from the global header) */
                u32 m = pv->enc[pv->senc - 1].method;
                e->enc = m == C_ZIP ? GZ_ENC_ZIPCRYPTO : (m == C_AES128 || m == C_AES256) ? GZ_ENC_AES : GZ_ENC_OTHER;
            }
            continue;
        }
        u64 cs = 0;
        for (u32 k = 0; k < t->nblk; k++) cs += pv->blk[t->blk0 + k].csize;
        e->csize = cs;
        if (t->nblk) e->method = pv->blk[t->blk0].method;
        if (t->nblk == 1 && pv->blk[t->blk0].usize == e->usize) { e->crc = pv->blk[t->blk0].crc; e->has_crc = 1; }
    }
    a->win_names = 1;
out:
    gz_free(rb);
    gz_free(nb);
    stream_done(js, s);
    return r;
}

/* ---------------- decryption ---------------- */

typedef struct {
    int kind;                          /* 0 none, 1 ZipCrypto, 2 AES, 3 LEA */
    gz_zipcrypto zc;
    gz_aes_ctr aes;
    gz_lea_ctr lea;
    gz_hmac_sha1 mac;
    int has_mac;
    u8 tag[10];
} egg_crypt;

GZ_INLINE void cr_apply(egg_crypt *cr, u8 *p, size_t n)
{
    switch (cr->kind) {
    case 1: gz_zc_decrypt(&cr->zc, p, n); break;
    case 2: if (cr->has_mac) gz_hmac_update(&cr->mac, p, n); gz_aes_ctr_kernel(&cr->aes, p, n); break;
    case 3: if (cr->has_mac) gz_hmac_update(&cr->mac, p, n); gz_lea_ctr_crypt(&cr->lea, p, n); break;
    }
}

/* key setup and password check for one password encoding */
static int cr_init(egg_crypt *cr, const egg_enc *h, const u8 *pw, size_t pwn)
{
    u32 need = enc_need(h->method);
    if (!need) return GZ_E_METHOD;
    if (h->len < need) return GZ_E_FORMAT;
    if (h->method == C_ZIP) {
        u8 v[12];
        __builtin_memcpy(v, h->d, 12);
        gz_zc_init(&cr->zc, pw, pwn);
        gz_zc_decrypt(&cr->zc, v, 12);
        if (v[11] != (u8)(rd32(h->d + 12) >> 24)) return GZ_E_PASSWORD;
        cr->kind = 1;
        cr->has_mac = 0;
        return GZ_OK;
    }
    u32 kl = (h->method == C_AES128 || h->method == C_LEA128) ? 16 : 32, sl = kl / 2;
    u8 dk[66];
    gz_pbkdf2_sha1(pw, pwn, h->d, sl, 1000, dk, 2 * kl + 2);
    if (dk[2 * kl] != h->d[sl] || dk[2 * kl + 1] != h->d[sl + 1]) return GZ_E_PASSWORD;
    if (h->method == C_AES128 || h->method == C_AES256) { gz_aes_ctr_setup(&cr->aes, dk, (int)kl); cr->kind = 2; }
    else { gz_lea_ctr_init(&cr->lea, dk, kl); cr->kind = 3; }
    cr->has_mac = h->len >= need + 10;
    if (cr->has_mac) {
        gz_hmac_init(&cr->mac, dk + kl, kl);
        __builtin_memcpy(cr->tag, h->d + need, 10);
    }
    return GZ_OK;
}

static int cr_mac_ok(egg_crypt *cr)
{
    if (!cr || cr->kind < 2 || !cr->has_mac) return 1;
    u8 m[20];
    gz_hmac_final(&cr->mac, m);
    return !__builtin_memcmp(m, cr->tag, 10);
}

/* password encodings: UTF-8, CP949, the ANSI code page */
typedef struct { u8 b[3][768]; size_t n[3]; int count; } pw_set;

static void pw_candidates(const gzch *pw, pw_set *ps)
{
    ps->count = 0;
    if (!pw) return;
    size_t wn = gz_wcslen(pw);
    if (wn > 250) wn = 250;
    int cps[3] = { 0, 949, gz_plat_acp() };
    for (int k = 0; k < 3; k++) {
        int n = !k ? gz_utf16_to_utf8(pw, wn, ps->b[ps->count])
                   : gz_plat_cp_valid(cps[k]) ? gz_plat_wc2mb(cps[k], pw, (int)wn, ps->b[ps->count], 760) : 0;
        if (n <= 0 && !(n == 0 && wn == 0)) continue;
        int dup = 0;
        for (int j = 0; j < ps->count; j++)
            if (ps->n[j] == (size_t)n && !__builtin_memcmp(ps->b[j], ps->b[ps->count], (size_t)n)) dup = 1;
        if (!dup) ps->n[ps->count++] = (size_t)n;
    }
}

/* ---------------- block decoding ---------------- */

typedef struct {
    gz_src *src;
    u64 pos, end;
    volatile long *cancel;
    egg_crypt *cr;
    int (*sink)(void *user, const u8 *p, size_t n);
    void *user;
    u64 written, limit;
    int do_crc;
    u32 crc;
} brd;

static int brd_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    brd *x = (brd *)ctx;
    *got = 0;
    if (x->cancel && *x->cancel) return GZ_E_CANCEL;
    u64 left = x->end - x->pos;
    if (!left || !cap) return GZ_OK;
    u32 n = left < cap ? (u32)left : cap, g = 0;
    int r = x->src->read_at(x->src, x->pos, buf, n, &g);
    if (r) return r;
    if (!g) return GZ_E_TRUNC;
    x->pos += g;
    if (x->cr) cr_apply(x->cr, buf, g);
    *got = g;
    return GZ_OK;
}

static int brd_write(void *ctx, const u8 *p, size_t n)
{
    brd *x = (brd *)ctx;
    if (n > x->limit - x->written) return GZ_E_DATA;          /* more than the block holds */
    x->written += n;
    if (x->do_crc) x->crc = gz_crc32(x->crc, p, n);
    return x->sink(x->user, p, n);
}

static void *bz_new(void) { return gz_bzip2_dec_new(); }
static void bz_free(void *p) { gz_bzip2_dec_free((gz_bzip2_dec *)p); }

static int lzma_props_ok(const u8 *h) { return rd16(h + 2) == 5 && h[4] < 225; }

/* LZMA block header (9 bytes: 4 bytes, ZIP style version + properties size, then the
 * 5 properties). unegg reads it in the clear while the data is decrypted; an
 * encrypted header is accepted too when only that reading makes sense (then the
 * cipher moves past it). h gets the plain header. */
static int lzma_head(gz_src *js, const egg_blk *b, egg_crypt *cr, u8 h[9])
{
    if (b->csize < 9) return GZ_E_DATA;
    int r = gz_src_read_exact(js, b->off, h, 9);
    if (r) return r == GZ_E_TRUNC ? GZ_E_DATA : r;
    if (cr && !lzma_props_ok(h)) {
        egg_crypt *tmp = (egg_crypt *)gz_alloc(sizeof(egg_crypt));
        if (!tmp) return GZ_E_NOMEM;
        u8 t[9];
        __builtin_memcpy(t, h, 9);
        *tmp = *cr;
        cr_apply(tmp, t, 9);
        gz_free(tmp);
        if (lzma_props_ok(t) || h[4] >= 225) cr_apply(cr, h, 9);
    }
    return h[4] < 225 ? GZ_OK : GZ_E_DATA;
}

/* Decode block b to sink. cr: the file's decryption state (continues across
 * blocks), NULL when not encrypted. Verifies size and CRC. */
static int run_block(gz_src *js, const egg_blk *b, egg_crypt *cr, int (*sink)(void *, const u8 *, size_t),
                     void *user, gz_ctx *c)
{
    if (b->trunc) return b->trunc == T_VOLUME ? GZ_E_VOLUME : GZ_E_TRUNC;
    brd x;
    __builtin_memset(&x, 0, sizeof x);
    x.src = js;
    x.pos = b->off;
    x.end = b->off + b->csize;
    x.cancel = c->cancel;
    x.cr = cr;
    x.sink = sink;
    x.user = user;
    x.limit = b->usize;
    x.do_crc = 1;
    gz_stream_io io = { brd_read, brd_write, &x };
    int st;
    u32 crc;
    switch (b->method) {
    case M_STORE: {
        u8 *buf = gz_ctx_buffer(c, 256u << 10);
        if (!buf) return GZ_E_NOMEM;
        st = GZ_OK;
        for (;;) {
            u32 got = 0;
            if ((st = brd_read(&x, buf, 256u << 10, &got)) || !got) break;
            if ((st = brd_write(&x, buf, got))) break;
        }
        crc = x.crc;
        break;
    }
    case M_DEFLATE: {
        gz_inflater *z = gz_ctx_inflater(c);
        if (!z) return GZ_E_NOMEM;
        x.do_crc = 0;
        st = gz_inflate_run(z, &io, 0);
        crc = z->crc;
        break;
    }
    case M_BZIP2: {
        gz_bzip2_dec *d = (gz_bzip2_dec *)gz_ctx_slot(c, GZ_SLOT_BZIP2, bz_new, bz_free);
        if (!d) return GZ_E_NOMEM;
        st = gz_bzip2_decode(d, &io, b->usize, 1, 0);
        if (st == GZ_E_FORMAT) st = GZ_E_DATA;
        crc = x.crc;
        break;
    }
    case M_AZO: {
        gz_azo_dec *d = (gz_azo_dec *)gz_ctx_slot(c, GZ_SLOT_MISC1, gz_azo_slot_new, gz_azo_slot_free);
        if (!d) return GZ_E_NOMEM;
        st = gz_azo_decode(d, &io, b->usize, 0);
        crc = x.crc;
        break;
    }
    case M_LZMA: {
        u8 h[9];
        int r = lzma_head(js, b, cr, h);
        if (r) return r;
        x.pos += 9;
        gz_lzma_dec *d = gz_xz_lzma_dec(c);
        if (!d) return GZ_E_NOMEM;
        gz_lzma_dec_set_flags(d, GZ_LZMA_LENIENT_END);
        st = gz_lzma_decode(d, h + 4, &io, b->usize, 0);
        gz_lzma_dec_set_flags(d, 0);
        crc = x.crc;
        break;
    }
    default:
        return GZ_E_METHOD;
    }
    /* keep the cipher (and the HMAC) in step: pass the unread rest of the block */
    if (cr && !st && x.pos < x.end) {
        u8 tmp[4096];
        while (x.pos < x.end && !st) {
            u32 got = 0;
            st = brd_read(&x, tmp, sizeof tmp, &got);
            if (!st && !got) st = GZ_E_TRUNC;
        }
    }
    if (!st && x.written != b->usize) st = GZ_E_DATA;
    if (!st && crc != b->crc) st = cr && cr->kind == 1 ? GZ_E_PASSWORD : GZ_E_CRC;
    return st;
}

/* run the cipher (and HMAC) over a block without decoding it */
static int skip_block(gz_src *js, const egg_blk *b, egg_crypt *cr, gz_ctx *c)
{
    if (!cr) return GZ_OK;
    if (b->trunc) return b->trunc == T_VOLUME ? GZ_E_VOLUME : GZ_E_TRUNC;
    brd x;
    __builtin_memset(&x, 0, sizeof x);
    x.src = js;
    x.pos = b->off;
    x.end = b->off + b->csize;
    x.cancel = c->cancel;
    x.cr = cr;
    if (b->method == M_LZMA) {
        u8 h[9];
        int r = lzma_head(js, b, cr, h);
        if (r) return r;
        x.pos += 9;
    }
    u8 *buf = gz_ctx_buffer(c, 256u << 10);
    if (!buf) return GZ_E_NOMEM;
    while (x.pos < x.end) {
        u32 got = 0;
        int r = brd_read(&x, buf, 256u << 10, &got);
        if (r) return r;
        if (!got) return GZ_E_TRUNC;
    }
    return GZ_OK;
}

static int out_sink(void *user, const u8 *p, size_t n)
{
    gz_out *o = (gz_out *)user;
    return o->write(o, p, n);
}

static int null_sink(void *user, const u8 *p, size_t n) { (void)user; (void)p; (void)n; return GZ_OK; }

/* derive the key for encryption field h from c->password; with several passing
 * encodings, the one whose first block decodes wins (blocks: NULL = take the first) */
static int find_key(const egg_enc *h, gz_ctx *c, egg_crypt *cr, gz_src *js, const egg_blk *blk, u32 nblk)
{
    pw_set *ps = (pw_set *)gz_alloc(sizeof(pw_set));
    egg_crypt *t = (egg_crypt *)gz_alloc(sizeof(egg_crypt));
    if (!ps || !t) { gz_free(ps); gz_free(t); return GZ_E_NOMEM; }
    pw_candidates(c->password, ps);
    int err = enc_need(h->method) ? GZ_E_PASSWORD : GZ_E_METHOD, found = 0;
    for (int k = 0; k < ps->count; k++) {
        int r = cr_init(t, h, ps->b[k], ps->n[k]);
        if (r == GZ_E_PASSWORD) continue;
        if (r) { err = r; break; }
        if (!found) { *cr = *t; found = 1; if (!blk || h->method != C_ZIP) break; continue; }
        /* a second ZipCrypto candidate passed the 1-byte check: try both on the data */
        egg_crypt *u = (egg_crypt *)gz_alloc(sizeof(egg_crypt));
        if (!u) break;
        *u = *cr;
        int ok = 1;
        for (u32 i = 0; i < nblk && ok; i++) ok = !run_block(js, &blk[i], u, null_sink, 0, c);
        if (!ok) *cr = *t;
        gz_free(u);
        break;
    }
    gz_free(ps);
    gz_free(t);
    return found ? GZ_OK : err;
}

/* ---------------- extraction ---------------- */

static int finish_entry(gz_out *out, u32 idx, int st)
{
    int r = out->open(out, idx);
    if (r) return r;
    r = out->close(out, idx, st);
    return st ? st : r;
}

/* Solid archives: the files with data are cut, in stream order, from the
 * concatenated block outputs. Entries are opened and closed strictly one after
 * the other. A block's CRC covers several files, so blocks up to SOLID_BUF are
 * decoded into memory and checked before any of their bytes are handed out;
 * larger blocks are streamed and a bad CRC only reaches the file open at the
 * block's end. */
#define SOLID_BUF (32u << 20)

typedef struct {
    gz_archive *a;
    gz_out *out;
    const u8 *sel;
    u32 only;                          /* single entry (extract), ~0 = use sel */
    u32 *list, nl;                     /* entries with data, in stream order */
    u8 *state;                         /* per list index: 0 new, 1 open, 2 not wanted / skipped, 3 done */
    u32 fi;                            /* file holding gpos */
    u64 gpos;                          /* position in the solid output */
    int fatal;                         /* open error / cancel: stop everything */
    int only_st;                       /* status reported for the single entry */
    u8 *buf; size_t buf_n, buf_cap;    /* buffered block */
} solid_run;

static int want(const solid_run *s, u32 idx) { return s->only != ~0u ? idx == s->only : s->sel[idx] != 0; }

static u64 f_off(const solid_run *s, u32 k) { return s->a->e[s->list[k]].off; }
static u64 f_end(const solid_run *s, u32 k) { return f_off(s, k) + s->a->e[s->list[k]].usize; }

/* report status st for file k, unless it is done already */
static int finish_file(solid_run *s, u32 k, int st)
{
    u32 idx = s->list[k];
    int r = GZ_OK;
    if (idx == s->only) s->only_st = st;
    if (s->state[k] == 1) r = s->out->close(s->out, idx, st);
    else if (!s->state[k] && want(s, idx)) {
        r = s->out->open(s->out, idx);
        if (!r) r = s->out->close(s->out, idx, st);
        else if (r == GZ_E_SKIP) r = GZ_OK;
    }
    s->state[k] = 3;
    if (r == GZ_E_CANCEL) { s->fatal = r; return r; }
    return GZ_OK;
}

/* bytes at gpos go to the file holding them; a file is closed as soon as it is complete */
static int route(void *user, const u8 *p, size_t n)
{
    solid_run *s = (solid_run *)user;
    while (n) {
        while (s->fi < s->nl && f_end(s, s->fi) <= s->gpos) s->fi++;
        if (s->fi == s->nl) { s->gpos += n; return GZ_OK; }   /* past the last file */
        u32 k = s->fi, idx = s->list[k];
        u64 fe = f_end(s, k);
        size_t m = fe - s->gpos < n ? (size_t)(fe - s->gpos) : n;
        if (!s->state[k]) {
            s->state[k] = 2;
            if (want(s, idx)) {
                int r = s->out->open(s->out, idx);
                if (r == GZ_E_SKIP && s->only == ~0u) s->state[k] = 3;
                else if (r) { s->fatal = r; return r; }
                else s->state[k] = 1;
            }
        }
        if (s->state[k] == 1) {
            int r = s->out->write(s->out, p, m);
            if (r) {
                if (r == GZ_E_CANCEL || s->only != ~0u) {
                    s->out->close(s->out, idx, r);
                    s->only_st = r;
                    s->state[k] = 3;
                    s->fatal = r;
                    return r;
                }
                if ((r = finish_file(s, k, r))) return r;      /* this file failed, go on */
            }
        }
        p += m; n -= m; s->gpos += m;
        if (s->gpos == fe && s->state[k] != 3) {
            int r = finish_file(s, k, GZ_OK);
            if (r) return r;
        }
    }
    return GZ_OK;
}

/* every file not done yet that overlaps [from, to) gets status st */
static int fail_range(solid_run *s, u64 from, u64 to, int st)
{
    for (u32 k = 0; k < s->nl; k++) {
        if (f_end(s, k) <= from || f_off(s, k) >= to || s->state[k] == 3) continue;
        int r = finish_file(s, k, st);
        if (r) return r;
    }
    return GZ_OK;
}

static int buf_sink(void *user, const u8 *p, size_t n)
{
    solid_run *s = (solid_run *)user;
    if (n > s->buf_cap - s->buf_n) return GZ_E_DATA;
    __builtin_memcpy(s->buf + s->buf_n, p, n);
    s->buf_n += n;
    return GZ_OK;
}

static int solid_extract(gz_archive *a, gz_src *s, const u8 *sel, u32 only, gz_out *out, gz_ctx *c)
{
    egg_priv *pv = (egg_priv *)a->priv;
    solid_run S;
    __builtin_memset(&S, 0, sizeof S);
    S.a = a; S.out = out; S.sel = sel; S.only = only;
    /* entries without data */
    for (u32 i = 0; i < a->n; i++) {
        gz_entry *e = &a->e[i];
        if (!(e->is_dir || !e->usize) || !want(&S, i)) continue;
        int r = out->open(out, i);
        if (r == GZ_E_SKIP && only == ~0u) continue;
        if (r) return r;
        if ((r = out->close(out, i, GZ_OK)) == GZ_E_CANCEL) return r;
    }
    int ret = GZ_OK;
    egg_crypt *cr = 0;
    gz_src *js = 0;
    S.list = (u32 *)gz_alloc((size_t)a->n * sizeof(u32) + 4);
    S.state = (u8 *)gz_alloc((size_t)a->n + 1);
    if (!S.list || !S.state) { ret = GZ_E_NOMEM; goto done; }
    u32 first = ~0u, last = 0;
    for (u32 i = 0; i < a->n; i++) {
        gz_entry *e = &a->e[i];
        if (e->is_dir || !e->usize) continue;
        if (want(&S, i)) { if (first == ~0u) first = S.nl; last = S.nl; }
        S.list[S.nl++] = i;
    }
    if (first == ~0u) goto done;
    if (!(js = stream_src(a, s))) { ret = GZ_E_NOMEM; goto done; }
    u64 from = f_off(&S, first), to = f_end(&S, last);
    int st0 = GZ_OK;
    if (pv->senc) {
        /* one key for the whole stream; authenticate it before handing out data */
        if (!(cr = (egg_crypt *)gz_alloc(sizeof(egg_crypt)))) { ret = GZ_E_NOMEM; goto done; }
        st0 = find_key(&pv->enc[pv->senc - 1], c, cr, js, 0, 0);
        if (!st0 && cr->has_mac) {
            egg_crypt *t = (egg_crypt *)gz_alloc(sizeof(egg_crypt));
            if (!t) { ret = GZ_E_NOMEM; goto done; }
            *t = *cr;
            for (u32 b = 0; b < pv->nblk && !st0; b++) st0 = skip_block(js, &pv->blk[b], t, c);
            if (!st0 && !cr_mac_ok(t)) st0 = GZ_E_AUTH;
            gz_free(t);
            cr->has_mac = 0;
        }
        if (st0 == GZ_E_CANCEL) { ret = st0; goto done; }
    }
    for (u32 b = 0; b < pv->nblk && !st0; b++) {
        const egg_blk *bk = &pv->blk[b];
        u64 bs = bk->ustart, be = bs + bk->usize;
        if (bs >= to) break;
        if (gz_cancelled(c)) { ret = GZ_E_CANCEL; break; }
        if (be <= from) {                          /* before the first wanted file */
            st0 = skip_block(js, bk, cr, c);
            continue;
        }
        S.gpos = bs;
        S.fi = 0;
        while (S.fi < S.nl && f_end(&S, S.fi) <= bs) S.fi++;
        int r;
        if (bk->usize <= SOLID_BUF) {
            if (S.buf_cap < bk->usize) {
                if (S.buf) gz_free_big(S.buf, S.buf_cap);
                S.buf_cap = bk->usize < (1u << 20) ? (1u << 20) : bk->usize;
                if (!(S.buf = (u8 *)gz_alloc_big(S.buf_cap))) { S.buf_cap = 0; ret = GZ_E_NOMEM; break; }
            }
            S.buf_n = 0;
            r = run_block(js, bk, cr, buf_sink, &S, c);
            if (!r) r = route(&S, S.buf, S.buf_n);
        } else {
            r = run_block(js, bk, cr, route, &S, c);
        }
        if (S.fatal) { ret = S.fatal; break; }
        if (r == GZ_E_CANCEL) { ret = r; break; }
        if (r) {
            /* the files touching the rest of this block are damaged; the next block
             * starts fresh unless the cipher state depends on this one */
            if ((ret = fail_range(&S, S.gpos < be ? S.gpos : be - 1, be, r))) break;
            if (cr) st0 = r;
        }
    }
    if (!ret) {
        /* files that got no (complete) data: a failed key or block, or the blocks end early */
        for (u32 k = first; k <= last && !ret; k++) {
            if (S.state[k] == 3) continue;
            ret = finish_file(&S, k, st0 ? st0 : pv->incomplete ? GZ_E_VOLUME : GZ_E_DATA);
        }
    } else {
        for (u32 k = first; k <= last; k++) if (S.state[k] == 1) out->close(out, S.list[k], ret);
    }
done:
    if (only != ~0u && ret == GZ_OK) ret = S.only_st;      /* the entry's own status */
    stream_done(js, s);
    gz_free(cr);
    if (S.buf) gz_free_big(S.buf, S.buf_cap);
    gz_free(S.list);
    gz_free(S.state);
    return ret;
}

static int egg_extract_solid(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_ctx *c)
{
    egg_priv *pv = (egg_priv *)a->priv;
    if (pv->solid) return solid_extract(a, s, sel, ~0u, out, c);
    for (u32 i = 0; i < a->n; i++) {
        if (gz_cancelled(c)) return GZ_E_CANCEL;
        if (!sel[i]) continue;
        int r = a->fmt->extract(a, s, i, out, c);
        if (r == GZ_E_CANCEL) return r;
    }
    return GZ_OK;
}

static int egg_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    egg_priv *pv = (egg_priv *)a->priv;
    gz_entry *e = &a->e[idx];
    egg_ent *t = &pv->ent[idx];
    if (e->is_dir) return finish_entry(out, idx, GZ_OK);
    if (pv->solid) return solid_extract(a, s, 0, idx, out, c);
    u64 sum = 0;
    for (u32 k = 0; k < t->nblk; k++) sum += pv->blk[t->blk0 + k].usize;
    if (!t->nblk) return finish_entry(out, idx, !e->usize ? GZ_OK : pv->incomplete ? GZ_E_VOLUME : GZ_E_DATA);
    gz_src *js = stream_src(a, s);
    if (!js) return GZ_E_NOMEM;
    egg_crypt *cr = 0;
    int r = GZ_OK;
    if (t->enc) {
        cr = (egg_crypt *)gz_alloc(sizeof(egg_crypt));
        if (!cr) r = GZ_E_NOMEM;
        else r = find_key(&pv->enc[t->enc - 1], c, cr, js, &pv->blk[t->blk0], t->nblk);
    }
    if (!r) r = out->open(out, idx);
    if (r) { gz_free(cr); stream_done(js, s); return r; }
    int st = sum == e->usize ? GZ_OK : GZ_E_DATA;
    for (u32 k = 0; k < t->nblk && !st; k++) {
        if (gz_cancelled(c)) { st = GZ_E_CANCEL; break; }
        st = run_block(js, &pv->blk[t->blk0 + k], cr, out_sink, out, c);
    }
    if (!st && !cr_mac_ok(cr)) st = GZ_E_AUTH;
    gz_free(cr);
    stream_done(js, s);
    int cl = out->close(out, idx, st);
    return st ? st : cl;
}

static int egg_check_password(gz_archive *a, gz_src *s, u32 idx, gz_ctx *c)
{
    egg_priv *pv = (egg_priv *)a->priv;
    gz_entry *e = &a->e[idx];
    egg_ent *t = &pv->ent[idx];
    u32 enc = pv->solid ? pv->senc : t->enc;
    if (!e->enc || e->is_dir || !enc) return GZ_OK;
    egg_crypt *cr = (egg_crypt *)gz_alloc(sizeof(egg_crypt));
    if (!cr) return GZ_E_NOMEM;
    int r = find_key(&pv->enc[enc - 1], c, cr, 0, 0, 0);
    gz_free(cr);
    (void)s;
    return r;
}

static void egg_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    const egg_priv *pv = (const egg_priv *)a->priv;
    const char *m;
    if (e->is_dir) m = "";
    else switch (e->method) {
    case M_STORE: m = "Store"; break;
    case M_DEFLATE: m = "Deflate"; break;
    case M_BZIP2: m = "BZip2"; break;
    case M_AZO: m = "AZO"; break;
    case M_LZMA: m = "LZMA"; break;
    default: m = "?"; break;
    }
    const char *enc = "";
    u32 ei = pv->solid ? pv->senc : pv->ent[e - a->e].enc;
    if (e->enc && ei) {
        switch (pv->enc[ei - 1].method) {
        case C_ZIP: enc = " ZipCrypto"; break;
        case C_AES128: enc = " AES-128"; break;
        case C_AES256: enc = " AES-256"; break;
        case C_LEA128: enc = " LEA-128"; break;
        case C_LEA256: enc = " LEA-256"; break;
        default: enc = " ?"; break;
        }
    }
    u32 i = 0;
    for (; *m && i + 1 < cap; m++) buf[i++] = *m;
    if (pv->solid && *m == 0 && !e->is_dir) for (const char *x = " Solid"; *x && i + 1 < cap; x++) buf[i++] = *x;
    for (; *enc && i + 1 < cap; enc++) buf[i++] = *enc;
    if (cap) buf[i] = 0;
}

/* stored, unencrypted single-block files inside one volume can be read in place */
static gz_src *egg_view(gz_archive *a, gz_src *s, u32 idx)
{
    egg_priv *pv = (egg_priv *)a->priv;
    gz_entry *e = &a->e[idx];
    egg_ent *t = &pv->ent[idx];
    if (pv->solid || e->is_dir || e->enc || t->nblk != 1) return 0;
    const egg_blk *b = &pv->blk[t->blk0];
    if (b->method != M_STORE || b->trunc || b->csize != e->usize || b->usize != e->usize) return 0;
    for (u32 k = 0; k < pv->nv; k++) {
        if (b->off < pv->lstart[k] || b->off - pv->lstart[k] >= pv->plen[k]) continue;
        u64 o = b->off - pv->lstart[k];
        if (e->usize > pv->plen[k] - o) return 0;
        gz_src *v = vol_src(pv, s, a->vols, k);
        return v ? gz_src_sub(v, pv->poff[k] + o, e->usize) : 0;
    }
    return 0;
}

static int egg_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 18 || rd32(h) != SIG_EGG) return 0;
    return rd16(h + 4) == 0x0100 ? 95 : 85;
}

GZ_FORMAT(gz_fmt_egg)
const gz_format gz_fmt_egg = {
    "EGG", "egg",
    0, egg_probe, egg_open, egg_close, egg_extract, egg_extract_solid, egg_check_password, egg_method, egg_view, 0
};
