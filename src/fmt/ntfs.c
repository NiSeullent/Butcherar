/*
 * 고깃ZIP - NTFS file system images (read-only)
 *
 *   Boot sector (BPB sanity, 512..4096-byte sectors, clusters up to 2 MiB),
 *   $MFT located through its own (possibly fragmented, attribute-listed)
 *   $DATA runlist, MFT records with update sequence (fixup) checks,
 *   resident / non-resident attributes and $ATTRIBUTE_LIST spanning extension
 *   records, $STANDARD_INFORMATION (times, attributes), $FILE_NAME (Win32 /
 *   POSIX names, DOS 8.3 duplicates skipped, every hard link listed as a file),
 *   the folder tree built from parent references (cycles and orphans go to
 *   "[LOST]"), unnamed $DATA = file content, named $DATA = alternate streams
 *   listed as "file:stream" (is_aux), sparse runs and data past the
 *   initialized size read as zeros, LZNT1 compressed attributes, WOF system
 *   compression (XPRESS 4K/8K/16K, LZX) from the WofCompressedData stream,
 *   symbolic links / junctions (substitute name) and ntfs-3g Interix symlinks,
 *   EFS-encrypted streams (GZ_E_METHOD), metafiles in "[SYSTEM]" (is_aux) like
 *   7-Zip, deleted records skipped, files > 4 GiB. The volume label becomes
 *   the archive comment.
 *
 *   Extraction re-reads the file's MFT records, so entries can be extracted in
 *   any order and from several threads (the volume state is read-only after
 *   open). Plain non-resident and resident streams have a random-access view.
 *
 *   Hostile images: record numbers, runs (lengths, LCNs, VCN continuity, total
 *   allocation), attribute and attribute-list bounds are all checked; attribute
 *   lists share a byte budget at open; the $MFT is clipped to what fits in the
 *   image; directory chains are resolved iteratively with cycle detection.
 */
#include "fs1.h"
#include "lznt1.h"
#include "xpress.h"
#include "lzx.h"

/* attribute types */
#define AT_SI       0x10u
#define AT_AL       0x20u
#define AT_FN       0x30u
#define AT_VOLNAME  0x60u
#define AT_DATA     0x80u
#define AT_REPARSE  0xC0u
#define AT_END      0xFFFFFFFFu
/* attribute flags */
#define AF_COMP     0x00FFu
#define AF_ENC      0x4000u
#define AF_SPARSE   0x8000u
/* file attributes */
#define FA_SYSTEM   0x0004u
#define FA_DIR      0x0010u
#define FA_ENC      0x4000u
/* reparse tags */
#define RT_MOUNT    0xA0000003u
#define RT_SYMLINK  0xA000000Cu
#define RT_WOF      0x80000017u

#define NT_HOLE     (~(u64)0)
#define NT_REF(x)   ((x) & 0xFFFFFFFFFFFFull)
#define NT_ROOT     5u
#define NT_SYSRECS  16u                /* records 0..15: metafiles */
#define NT_MAX_RUNS (1u << 21)         /* runs per attribute */
#define NT_MAX_AL   (1u << 20)         /* attribute list bytes */
#define NT_MAX_RP   (16u << 10)        /* reparse data bytes */
#define NT_MAX_REC  (1u << 28)         /* records in $MFT */
#define NT_XCACHE   8                  /* extension records cached per walk */
#define NT_OBUF     (1u << 20)         /* output batch for decoded data */
#define NT_RCACHE   (1u << 20)         /* read-ahead window */
#define NT_MAX_FENT 8192u              /* entries (links x streams) per file */

/* entry kinds (gz_entry.method) */
enum { NK_RESIDENT = 0, NK_PLAIN, NK_SPARSE, NK_LZNT1, NK_WOF, NK_EFS, NK_UNSUP, NK_LINK };

typedef struct { u64 vcn, lcn, len; } nt_run;                    /* len in clusters */
typedef struct { nt_run *r; u32 n, cap; u64 end, phys; } nt_runs; /* end = next VCN */

typedef struct {
    u32 cs, cshift;                    /* cluster size */
    u32 rs;                            /* MFT record size */
    u64 nclus;                         /* clusters in the volume */
    u64 nrec;                          /* records in $MFT */
    nt_runs mft;                       /* $MFT:$DATA runs */
} nt_fs;

static u32 ctz32(u32 x) { return (u32)__builtin_ctz(x); }

/* ---------------- runlists ---------------- */

static void runs_free(nt_runs *rl)
{
    gz_free(rl->r);
    __builtin_memset(rl, 0, sizeof *rl);
}

static int runs_push(nt_runs *rl, u64 lcn, u64 len)
{
    if (rl->n) {
        nt_run *p = &rl->r[rl->n - 1];
        if (lcn == NT_HOLE ? p->lcn == NT_HOLE : (p->lcn != NT_HOLE && p->lcn + p->len == lcn)) {
            p->len += len;
            rl->end += len;
            return GZ_OK;
        }
    }
    if (rl->n == rl->cap) {
        if (rl->cap >= NT_MAX_RUNS) return GZ_E_LIMIT;
        u32 nc = rl->cap ? rl->cap * 2 : 16;
        nt_run *nr = (nt_run *)gz_realloc(rl->r, (size_t)nc * sizeof(nt_run));
        if (!nr) return GZ_E_NOMEM;
        rl->r = nr;
        rl->cap = nc;
    }
    nt_run *x = &rl->r[rl->n++];
    x->vcn = rl->end;
    x->lcn = lcn;
    x->len = len;
    rl->end += len;
    return GZ_OK;
}

/* Decode one extent's mapping pairs p[0..n) (lowest VCN vcn) and append them to rl.
 * Extents must follow each other; LCNs must lie in the volume; the allocated
 * clusters of one attribute cannot exceed the volume. */
static int runs_decode(const nt_fs *fs, nt_runs *rl, const u8 *p, u32 n, u64 vcn)
{
    if (vcn != rl->end) return GZ_E_FORMAT;
    u64 vmax = (u64)1 << (62 - fs->cshift);           /* byte offsets stay < 2^62 */
    u64 lcn = 0;
    u32 i = 0;
    while (i < n && p[i]) {
        u32 ls = p[i] & 15, os = p[i] >> 4;
        i++;
        if (!ls || ls > 8 || os > 8 || ls + os > n - i) return GZ_E_FORMAT;
        u64 len = 0;
        for (u32 k = 0; k < ls; k++) len |= (u64)p[i + k] << (8 * k);
        i += ls;
        if (!len || len > vmax - rl->end) return GZ_E_FORMAT;
        u64 at = NT_HOLE;
        if (os) {
            u64 d = 0;
            for (u32 k = 0; k < os; k++) d |= (u64)p[i + k] << (8 * k);
            if (os < 8 && (p[i + os - 1] & 0x80)) d |= ~(u64)0 << (8 * os);
            i += os;
            lcn += d;
            if (lcn >= fs->nclus || len > fs->nclus - lcn) return GZ_E_FORMAT;
            if (len > fs->nclus - rl->phys) return GZ_E_FORMAT;
            rl->phys += len;
            at = lcn;
        }
        int r = runs_push(rl, at, len);
        if (r) return r;
    }
    return GZ_OK;
}

/* index of the run holding vcn (vcn < rl->end) */
static u32 run_find(const nt_runs *rl, u64 vcn)
{
    u32 lo = 0, hi = rl->n;
    while (hi - lo > 1) {
        u32 mid = (lo + hi) / 2;
        if (rl->r[mid].vcn <= vcn) lo = mid; else hi = mid;
    }
    return lo;
}

/* Read len bytes at logical offset off of a run-mapped stream (holes: zeros, or an
 * error when !holes_ok). */
static int runs_read(const nt_fs *fs, gz_src *s, const nt_runs *rl, u64 off, u8 *buf, u32 len, int holes_ok)
{
    while (len) {
        u64 vcn = off >> fs->cshift;
        if (vcn >= rl->end) return GZ_E_FORMAT;
        const nt_run *r = &rl->r[run_find(rl, vcn)];
        u64 in = off - (r->vcn << fs->cshift), avail = (r->len << fs->cshift) - in;
        u32 n = len < avail ? len : (u32)avail;
        if (r->lcn == NT_HOLE) {
            if (!holes_ok) return GZ_E_FORMAT;
            __builtin_memset(buf, 0, n);
        } else {
            int e = gz_src_read_exact(s, (r->lcn << fs->cshift) + in, buf, n);
            if (e) return e;
        }
        buf += n;
        off += n;
        len -= n;
    }
    return GZ_OK;
}

/* ---------------- MFT records and attributes ---------------- */

/* Apply the update sequence array of a record read into b (rs bytes). */
static int rec_fix(const nt_fs *fs, u8 *b)
{
    if (__builtin_memcmp(b, "FILE", 4)) return GZ_E_FORMAT;
    u32 uo = rd16(b + 4), un = rd16(b + 6), rs = fs->rs;
    if (un < 2 || (uo & 1) || uo < 0x28) return GZ_E_FORMAT;
    u32 stride = rs / (un - 1);
    if (stride < 256 || (stride & (stride - 1)) || stride * (un - 1) != rs || uo + 2 * un > stride - 2)
        return GZ_E_FORMAT;
    u16 usn = rd16(b + uo);
    for (u32 i = 1; i < un; i++) {
        u8 *p = b + i * stride - 2;
        if (rd16(p) != usn) return GZ_E_FORMAT;       /* torn write */
        __builtin_memcpy(p, b + uo + 2 * i, 2);
    }
    u32 ao = rd16(b + 0x14);
    if (ao < uo + 2 * un || ao + 8 > rs) return GZ_E_FORMAT;
    return GZ_OK;
}

static u32 rec_used(const nt_fs *fs, const u8 *b)
{
    u32 u = rd32(b + 0x18);
    return u && u <= fs->rs ? u : fs->rs;
}

/* Read record recno through the $MFT runs and fix it up. */
static int rec_read(const nt_fs *fs, gz_src *s, u64 recno, u8 *b)
{
    if (recno >= fs->nrec) return GZ_E_FORMAT;
    int r = runs_read(fs, s, &fs->mft, recno * fs->rs, b, fs->rs, 0);
    return r ? r : rec_fix(fs, b);
}

/* Next attribute of record b at *pos (checked header), NULL at the end. */
static const u8 *attr_next(const nt_fs *fs, const u8 *b, u32 *pos)
{
    u32 lim = rec_used(fs, b), p = *pos;
    if (p >= lim || lim - p < 4 || rd32(b + p) == AT_END || lim - p < 0x18) return 0;
    const u8 *a = b + p;
    u32 l = rd32(a + 4);
    if (l < 0x18 || l > lim - p) return 0;
    if (a[8]) {
        if (l < 0x40 || rd16(a + 0x20) >= l) return 0;
    } else {
        u32 vo = rd16(a + 0x14), vl = rd32(a + 0x10);
        if (vo > l || vl > l - vo) return 0;
    }
    if (a[9] && rd16(a + 10) + 2u * a[9] > l) return 0;
    *pos = p + l;
    return a;
}

static const u8 *res_val(const u8 *a, u32 *n) { *n = rd32(a + 0x10); return a + rd16(a + 0x14); }
static int name_eq(const u8 *a, const u8 *name, u32 nlen)
{
    return a[9] == nlen && (!nlen || !__builtin_memcmp(a + rd16(a + 10), name, 2 * nlen));
}

/* ---------------- attribute walk (base record + attribute list) ---------------- */

typedef int (*nt_cb)(void *user, const u8 *a);

typedef struct {
    const nt_fs *fs;
    gz_src *s;
    const u8 *base;                    /* fixed-up base record */
    u64 recno;
    u8 *xbuf;                          /* NT_XCACHE extension records */
    u64 xtag[NT_XCACHE];               /* record number + 1, 0 = empty */
    u64 *budget;                       /* attribute list bytes still allowed (open) */
} nt_walk;

/* Extension record rn belonging to the walked file, or NULL. */
static const u8 *walk_xrec(nt_walk *w, u64 rn, u32 seq)
{
    const nt_fs *fs = w->fs;
    if (!w->xbuf && !(w->xbuf = (u8 *)gz_alloc((size_t)fs->rs * NT_XCACHE))) return 0;
    u32 slot = (u32)(rn % NT_XCACHE);
    u8 *b = w->xbuf + (size_t)slot * fs->rs;
    if (w->xtag[slot] != rn + 1) {
        w->xtag[slot] = 0;
        if (rec_read(fs, w->s, rn, b)) return 0;
        if (!(rd16(b + 0x16) & 1) || !rd64(b + 0x20) || NT_REF(rd64(b + 0x20)) != w->recno) return 0;
        w->xtag[slot] = rn + 1;
    }
    if (seq && rd16(b + 0x10) != seq) return 0;
    return b;
}

/* Load an attribute value (resident or non-resident, at most cap bytes) into a new buffer. */
static int attr_load(const nt_fs *fs, gz_src *s, const u8 *a, u32 cap, u8 **out, u32 *outn)
{
    *out = 0;
    *outn = 0;
    if (!a[8]) {
        u32 n;
        const u8 *v = res_val(a, &n);
        if (n > cap) return GZ_E_LIMIT;
        u8 *p = (u8 *)gz_alloc(n + 1);
        if (!p) return GZ_E_NOMEM;
        __builtin_memcpy(p, v, n);
        *out = p;
        *outn = n;
        return GZ_OK;
    }
    u64 size = rd64(a + 0x30);
    if (rd64(a + 0x10) || size > cap) return size > cap ? GZ_E_LIMIT : GZ_E_FORMAT;
    if (rd16(a + 0x0C) & (AF_COMP | AF_ENC)) return GZ_E_METHOD;
    nt_runs rl;
    __builtin_memset(&rl, 0, sizeof rl);
    u32 mo = rd16(a + 0x20);
    int r = runs_decode(fs, &rl, a + mo, rd32(a + 4) - mo, 0);
    u8 *p = r ? 0 : (u8 *)gz_alloc((size_t)size + 1);
    if (!r && !p) r = GZ_E_NOMEM;
    if (!r) r = runs_read(fs, s, &rl, 0, p, (u32)size, 1);
    runs_free(&rl);
    if (r) { gz_free(p); return r; }
    *out = p;
    *outn = (u32)size;
    return GZ_OK;
}

/* Call cb for every attribute of the file: in record order, or in attribute list
 * order (type, name, VCN) when the base record has an $ATTRIBUTE_LIST. */
static int walk_attrs(nt_walk *w, nt_cb cb, void *user)
{
    const nt_fs *fs = w->fs;
    const u8 *a, *al_attr = 0;
    u32 pos = rd16(w->base + 0x14);
    while ((a = attr_next(fs, w->base, &pos)))
        if (rd32(a) == AT_AL) { al_attr = a; break; }
    if (al_attr && w->budget) {
        u64 need = al_attr[8] ? rd64(al_attr + 0x30) : rd32(al_attr + 0x10);
        if (need > *w->budget) al_attr = 0;           /* budget spent: base record only */
        else *w->budget -= need;
    }
    u8 *al = 0;
    u32 aln = 0;
    if (al_attr) {
        int r = attr_load(fs, w->s, al_attr, NT_MAX_AL, &al, &aln);
        if (r == GZ_E_NOMEM) return r;
        if (r) al = 0;                                /* unreadable list: base record only */
    }
    if (!al) {
        pos = rd16(w->base + 0x14);
        while ((a = attr_next(fs, w->base, &pos))) {
            int r = cb(user, a);
            if (r) return r;
        }
        return GZ_OK;
    }
    int r = GZ_OK;
    u8 seen[32];                                      /* base attributes reached through the list */
    __builtin_memset(seen, 0, sizeof seen);
    for (u32 p = 0; p + 0x1A <= aln;) {
        const u8 *e = al + p;
        u32 el = rd16(e + 4);
        if (el < 0x1A || el > aln - p) break;
        p += el;
        u32 type = rd32(e);
        if (type == AT_AL || type == AT_END) continue;
        u64 ref = rd64(e + 0x10), rn = NT_REF(ref);
        const u8 *b = rn == w->recno ? w->base : walk_xrec(w, rn, (u32)(ref >> 48));
        if (!b) continue;
        u32 q = rd16(b + 0x14), k = 0;
        u16 inst = rd16(e + 0x18);
        for (; (a = attr_next(fs, b, &q)); k++)
            if (rd32(a) == type && rd16(a + 0x0E) == inst) break;
        if (!a) continue;
        if (b == w->base && k < 256) {
            if (seen[k >> 3] & (1u << (k & 7))) continue;  /* listed twice */
            seen[k >> 3] |= (u8)(1u << (k & 7));
        }
        if ((r = cb(user, a))) break;
    }
    /* base attributes the list does not reach (damaged list) are still the file's */
    pos = rd16(w->base + 0x14);
    for (u32 k = 0; !r && k < 256 && (a = attr_next(fs, w->base, &pos)); k++)
        if (!(seen[k >> 3] & (1u << (k & 7))) && rd32(a) != AT_AL) r = cb(user, a);
    gz_free(al);
    return r;
}

static void walk_done(nt_walk *w)
{
    gz_free(w->xbuf);
    w->xbuf = 0;
}

/* ---------------- streams ---------------- */

typedef struct {
    u64 size, alloc, init, csize;
    u16 flags;
    u8 cu, resident, found;
    u8 *res;                           /* resident value (size bytes) */
    nt_runs rl;
} nt_data;

typedef struct { const nt_fs *fs; nt_data *d; const u8 *name; u32 nlen; int err; } nt_dsel;

static int data_cb(void *user, const u8 *a)
{
    nt_dsel *q = (nt_dsel *)user;
    nt_data *d = q->d;
    if (rd32(a) != AT_DATA || !name_eq(a, q->name, q->nlen)) return GZ_OK;
    if (!a[8]) {
        if (d->found) return GZ_OK;                   /* duplicate: keep the first */
        u32 n;
        const u8 *v = res_val(a, &n);
        d->res = (u8 *)gz_alloc(n + 1);
        if (!d->res) return GZ_E_NOMEM;
        __builtin_memcpy(d->res, v, n);
        d->size = d->alloc = d->init = d->csize = n;
        d->resident = 1;
        d->found = 1;
        return GZ_OK;
    }
    if (d->resident) return GZ_OK;
    u64 lv = rd64(a + 0x10);
    if (!d->found) {
        if (lv) return GZ_OK;                         /* first extent must start at VCN 0 */
        d->found = 1;
        d->flags = rd16(a + 0x0C);
        d->cu = a[0x22];
        d->alloc = rd64(a + 0x28);
        d->size = rd64(a + 0x30);
        d->init = rd64(a + 0x38);
        d->csize = (rd16(a + 0x20) >= 0x48 && (d->flags & (AF_COMP | AF_SPARSE))) ? rd64(a + 0x40) : d->alloc;
        if (d->size > d->alloc || d->init > d->size) q->err = GZ_E_FORMAT;
    }
    u32 mo = rd16(a + 0x20);
    int r = runs_decode(q->fs, &d->rl, a + mo, rd32(a + 4) - mo, lv);
    if (r == GZ_E_NOMEM || r == GZ_E_LIMIT) return r;
    if (r && !q->err) q->err = r;
    return GZ_OK;
}

static void data_free(nt_data *d)
{
    gz_free(d->res);
    runs_free(&d->rl);
}

/* Read base record recno into b (rs bytes): in use, not an extension record. */
static int base_read(const nt_fs *fs, gz_src *s, u64 recno, u8 *b)
{
    int r = rec_read(fs, s, recno, b);
    if (r) return r;
    if (!(rd16(b + 0x16) & 1) || rd64(b + 0x20)) return GZ_E_FORMAT;
    return GZ_OK;
}

/* Load the $DATA stream called name (UTF-16LE, nlen chars, 0 = unnamed) of record recno. */
static int data_load(const nt_fs *fs, gz_src *s, u64 recno, const u8 *name, u32 nlen, nt_data *d)
{
    __builtin_memset(d, 0, sizeof *d);
    u8 *b = (u8 *)gz_alloc(fs->rs);
    if (!b) return GZ_E_NOMEM;
    int r = base_read(fs, s, recno, b);
    if (!r) {
        nt_walk w;
        __builtin_memset(&w, 0, sizeof w);
        w.fs = fs; w.s = s; w.base = b; w.recno = recno;
        nt_dsel q = { fs, d, name, nlen, 0 };
        r = walk_attrs(&w, data_cb, &q);
        walk_done(&w);
        if (!r) r = q.err ? q.err : (d->found ? GZ_OK : GZ_E_FORMAT);
    }
    gz_free(b);
    if (r) data_free(d);
    return r;
}

/* Emit the bytes of a plain (uncompressed) non-resident stream: runs up to the
 * initialized size, zeros after it. */
static int emit_plain(const nt_fs *fs, const nt_data *d, gz_fs1_sink *k)
{
    u64 init = d->init, pos = 0;
    for (u32 i = 0; i < d->rl.n && pos < init; i++) {
        const nt_run *r = &d->rl.r[i];
        u64 rb = r->vcn << fs->cshift, rl = r->len << fs->cshift;
        if (rl > init - rb) rl = init - rb;
        int e = gz_fs1_emit(k, r->lcn == NT_HOLE ? GZ_FS1_HOLE : r->lcn << fs->cshift, rl);
        pos = rb + rl;
        if (e == GZ_FS1_FULL) break;
        if (e) return e;
    }
    if (pos < init && k->pos < k->limit) return GZ_E_DATA;   /* runs end before the data */
    return gz_fs1_flush(k, 1);
}

/* Sequential read-ahead over a source: random patterns read what is asked,
 * a read that continues the window refills it with up to NT_RCACHE bytes. */
typedef struct { gz_src *s; u8 *buf; u32 cap, len; u64 base; } nt_rcache;

static int rc_read(nt_rcache *rc, u64 off, u8 *dst, u32 n)
{
    if (off >= rc->base && off - rc->base <= rc->len && n <= rc->len - (off - rc->base)) {
        __builtin_memcpy(dst, rc->buf + (off - rc->base), n);
        return GZ_OK;
    }
    if (off != rc->base + rc->len || n > rc->cap) {
        rc->base = off + n;
        rc->len = 0;
        return gz_src_read_exact(rc->s, off, dst, n);
    }
    u64 avail = rc->s->size > off ? rc->s->size - off : 0;
    u32 want = avail < rc->cap ? (u32)avail : rc->cap;
    if (want < n) return GZ_E_TRUNC;
    rc->len = 0;
    int r = gz_src_read_exact(rc->s, off, rc->buf, want);
    if (r) return r;
    rc->base = off;
    rc->len = want;
    __builtin_memcpy(dst, rc->buf, n);
    return GZ_OK;
}

/* output batching */
typedef struct { gz_out *out; u8 *buf; u32 n, cap; } nt_obuf;
static int ob_flush(nt_obuf *o)
{
    int r = o->n ? o->out->write(o->out, o->buf, o->n) : GZ_OK;
    o->n = 0;
    return r;
}

/* physical pieces of the clusters [vcn, vcn + cnt) up to the first hole */
typedef struct { u64 off; u32 len; } nt_piece;

static u32 cu_pieces(const nt_fs *fs, const nt_runs *rl, u32 *ri, u64 vcn, u32 cnt, nt_piece *pc, u32 *npc)
{
    while (*ri < rl->n && rl->r[*ri].vcn + rl->r[*ri].len <= vcn) (*ri)++;
    u32 got = 0, k = 0;
    for (u32 i = *ri; got < cnt && i < rl->n; i++) {
        const nt_run *x = &rl->r[i];
        u64 v = vcn + got;
        if (x->vcn > v || x->lcn == NT_HOLE) break;
        u64 in = v - x->vcn, avail = x->len - in;
        u32 take = cnt - got < avail ? cnt - got : (u32)avail;
        pc[k].off = (x->lcn + in) << fs->cshift;
        pc[k].len = take << fs->cshift;
        k++;
        got += take;
    }
    *npc = k;
    return got;
}

/* LZNT1 compressed stream: compression units of 2^cu clusters. A unit whose
 * clusters are all allocated is stored, one that starts with a hole is zeros,
 * otherwise the allocated clusters up to the first hole hold LZNT1 chunks. */
static int write_lznt1(const nt_fs *fs, gz_src *s, const nt_data *d, gz_out *out, gz_ctx *c)
{
    u32 ucl = 1u << d->cu, ub = fs->cs << d->cu;
    u8 *mem = gz_ctx_buffer(c, NT_OBUF + NT_RCACHE + 2 * ub);
    nt_piece *pc = (nt_piece *)gz_alloc(ucl * sizeof(nt_piece));
    if (!mem || !pc) { gz_free(pc); return GZ_E_NOMEM; }
    nt_obuf ob = { out, mem, 0, NT_OBUF + ub };
    u8 *inb = mem + NT_OBUF + ub;
    nt_rcache rc = { s, inb + ub, NT_RCACHE, 0, 0 };
    u32 ri = 0;
    int r = GZ_OK;
    for (u64 pos = 0; pos < d->size && !r; pos += ub) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        u64 vcn = pos >> fs->cshift;
        u8 *o = ob.buf + ob.n;
        u32 np, got = cu_pieces(fs, &d->rl, &ri, vcn, ucl, pc, &np);
        if (!got) {
            if (vcn >= d->rl.end && pos < d->init) { r = GZ_E_DATA; break; }   /* not mapped */
            __builtin_memset(o, 0, ub);
        } else {
            u8 *dst = got == ucl ? o : inb;
            for (u32 i = 0; i < np && !r; i++) {
                r = rc_read(&rc, pc[i].off, dst, pc[i].len);
                dst += pc[i].len;
            }
            if (r) break;
            if (got < ucl) {
                size_t on = 0;
                if (gz_lznt1_decode(inb, (size_t)got << fs->cshift, o, ub, &on)) { r = GZ_E_DATA; break; }
                if (on < ub) __builtin_memset(o + on, 0, ub - on);
            }
        }
        u64 left = d->size - pos;
        u32 n = left < ub ? (u32)left : ub;
        if (pos + n > d->init) {                       /* past the initialized size */
            u32 z0 = d->init > pos ? (u32)(d->init - pos) : 0;
            __builtin_memset(o + z0, 0, n - z0);
        }
        ob.n += n;
        if (ob.n >= NT_OBUF) r = ob_flush(&ob);
    }
    gz_free(pc);
    if (!r) r = ob_flush(&ob);
    return r;
}

/* Random-access source over a stream (resident copy, or plain runs). Takes the
 * resident buffer from d. */
static int data_src(const nt_fs *fs, gz_src *s, nt_data *d, gz_src **out)
{
    *out = 0;
    if (d->resident) {
        gz_src *v = gz_src_mem(d->res, d->size, 1);
        if (!v) return GZ_E_NOMEM;
        d->res = 0;
        *out = v;
        return GZ_OK;
    }
    if (d->flags & AF_ENC) return GZ_E_METHOD;
    if ((d->flags & AF_COMP) && d->cu) return GZ_E_METHOD;
    gz_fs1_list l;
    gz_fs1_list_init(&l, d->size, NT_MAX_RUNS + 2);
    int r = emit_plain(fs, d, &l.k);
    if (r) { gz_fs1_list_free(&l); return r; }
    *out = gz_fs1_list_src(s, &l);
    return *out ? GZ_OK : GZ_E_DATA;
}

static int write_data(const nt_fs *fs, gz_src *s, nt_data *d, gz_out *out, gz_ctx *c)
{
    if (d->resident) return d->size ? out->write(out, d->res, (size_t)d->size) : GZ_OK;
    if (d->flags & AF_ENC) return GZ_E_METHOD;
    if ((d->flags & AF_COMP) && d->cu) {
        if ((d->flags & AF_COMP) != 1 || d->cu > 8 || (fs->cs << d->cu) > (2u << 20)) return GZ_E_METHOD;
        return write_lznt1(fs, s, d, out, c);
    }
    gz_fs1_copy w;
    int r = gz_fs1_copy_init(&w, s, out, c, d->size);
    return r ? r : emit_plain(fs, d, &w.k);
}

/* ---------------- WOF system compression ---------------- */

static const u8 wof_name[34] = { 'W',0,'o',0,'f',0,'C',0,'o',0,'m',0,'p',0,'r',0,'e',0,'s',0,'s',0,
                                 'e',0,'d',0,'D',0,'a',0,'t',0,'a',0 };

/* WofCompressedData: chunk table ((chunks - 1) offsets, 4 bytes, 8 when the file
 * is >= 4 GiB, relative to the table end), then the chunks; a chunk as large as
 * its output is stored. algo: 0 XPRESS4K, 1 LZX (32K), 2 XPRESS8K, 3 XPRESS16K. */
static int write_wof(const nt_fs *fs, gz_src *s, u64 recno, u64 usize, u32 algo, gz_out *out, gz_ctx *c)
{
    nt_data d;
    int r = data_load(fs, s, recno, wof_name, 17, &d);
    if (r) return r;
    gz_src *v;
    r = data_src(fs, s, &d, &v);
    data_free(&d);
    if (r) return r;
    u32 csh = algo == 1 ? 15 : algo ? 11 + algo : 12, chunk = 1u << csh;
    u64 nch = (usize + chunk - 1) >> csh;
    u32 esz = usize > 0xFFFFFFFFu ? 8 : 4;
    u64 tsz = (nch - 1) * esz;
    u8 *mem = gz_ctx_buffer(c, NT_OBUF + NT_RCACHE + 2 * chunk + 65536);
    gz_lzx_dec *lz = 0;
    if (!mem) r = GZ_E_NOMEM;
    else if (tsz > v->size) r = GZ_E_DATA;
    else if (algo == 1) {
        lz = (gz_lzx_dec *)gz_ctx_slot(c, GZ_SLOT_LZX, gz_lzx_slot_new, gz_lzx_slot_free);
        r = lz ? gz_lzx_init(lz, 15, GZ_LZX_WIM) : GZ_E_NOMEM;
    }
    if (r) { gz_src_free(v); return r; }
    nt_obuf ob = { out, mem, 0, NT_OBUF + chunk };
    u8 *inb = mem + NT_OBUF + chunk, *tab = inb + chunk;
    nt_rcache rc = { v, tab + 65536, NT_RCACHE, 0, 0 };
    u64 dlen = v->size - tsz, prev = 0, tb = 0, tn = 0;     /* table window: entries [tb, tb + tn) */
    for (u64 i = 0; i < nch; i++) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        u64 end = dlen;
        if (i + 1 < nch) {
            if (i < tb || i >= tb + tn) {
                tb = i;
                tn = nch - 1 - i < 65536 / esz ? nch - 1 - i : 65536 / esz;
                if ((r = gz_src_read_exact(v, i * esz, tab, (u32)(tn * esz)))) break;
            }
            const u8 *p = tab + (i - tb) * esz;
            end = esz == 8 ? rd64(p) : rd32(p);
        }
        u64 left = usize - (i << csh);
        u32 un = left < chunk ? (u32)left : chunk;
        if (end <= prev || end > dlen || end - prev > un) { r = GZ_E_DATA; break; }
        u32 cn = (u32)(end - prev);
        u8 *o = ob.buf + ob.n;
        if (cn == un) {
            r = rc_read(&rc, tsz + prev, o, un);
        } else if (!(r = rc_read(&rc, tsz + prev, inb, cn))) {
            r = algo == 1 ? gz_lzx_decode_chunk(lz, inb, cn, o, un) : gz_xpress_huff_decode(inb, cn, o, un);
            if (r) r = GZ_E_DATA;
        }
        if (r) break;
        prev = end;
        ob.n += un;
        if (ob.n >= NT_OBUF && (r = ob_flush(&ob))) break;
    }
    if (!r) r = ob_flush(&ob);
    gz_src_free(v);
    return r;
}

/* ---------------- open: MFT scan ---------------- */

typedef struct {
    u64 mtime;
    u32 rec, attr;
    u16 seq, rflags;
    u32 name0, nname;                  /* names[] */
    u32 strm0, nstrm;                  /* strms[] */
    u32 lk_off, lk_len;                /* link target (UTF-8) in a->raw */
    u8 kind;                           /* NK_LINK / NK_WOF / NK_UNSUP (reparse) or 0 */
    u8 wof;                            /* WOF algorithm */
    u8 has_si;
} nt_file;

typedef struct { u64 parent; u32 off; u8 len, ns; } nt_name;            /* name in pool */
typedef struct { u64 size, csize; u32 off; u16 flags; u8 len, res, cu; } nt_strm;

typedef struct {
    gz_archive *a;
    gz_src *s;
    gz_ctx *c;
    nt_fs *fs;
    nt_file *f;  u32 nf, capf;
    nt_name *nm; u32 nn, capn;
    nt_strm *st; u32 ns, caps;
    u8 *pool;    u32 np, capp;
    i32 *fidx;                         /* record -> file index (-1 = none) */
    u64 budget;                        /* attribute list bytes still allowed */
    nt_file cur;                       /* file being scanned */
    u8 *rp; u32 rpn;                   /* its reparse data */
    u8 intx[8 + 2 * 1024]; u32 intxn;  /* its resident Interix symlink data */
} nt_open;

static int grow(void **p, u32 *cap, u32 n, u32 add, size_t esz)
{
    if ((u64)n + add <= *cap) return GZ_OK;
    u64 nc = *cap ? *cap : 64;
    while (nc < (u64)n + add) nc *= 2;
    if (nc > 0x7FFFFFFFu || nc * esz > ((size_t)-1) / 4) return GZ_E_LIMIT;
    void *q = gz_realloc(*p, (size_t)(nc * esz));
    if (!q) return GZ_E_NOMEM;
    *p = q;
    *cap = (u32)nc;
    return GZ_OK;
}

static int pool_add(nt_open *o, const u8 *p, u32 n, u32 *off)
{
    int r = grow((void **)&o->pool, &o->capp, o->np, n + 1, 1);
    if (r) return r;
    if (n) __builtin_memcpy(o->pool + o->np, p, n);
    *off = o->np;
    o->np += n;
    return GZ_OK;
}

static int scan_cb(void *user, const u8 *a)
{
    nt_open *o = (nt_open *)user;
    nt_file *f = &o->cur;
    u32 t = rd32(a), n;
    int r;
    if (t == AT_SI) {
        if (a[8] || f->has_si) return GZ_OK;
        const u8 *v = res_val(a, &n);
        if (n < 0x24) return GZ_OK;
        f->mtime = rd64(v + 8);
        f->attr = rd32(v + 0x20);
        f->has_si = 1;
    } else if (t == AT_FN) {
        if (a[8] || o->nn - f->name0 >= 1024) return GZ_OK;
        const u8 *v = res_val(a, &n);
        u32 len = n >= 0x42 ? v[0x40] : 0;
        if (!len || 0x42 + 2 * len > n) return GZ_OK;
        if ((r = grow((void **)&o->nm, &o->capn, o->nn, 1, sizeof(nt_name)))) return r;
        nt_name *x = &o->nm[o->nn];
        if ((r = pool_add(o, v + 0x42, 2 * len, &x->off))) return r;
        x->parent = rd64(v);
        x->len = (u8)len;
        x->ns = v[0x41];
        o->nn++;
        if (!f->has_si && !f->mtime) f->mtime = rd64(v + 0x10);
    } else if (t == AT_DATA) {
        if ((a[8] && rd64(a + 0x10)) || o->ns - f->strm0 >= 1024) return GZ_OK;
        if ((r = grow((void **)&o->st, &o->caps, o->ns, 1, sizeof(nt_strm)))) return r;
        nt_strm *x = &o->st[o->ns];
        __builtin_memset(x, 0, sizeof *x);
        x->flags = rd16(a + 0x0C);
        if (!a[8]) {
            const u8 *v = res_val(a, &n);
            x->size = x->csize = n;
            x->res = 1;
            if (!a[9] && n >= 10 && n <= sizeof o->intx && !__builtin_memcmp(v, "IntxLNK\1", 8)) {
                __builtin_memcpy(o->intx, v, n);
                o->intxn = n;
            }
        } else {
            u64 alloc = rd64(a + 0x28);
            x->size = rd64(a + 0x30);
            x->cu = a[0x22];
            x->csize = (rd16(a + 0x20) >= 0x48 && (x->flags & (AF_COMP | AF_SPARSE))) ? rd64(a + 0x40) : alloc;
        }
        x->len = a[9];
        if ((r = pool_add(o, a + rd16(a + 10), 2u * a[9], &x->off))) return r;
        o->ns++;
    } else if (t == AT_REPARSE) {
        if (o->rpn) return GZ_OK;
        u8 *p;
        u32 pn;
        r = attr_load(o->fs, o->s, a, NT_MAX_RP, &p, &pn);
        if (r == GZ_E_NOMEM) return r;
        if (!r && pn >= 8) { gz_free(o->rp); o->rp = p; o->rpn = pn; }
        else gz_free(p);
    } else if (t == AT_VOLNAME && f->rec == 3 && !a[8] && !o->a->comment_raw) {
        const u8 *v = res_val(a, &n);
        n &= ~1u;
        if (n && n <= 256 && (o->a->comment_raw = (u8 *)gz_alloc(n))) {
            __builtin_memcpy(o->a->comment_raw, v, n);
            o->a->comment_len = n;
            o->a->comment_enc = GZ_NE_UTF16LE;
        }
    }
    return GZ_OK;
}

/* Store a link target given as UTF-16LE (nb bytes). nt: Windows path (substitute
 * name): "\??\" prefix dropped, "UNC\" -> "//", '\' -> '/'. */
static int set_link(nt_open *o, nt_file *f, const u8 *p, u32 nb, int nt)
{
    u32 n = nb / 2, i = 0, k = 0;
    if (!n || n > 8192) return GZ_OK;
    gzch *w = (gzch *)gz_alloc((size_t)n * 2 + 8);
    u8 *u = (u8 *)gz_alloc((size_t)n * 3 + 8);
    int r = GZ_E_NOMEM;
    if (w && u) {
        if (nt && n >= 4 && rd16(p) == '\\' && rd16(p + 2) == '?' && rd16(p + 4) == '?' && rd16(p + 6) == '\\') {
            i = 4;
            if (n >= 8 && (rd16(p + 8) | 0x20) == 'u' && (rd16(p + 10) | 0x20) == 'n' &&
                (rd16(p + 12) | 0x20) == 'c' && rd16(p + 14) == '\\') {
                i = 8;
                w[k++] = '/';
                w[k++] = '/';
            }
        }
        for (; i < n; i++) {
            gzch ch = rd16(p + 2 * i);
            if (!ch) break;
            w[k++] = nt && ch == '\\' ? '/' : ch;
        }
        r = GZ_OK;
        if (k) {
            u32 m = (u32)gz_utf16_to_utf8(w, k, u);
            if (m && !(r = gz_arc_raw_append(o->a, u, m, &f->lk_off))) {
                f->lk_len = m;
                f->kind = NK_LINK;
            }
        }
    }
    gz_free(w);
    gz_free(u);
    return r;
}

/* 1 + index of f's stream called name, 0 = none */
static u32 find_stream(const nt_open *o, const nt_file *f, const u8 *name, u32 nlen)
{
    for (u32 i = 0; i < f->nstrm; i++) {
        const nt_strm *x = &o->st[f->strm0 + i];
        if (x->len == nlen && (!nlen || !__builtin_memcmp(o->pool + x->off, name, 2 * nlen))) return i + 1;
    }
    return 0;
}

/* reparse point: symbolic link, junction or WOF */
static int use_reparse(nt_open *o, nt_file *f)
{
    const u8 *p = o->rp;
    u32 tag = rd32(p), dl = rd16(p + 4);
    if (dl > o->rpn - 8) dl = o->rpn - 8;
    if (tag == RT_SYMLINK || tag == RT_MOUNT) {
        u32 hdr = tag == RT_SYMLINK ? 12 : 8;
        if (dl < hdr) return GZ_OK;
        u32 so = rd16(p + 8), sl = rd16(p + 10);
        if (so + sl > dl - hdr) return GZ_OK;
        return set_link(o, f, p + 8 + hdr + so, sl, 1);
    }
    if (tag == RT_WOF && dl >= 16 && find_stream(o, f, wof_name, 17)) {
        if (rd32(p + 8) != 1 || rd32(p + 12) != 2 || rd32(p + 16) != 1 || rd32(p + 20) > 3) {
            f->kind = NK_UNSUP;                    /* WIMBoot (provider 1) or a newer layout */
        } else {
            f->kind = NK_WOF;
            f->wof = (u8)rd32(p + 20);
        }
    }
    return GZ_OK;
}

static int scan_file(nt_open *o, u64 recno, const u8 *b)
{
    nt_file *f = &o->cur;
    __builtin_memset(f, 0, sizeof *f);
    f->rec = (u32)recno;
    f->seq = rd16(b + 0x10);
    f->rflags = rd16(b + 0x16);
    f->name0 = o->nn;
    f->strm0 = o->ns;
    o->rpn = 0;
    o->intxn = 0;
    nt_walk w;
    __builtin_memset(&w, 0, sizeof w);
    w.fs = o->fs; w.s = o->s; w.base = b; w.recno = recno; w.budget = &o->budget;
    int r = walk_attrs(&w, scan_cb, o);
    walk_done(&w);
    if (r) return r;
    f->nname = o->nn - f->name0;
    f->nstrm = o->ns - f->strm0;
    if (!f->nname) {                               /* nameless record: not listed */
        o->nn = f->name0;
        o->ns = f->strm0;
        return GZ_OK;
    }
    if (o->rpn) r = use_reparse(o, f);
    else if (o->intxn && (f->attr & FA_SYSTEM) && !(f->rflags & 2))
        r = set_link(o, f, o->intx + 8, o->intxn - 8, 0);   /* ntfs-3g (Interix) symlink */
    if (r) return r;
    if ((r = grow((void **)&o->f, &o->capf, o->nf, 1, sizeof(nt_file)))) return r;
    o->fidx[recno] = (i32)o->nf;
    o->f[o->nf++] = *f;
    return GZ_OK;
}

/* non-resident Interix symlinks (long targets) */
static int intx_nonres(nt_open *o, nt_file *f)
{
    u32 k = find_stream(o, f, 0, 0);
    if (!k || f->kind || !(f->attr & FA_SYSTEM) || (f->rflags & 2)) return GZ_OK;
    const nt_strm *x = &o->st[f->strm0 + k - 1];
    if (x->res || x->size < 10 || x->size > 8 + 2 * 8192 || (x->flags & (AF_COMP | AF_ENC))) return GZ_OK;
    nt_data d;
    int r = data_load(o->fs, o->s, f->rec, 0, 0, &d);
    if (r) return r == GZ_E_NOMEM ? r : GZ_OK;
    u8 *buf = 0;
    if (d.resident || d.size < 10 || d.size > 8 + 2 * 8192 || d.init < d.size) r = GZ_E_FORMAT;
    else if (!(buf = (u8 *)gz_alloc((size_t)d.size))) r = GZ_E_NOMEM;
    else r = runs_read(o->fs, o->s, &d.rl, 0, buf, (u32)d.size, 1);
    if (!r && !__builtin_memcmp(buf, "IntxLNK\1", 8)) r = set_link(o, f, buf + 8, (u32)d.size - 8, 0);
    gz_free(buf);
    data_free(&d);
    return r == GZ_E_NOMEM ? r : GZ_OK;
}

/* ---------------- open: folder tree and entries ---------------- */

#define ND_UNSET (-1)
#define ND_BUSY  (-2)

typedef struct {
    nt_open *o;
    gz_fs1_tree t;
    i32 *node;                         /* file index -> tree node of a directory */
    u32 *stack;
    i32 sys, lost;                     /* "[SYSTEM]" / "[LOST]" nodes (-1 = not made yet) */
    u8 nbuf[2 * (255 + 1 + 255) + 8];  /* "name:stream" */
} nt_tree;

static i32 special_node(nt_tree *T, i32 *slot, const char *name, u32 aux)
{
    if (*slot >= 0) return *slot;
    u8 w[32];
    u32 n = 0;
    for (; name[n]; n++) { w[2 * n] = (u8)name[n]; w[2 * n + 1] = 0; }
    *slot = gz_fs1_tree_add(&T->t, 0, w, 2 * n, GZ_NE_UTF16LE, 0, 0, aux);
    return *slot;
}

/* Win32 / POSIX name (a DOS 8.3 name only when there is nothing else) */
static u32 prim_name(const nt_open *o, const nt_file *f)
{
    for (u32 i = 0; i < f->nname; i++)
        if (o->nm[f->name0 + i].ns != 2) return f->name0 + i;
    return f->name0;
}

/* metafiles in the root directory go to "[SYSTEM]" */
static i32 top_node(nt_tree *T, const nt_file *f)
{
    return f->rec < NT_SYSRECS ? special_node(T, &T->sys, "[SYSTEM]", 1) : 0;
}

/* directory a parent reference points to: file index, -1 = root, -2 = none */
static i32 parent_dir(const nt_open *o, u64 ref)
{
    u64 rn = NT_REF(ref);
    u32 seq = (u32)(ref >> 48);
    if (rn == NT_ROOT) return -1;
    if (rn >= o->fs->nrec || o->fidx[rn] < 0) return -2;
    const nt_file *p = &o->f[o->fidx[rn]];
    if (!(p->rflags & 2) || (seq && p->seq != seq)) return -2;
    return o->fidx[rn];
}

/* Tree node of directory fi: climbs the parent chain iteratively; a cycle or a
 * missing parent attaches the topmost directory to "[LOST]". -1 = out of memory. */
static i32 dir_node(nt_tree *T, u32 fi)
{
    nt_open *o = T->o;
    i32 *node = T->node;
    u32 n = 0, x = fi;
    i32 par;
    for (;;) {
        if (node[x] >= 0) { par = node[x]; break; }
        if (node[x] == ND_BUSY) { par = special_node(T, &T->lost, "[LOST]", 0); break; }
        T->stack[n++] = x;
        node[x] = ND_BUSY;
        const nt_file *f = &o->f[x];
        i32 p = parent_dir(o, o->nm[prim_name(o, f)].parent);
        if (p == -1) { par = top_node(T, f); break; }
        if (p == -2) { par = special_node(T, &T->lost, "[LOST]", 0); break; }
        x = (u32)p;
    }
    for (u32 i = n; i-- > 0;) {
        u32 y = T->stack[i];
        i32 k = -1;
        if (par >= 0) {
            const nt_name *nm = &o->nm[prim_name(o, &o->f[y])];
            k = gz_fs1_tree_add(&T->t, par, o->pool + nm->off, 2u * nm->len, GZ_NE_UTF16LE, y, 0, T->t.n[par].aux);
            if (k == -2) {                         /* too deep: continue below "[LOST]" */
                i32 l = special_node(T, &T->lost, "[LOST]", 0);
                k = l < 0 ? -1 : gz_fs1_tree_add(&T->t, l, o->pool + nm->off, 2u * nm->len, GZ_NE_UTF16LE, y, 0, 0);
            }
        }
        node[y] = k >= 0 ? k : ND_UNSET;
        par = k;
    }
    return node[fi] >= 0 ? node[fi] : -1;
}

static u8 strm_kind(const nt_fs *fs, const nt_file *f, const nt_strm *x)
{
    if ((x->flags & AF_ENC) || (f->attr & FA_ENC)) return NK_EFS;
    if (x->res) return NK_RESIDENT;
    if ((x->flags & AF_COMP) && x->cu)
        return ((x->flags & AF_COMP) == 1 && x->cu <= 8 && (fs->cs << x->cu) <= (2u << 20)) ? NK_LZNT1 : NK_UNSUP;
    return (x->flags & AF_SPARSE) ? NK_SPARSE : NK_PLAIN;
}

static int add_entry(nt_tree *T, i32 par, const nt_name *nm, const nt_strm *x, gz_entry **pe)
{
    nt_open *o = T->o;
    const u8 *name = o->pool + nm->off;
    u32 len = 2u * nm->len;
    if (x) {
        __builtin_memcpy(T->nbuf, name, len);
        T->nbuf[len] = ':';
        T->nbuf[len + 1] = 0;
        __builtin_memcpy(T->nbuf + len + 2, o->pool + x->off, 2u * x->len);
        name = T->nbuf;
        len += 2 + 2u * x->len;
    }
    return gz_fs1_add_entry(o->a, &T->t, par, name, len, GZ_NE_UTF16LE, pe);
}

static void fill(const nt_file *f, gz_entry *e, int isdir, u8 aux)
{
    e->off = f->rec;
    if (f->mtime) {
        e->mtime = f->mtime;
        e->mtime_kind = GZ_MT_FILETIME;
    }
    e->attr = f->attr | (isdir ? FA_DIR : 0);
    e->is_dir = (u8)isdir;
    e->is_aux = aux;
}

/* entries of one file: every hard link, and for each its alternate streams */
static int emit_file(nt_tree *T, u32 fi)
{
    nt_open *o = T->o;
    const nt_file *f = &o->f[fi];
    if (f->rec == NT_ROOT) return GZ_OK;
    int isdir = (f->rflags & 2) && f->kind != NK_LINK;
    u32 prim = prim_name(o, f), us = find_stream(o, f, 0, 0);
    int dos_only = o->nm[prim].ns == 2;
    const nt_strm *ux = us ? &o->st[f->strm0 + us - 1] : 0;
    u32 nent = 0;                                  /* links x streams: bounded per file */
    for (u32 i = 0; i < f->nname && nent < NT_MAX_FENT; i++) {
        const nt_name *nm = &o->nm[f->name0 + i];
        if (isdir ? f->name0 + i != prim : (nm->ns == 2 && !dos_only)) continue;
        i32 par;
        if (isdir) {
            i32 dn = dir_node(T, fi);
            if (dn < 0) return GZ_E_NOMEM;
            par = T->t.n[dn].parent;
        } else {
            i32 p = parent_dir(o, nm->parent);
            par = p == -1 ? top_node(T, f) : p == -2 ? special_node(T, &T->lost, "[LOST]", 0) : dir_node(T, (u32)p);
            if (par < 0) return GZ_E_NOMEM;
        }
        u8 aux = (u8)(T->t.n[par].aux & 1);
        gz_entry *e;
        int r = add_entry(T, par, nm, 0, &e);
        if (r) return r;
        fill(f, e, isdir, aux);
        nent++;
        if (!isdir) {
            if (f->kind == NK_LINK) {
                e->is_link = 1;
                e->link_off = f->lk_off;
                e->link_len = f->lk_len;
                e->method = NK_LINK;
            } else if (ux) {
                e->usize = ux->size;
                e->csize = ux->csize;
                e->flags = ux->flags;
                e->method = strm_kind(o->fs, f, ux);
                if (f->kind == NK_UNSUP) e->method = NK_UNSUP;
                if (f->kind == NK_WOF && e->method != NK_EFS) {
                    u32 k = find_stream(o, f, wof_name, 17);
                    e->method = NK_WOF;
                    e->aux32 = f->wof;
                    e->csize = o->st[f->strm0 + k - 1].size;
                }
            }
        }
        for (u32 j = 0; j < f->nstrm && ++nent <= NT_MAX_FENT; j++) {
            const nt_strm *x = &o->st[f->strm0 + j];
            const u8 *sn = o->pool + x->off;
            if (!x->len) continue;
            if (f->kind == NK_WOF && x->len == 17 && !__builtin_memcmp(sn, wof_name, 34)) continue;
            if (f->rec == 8 && x->len == 4 && !__builtin_memcmp(sn, "$\0B\0a\0d\0", 8)) continue;   /* $BadClus */
            u32 so;
            if ((r = gz_arc_raw_append(o->a, sn, 2u * x->len, &so))) return r;
            if ((r = add_entry(T, par, nm, x, &e))) return r;
            fill(f, e, 0, 1);
            e->attr &= ~(u32)FA_DIR;
            e->aux = so | (u64)x->len << 32;
            e->usize = x->size;
            e->csize = x->csize;
            e->flags = x->flags;
            e->method = strm_kind(o->fs, f, x);
        }
    }
    return GZ_OK;
}

static int build_entries(nt_open *o)
{
    nt_tree *T = (nt_tree *)gz_alloc(sizeof(nt_tree));
    if (!T) return GZ_E_NOMEM;
    T->o = o;
    T->sys = T->lost = -1;
    int r = gz_fs1_tree_init(&T->t, GZ_NE_UTF8, GZ_CP_UTF8);
    T->node = (i32 *)gz_alloc((size_t)o->nf * sizeof(i32) + 4);
    T->stack = (u32 *)gz_alloc((size_t)o->nf * sizeof(u32) + 4);
    if (!r && (!T->node || !T->stack)) r = GZ_E_NOMEM;
    if (!r) for (u32 i = 0; i < o->nf; i++) T->node[i] = ND_UNSET;
    for (u32 i = 0; !r && i < o->nf; i++) {
        if (!(i & 1023)) {
            if (gz_cancelled(o->c)) { r = GZ_E_CANCEL; break; }
        }
        r = emit_file(T, i);
    }
    gz_fs1_tree_free(&T->t);
    gz_free(T->node);
    gz_free(T->stack);
    gz_free(T);
    return r;
}

/* ---------------- volume ---------------- */

/* Boot sector -> geometry. 0 when it is not an NTFS boot sector. */
static int boot_parse(const u8 *b, nt_fs *fs, u64 *mft, u64 *mirr)
{
    if (__builtin_memcmp(b + 3, "NTFS    ", 8) || b[510] != 0x55 || b[511] != 0xAA) return 0;
    u32 ss = rd16(b + 11), spc = b[13];
    if (ss < 256 || ss > 4096 || (ss & (ss - 1))) return 0;
    if (b[0x10] || rd16(b + 0x11) || rd16(b + 0x13) || rd16(b + 0x16)) return 0;   /* FAT fields */
    u32 sh;
    if (spc <= 0x80) {
        if (!spc || (spc & (spc - 1))) return 0;
        sh = ctz32(spc);
    } else {
        sh = 256 - spc;                                /* 2^(256 - n) sectors (64 KiB+ clusters) */
    }
    u32 cshift = ctz32(ss) + sh;
    if (cshift > 21) return 0;                          /* 2 MiB clusters at most */
    u64 nclus = rd64(b + 0x28) >> sh;
    if (!nclus || nclus > ((u64)1 << (62 - cshift))) return 0;
    i32 v = (i8)b[0x40];
    u32 rs;
    if (v > 0) {
        if (v & (v - 1) || cshift + ctz32((u32)v) > 16) return 0;
        rs = (u32)v << cshift;
    } else {
        if (v > -9 || v < -16) return 0;
        rs = 1u << -v;
    }
    u64 m = rd64(b + 0x30), mm = rd64(b + 0x38);
    if (m >= nclus) return 0;
    if (fs) {
        fs->cs = 1u << cshift;
        fs->cshift = cshift;
        fs->rs = rs;
        fs->nclus = nclus;
        *mft = m;
        *mirr = mm < nclus && mm != m ? mm : 0;
    }
    return 1;
}

static int ntfs_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    return n >= 512 && boot_parse(h, 0, 0, 0) ? 95 : 0;
}

/* $MFT:$DATA runs from record 0 at lcn (and its attribute list extents). */
static int mft_init(nt_fs *fs, gz_src *s, u64 lcn)
{
    runs_free(&fs->mft);
    fs->nrec = 0;
    u32 rs = fs->rs, rsh = ctz32(rs);
    u8 *b = (u8 *)gz_alloc((size_t)rs * 2);
    if (!b) return GZ_E_NOMEM;
    int r = gz_src_read_exact(s, lcn << fs->cshift, b, rs);
    if (!r) r = rec_fix(fs, b);
    if (!r && (!(rd16(b + 0x16) & 1) || rd64(b + 0x20))) r = GZ_E_FORMAT;
    const u8 *a, *al = 0;
    u64 dsize = 0;
    int got = 0;
    u32 pos = rd16(b + 0x14);
    while (!r && (a = attr_next(fs, b, &pos))) {
        u32 t = rd32(a);
        if (t == AT_AL && !al) al = a;
        if (t == AT_DATA && !a[9] && a[8] && !rd64(a + 0x10) && !got) {
            got = 1;
            dsize = rd64(a + 0x30);
            u32 mo = rd16(a + 0x20);
            r = runs_decode(fs, &fs->mft, a + mo, rd32(a + 4) - mo, 0);
        }
    }
    if (!r && !got) r = GZ_E_FORMAT;
    u8 *alv = 0;
    u32 aln = 0;
    if (!r && al && !attr_load(fs, s, al, NT_MAX_AL, &alv, &aln)) {
        /* later extents live in extension records reachable through the runs so far */
        u8 *x = b + rs;
        for (u32 p = 0; p + 0x1A <= aln;) {
            const u8 *e = alv + p;
            u32 el = rd16(e + 4);
            if (el < 0x1A || el > aln - p) break;
            p += el;
            u64 rn = NT_REF(rd64(e + 0x10));
            if (rd32(e) != AT_DATA || e[6] || !rd64(e + 8) || !rn) continue;
            u64 nr = (fs->mft.end << fs->cshift) >> rsh;
            fs->nrec = nr < NT_MAX_REC ? nr : NT_MAX_REC;
            if (rec_read(fs, s, rn, x) || !rd64(x + 0x20) || NT_REF(rd64(x + 0x20))) break;
            u32 q = rd16(x + 0x14);
            while ((a = attr_next(fs, x, &q)))
                if (rd32(a) == AT_DATA && rd16(a + 0x0E) == rd16(e + 0x18)) break;
            if (!a || !a[8] || a[9]) break;
            u32 mo = rd16(a + 0x20);
            if (runs_decode(fs, &fs->mft, a + mo, rd32(a + 4) - mo, rd64(a + 0x10))) break;
        }
    }
    gz_free(alv);
    gz_free(b);
    if (r) return r;
    u64 cover = fs->mft.end;                           /* records up to the first hole */
    for (u32 i = 0; i < fs->mft.n; i++)
        if (fs->mft.r[i].lcn == NT_HOLE) { cover = fs->mft.r[i].vcn; break; }
    u64 bytes = cover << fs->cshift;
    if (dsize < bytes) bytes = dsize;
    u64 n = bytes >> rsh;
    /* overlapping runs cannot hold more records than the image */
    if (fs->mft.phys > ((s->size + fs->cs - 1) >> fs->cshift) && n > (s->size >> rsh)) n = s->size >> rsh;
    if (n > NT_MAX_REC) n = NT_MAX_REC;
    fs->nrec = n;
    return n ? GZ_OK : GZ_E_FORMAT;
}

static void ntfs_close(gz_archive *a)
{
    nt_fs *fs = (nt_fs *)a->priv;
    if (!fs) return;
    runs_free(&fs->mft);
    gz_free(fs);
    a->priv = 0;
}

#define NT_SCAN (1u << 20)

static int ntfs_open(gz_archive *a, gz_src *s, const gz_open_opts *oo, gz_ctx *c)
{
    (void)oo;
    u8 bs[512];
    int r = gz_src_read_exact(s, 0, bs, 512);
    if (r) return r;
    nt_fs *fs = (nt_fs *)gz_alloc(sizeof(nt_fs));
    if (!fs) return GZ_E_NOMEM;
    a->priv = fs;
    u64 mlcn, mirr;
    if (!boot_parse(bs, fs, &mlcn, &mirr)) return GZ_E_FORMAT;
    r = mft_init(fs, s, mlcn);
    if (r && r != GZ_E_NOMEM && mirr) r = mft_init(fs, s, mirr);
    if (r) return r;

    nt_open *o = (nt_open *)gz_alloc(sizeof(nt_open));
    if (!o) return GZ_E_NOMEM;
    o->a = a; o->s = s; o->c = c; o->fs = fs;
    o->budget = s->size + fs->nrec * fs->rs + (1u << 20);
    o->fidx = (i32 *)gz_alloc((size_t)fs->nrec * sizeof(i32));
    u32 per = NT_SCAN / fs->rs;
    u8 *buf = (u8 *)gz_alloc(NT_SCAN);
    if (!o->fidx || !buf) r = GZ_E_NOMEM;
    else __builtin_memset(o->fidx, 0xFF, (size_t)fs->nrec * sizeof(i32));
    for (u64 rn = 0; !r && rn < fs->nrec;) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        u32 cnt = fs->nrec - rn < per ? (u32)(fs->nrec - rn) : per;
        int bad = runs_read(fs, s, &fs->mft, rn * fs->rs, buf, cnt * fs->rs, 0);
        for (u32 i = 0; i < cnt && !r; i++, rn++) {
            u8 *b = buf + (size_t)i * fs->rs;
            if (bad ? rec_read(fs, s, rn, b) : rec_fix(fs, b)) continue;     /* unreadable / torn */
            if (!(rd16(b + 0x16) & 1) || rd64(b + 0x20)) continue;            /* free / extension */
            r = scan_file(o, rn, b);
            if (r == GZ_E_LIMIT) r = GZ_OK;                                    /* skip, keep going */
        }
        if (c && c->progress) c->progress(c->progress_user, rn, fs->nrec);
    }
    gz_free(buf);
    for (u32 i = 0; !r && i < o->nf; i++) r = intx_nonres(o, &o->f[i]);
    if (!r) r = build_entries(o);
    gz_free(o->fidx);
    gz_free(o->f);
    gz_free(o->nm);
    gz_free(o->st);
    gz_free(o->pool);
    gz_free(o->rp);
    gz_free(o);
    return r;
}

/* ---------------- extract / view ---------------- */

static int ntfs_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    const nt_fs *fs = (const nt_fs *)a->priv;
    const gz_entry *e = &a->e[idx];
    if (!e->is_dir && (e->method == NK_EFS || e->method == NK_UNSUP)) return GZ_E_METHOD;
    int r = out->open(out, idx);
    if (r) return r;
    if (e->is_dir || e->is_link || !e->usize) return out->close(out, idx, GZ_OK);
    int st;
    if (e->method == NK_WOF) {
        st = write_wof(fs, s, e->off, e->usize, e->aux32, out, c);
    } else {
        nt_data d;
        u32 nl = (u32)(e->aux >> 32);
        st = data_load(fs, s, e->off, nl ? a->raw + (u32)e->aux : 0, nl, &d);
        if (!st) {
            st = d.size != e->usize ? GZ_E_DATA : write_data(fs, s, &d, out, c);
            data_free(&d);
        }
    }
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static gz_src *ntfs_view(gz_archive *a, gz_src *s, u32 idx)
{
    const nt_fs *fs = (const nt_fs *)a->priv;
    const gz_entry *e = &a->e[idx];
    if (e->is_dir || e->is_link || (e->method != NK_RESIDENT && e->method != NK_PLAIN && e->method != NK_SPARSE))
        return 0;
    if (!e->usize) return gz_src_sub(s, 0, 0);
    nt_data d;
    u32 nl = (u32)(e->aux >> 32);
    if (data_load(fs, s, e->off, nl ? a->raw + (u32)e->aux : 0, nl, &d)) return 0;
    gz_src *v = 0;
    if (d.size == e->usize) data_src(fs, s, &d, &v);
    data_free(&d);
    return v;
}

static void ntfs_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    static const char *const wof[4] = { "XPRESS4K", "LZX", "XPRESS8K", "XPRESS16K" };
    (void)a;
    const char *m = "";
    switch (e->method) {
    case NK_SPARSE: m = "Sparse"; break;
    case NK_LZNT1:  m = "LZNT1"; break;
    case NK_WOF:    m = wof[e->aux32 & 3]; break;
    case NK_EFS:    m = "EFS"; break;
    case NK_UNSUP:  m = "Unsupported"; break;
    default: break;
    }
    u32 i = 0;
    for (; m[i] && i + 1 < cap; i++) buf[i] = m[i];
    if (cap) buf[i] = 0;
}

GZ_FORMAT(gz_fmt_ntfs)
const gz_format gz_fmt_ntfs = {
    "NTFS", "ntfs img", 0, ntfs_probe, ntfs_open, ntfs_close, ntfs_extract, 0, 0, ntfs_method, ntfs_view, 0
};

