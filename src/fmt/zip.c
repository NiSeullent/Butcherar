/*
 * 고깃ZIP - ZIP reader
 *   ZIP64, SFX/prefix data, data descriptors, NTFS/Unix timestamps,
 *   Info-ZIP Unicode Path (0x7075), WinZip AES (0x9901), ZipCrypto.
 *   Methods: Store, Deflate, Deflate64 (inflater fast path), Shrink (1),
 *   Reduce (2-5), Implode (6), BZip2 (12), LZMA (14), Zstd (93), XZ (95),
 *   PPMd var.I (98).
 *   Split / spanned sets: name.z01 .. name.zNN + name.zip (Info-ZIP zip -s,
 *   PKZIP, WinZip). Entries are located by (disk, offset); data may run across
 *   parts. Missing parts give GZ_E_VOLUME for the entries that need them.
 */
#include "arc.h"
#include "crc32.h"
#include "bzip2.h"
#include "implode.h"
#include "lzw.h"
#include "ppmd8.h"
#include "zstd.h"
#include "xz.h"

#define SIG_LOCAL   0x04034b50u
#define SIG_CENTRAL 0x02014b50u
#define SIG_EOCD    0x06054b50u
#define SIG_EOCD64  0x06064b50u
#define SIG_LOC64   0x07064b50u

#define ZIP_MAX_DISKS 65535u           /* 0xFFFF in the 16-bit field is the ZIP64 marker */

static int read_exact(gz_src *s, u64 off, void *buf, u32 n)
{
    return gz_src_read_exact(s, off, buf, n);
}

/* ---------------- split / spanned sets ---------------- */

/* a->vols[k] is the source of disk k (NULL for the disk the archive was opened
 * from, which extraction gets as its own source, and for missing parts) */
typedef struct zip_priv {
    u32 ndisks;              /* > 1: split set                                   */
    u32 self;                /* disk number of the opened file                   */
    u64 *size;               /* bytes of each disk (0 when missing)              */
    u64 *start;              /* position of each disk in the joined set          */
    u8 *have;                /* disk available                                   */
} zip_priv;

/* View of the joined parts from (disk d0, offset base) onwards. Ends at the end of
 * the set, or, when a later part is missing, reading into it gives GZ_E_VOLUME. */
typedef struct {
    gz_src s;
    const zip_priv *pv;
    gz_src *self;
    gz_src **vols;
    u32 d0, dl;              /* disks covered (all present)                       */
    int open_end;            /* a missing disk follows dl                         */
    u64 g0;                  /* joined position of offset 0                       */
} span_src;

static int span_read(gz_src *s, u64 off, void *buf, u32 n, u32 *got)
{
    span_src *v = (span_src *)s;
    const zip_priv *pv = v->pv;
    u8 *p = (u8 *)buf;
    *got = 0;
    if (off >= s->size) return GZ_OK;
    if (n > s->size - off) n = (u32)(s->size - off);
    u64 g = v->g0 + off, end = pv->start[v->dl] + pv->size[v->dl];
    if (g >= end) return v->open_end ? GZ_E_VOLUME : GZ_OK;
    u32 lo = v->d0, hi = v->dl;                     /* last disk starting at or before g */
    while (lo < hi) {
        u32 mid = lo + (hi - lo + 1) / 2;
        if (pv->start[mid] <= g) lo = mid; else hi = mid - 1;
    }
    for (u32 k = lo; n; k++) {
        if (k > v->dl) return v->open_end ? GZ_E_VOLUME : GZ_OK;
        u64 o = g - pv->start[k];
        if (o >= pv->size[k]) continue;
        u32 take = pv->size[k] - o < n ? (u32)(pv->size[k] - o) : n, gg = 0;
        gz_src *src = k == pv->self ? v->self : v->vols[k];
        int r = src->read_at(src, o, p, take, &gg);
        if (r) return r;
        *got += gg;
        if (gg < take) return GZ_OK;
        p += gg; g += gg; n -= gg;
    }
    return GZ_OK;
}

static void span_free(gz_src *s) { gz_free(s); }

/* view of len bytes (GZ_SIZE_UNKNOWN = up to the end) from (disk, off); NULL with
 * *err = GZ_E_VOLUME when that disk is missing */
static gz_src *span_new(gz_archive *a, gz_src *self, u32 disk, u64 off, u64 len, int *err)
{
    const zip_priv *pv = (const zip_priv *)a->priv;
    *err = GZ_E_FORMAT;
    if (disk >= pv->ndisks) return 0;
    *err = GZ_E_VOLUME;
    if (!pv->have[disk]) return 0;
    *err = GZ_E_NOMEM;
    span_src *v = (span_src *)gz_alloc(sizeof(span_src));
    if (!v) return 0;
    u32 dl = disk;
    while (dl + 1 < pv->ndisks && pv->have[dl + 1]) dl++;
    v->pv = pv;
    v->self = self;
    v->vols = a->vols;
    v->d0 = disk;
    v->dl = dl;
    v->open_end = dl + 1 < pv->ndisks;
    v->g0 = pv->start[disk] + off;
    u64 avail = pv->start[dl] + pv->size[dl];
    avail = avail > v->g0 ? avail - v->g0 : 0;
    if (v->open_end) avail = ~(u64)0 >> 1;          /* reading on reports the missing part */
    v->s.read_at = span_read;
    v->s.size = len < avail ? len : avail;
    v->s.free = span_free;
    return &v->s;
}

/* Source holding entry e and the local header offset in it. *src != s must be freed. */
static int entry_src(gz_archive *a, gz_src *s, const gz_entry *e, gz_src **src, u64 *lho)
{
    const zip_priv *pv = (const zip_priv *)a->priv;
    if (!pv || pv->ndisks <= 1) { *src = s; *lho = e->off; return GZ_OK; }
    int err;
    *src = span_new(a, s, e->aux32, e->off, GZ_SIZE_UNKNOWN, &err);
    *lho = 0;
    return *src ? GZ_OK : err;
}

static void zip_close(gz_archive *a)
{
    zip_priv *pv = (zip_priv *)a->priv;
    if (pv) {
        gz_free(pv->size);
        gz_free(pv->start);
        gz_free(pv->have);
        gz_free(pv);
    }
    a->priv = 0;
}

/* Part names: base + ".z01" .. for disks 0..n-2, base + ".zip" for the last one.
 * base = the file name without its extension; up = upper-case extension. */
static gzch *vol_name(const gzch *fn, size_t base, u32 disk, u32 ndisks, int up)
{
    gzch *nm = (gzch *)gz_alloc((base + 16) * sizeof(gzch));
    if (!nm) return 0;
    __builtin_memcpy(nm, fn, base * sizeof(gzch));
    size_t i = base;
    nm[i++] = '.';
    if (disk + 1 == ndisks) {
        nm[i++] = up ? 'Z' : 'z'; nm[i++] = up ? 'I' : 'i'; nm[i++] = up ? 'P' : 'p';
    } else {
        char d[12];
        u32 nd = 0, v = disk + 1;
        for (; v || nd < 2; v /= 10) d[nd++] = (char)('0' + v % 10);
        nm[i++] = up ? 'Z' : 'z';
        while (nd) nm[i++] = (gzch)d[--nd];
    }
    nm[i] = 0;
    return nm;
}

static int open_vol(const gz_open_opts *o, const gzch *fn, size_t base, u32 disk, u32 ndisks, int up, gz_src **out)
{
    *out = 0;
    for (int k = 0; k < 2 && !*out; k++) {          /* matching case first, then the other */
        gzch *nm = vol_name(fn, base, disk, ndisks, k ? !up : up);
        if (!nm) return GZ_E_NOMEM;
        gz_src *v = 0;
        if (!o->open_volume(o->user, nm, &v) && v) *out = v;
        gz_free(nm);
    }
    return GZ_OK;
}

/* length of the name without its extension, and whether the extension is upper case */
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

/* disk number of a ".z01".."z99999" name (1-based), 0 if not such a name */
static u32 zpart_number(const gzch *fn)
{
    int up;
    size_t n = gz_wcslen(fn), b = name_base(fn, &up);
    if (b + 3 > n || (fn[b + 1] | 0x20) != 'z') return 0;
    u32 v = 0;
    for (size_t i = b + 2; i < n; i++) {
        if (fn[i] < '0' || fn[i] > '9' || i - b > 7) return 0;
        v = v * 10 + (fn[i] - '0');
    }
    return v;
}

/* ---------------- central directory ---------------- */

static void parse_extra(gz_entry *e, const u8 *x, u32 xn, u32 *z64_need, const u8 **uni, u32 *unin,
                        u32 raw_crc)
{
    u32 i = 0;
    while (i + 4 <= xn) {
        u32 id = rd16(x + i), sz = rd16(x + i + 2);
        const u8 *d = x + i + 4;
        if (i + 4 + sz > xn) break;
        if (id == 0x0001) {                 /* ZIP64 */
            u32 p = 0;
            if ((*z64_need & 1) && p + 8 <= sz) { e->usize = rd64(d + p); p += 8; }
            if ((*z64_need & 2) && p + 8 <= sz) { e->csize = rd64(d + p); p += 8; }
            if ((*z64_need & 4) && p + 8 <= sz) { e->off = rd64(d + p); p += 8; }
            if ((*z64_need & 8) && p + 4 <= sz) { e->aux32 = rd32(d + p); p += 4; }
            *z64_need = 0;
        } else if (id == 0x000A && sz >= 32) {   /* NTFS */
            u32 p = 4;
            while (p + 4 <= sz) {
                u32 tag = rd16(d + p), tsz = rd16(d + p + 2);
                if (tag == 1 && tsz >= 24 && p + 4 + 24 <= sz) {
                    u64 mt = rd64(d + p + 4);
                    if (mt) { e->mtime = mt; e->mtime_kind = GZ_MT_FILETIME; }
                    break;
                }
                p += 4 + tsz;
            }
        } else if (id == 0x5455 && sz >= 5) {    /* extended timestamp */
            if ((d[0] & 1) && e->mtime_kind != GZ_MT_FILETIME) {
                i32 t = (i32)rd32(d + 1);
                e->mtime = gz_unix_to_filetime(t);
                e->mtime_kind = GZ_MT_FILETIME;
            }
        } else if (id == 0x7075 && sz >= 5) {    /* Info-ZIP Unicode Path */
            if (d[0] == 1 && rd32(d + 1) == raw_crc) { *uni = d + 5; *unin = sz - 5; }
        } else if (id == 0x9901 && sz >= 7) {    /* WinZip AES */
            e->aes_ver = (u8)rd16(d);
            e->aes_strength = d[4];
            e->aes_method = rd16(d + 5);
        }
        i += 4 + sz;
    }
}

/* Locate the End Of Central Directory in the last 64 KiB of m. buf receives the
 * tail; returns the record offset in buf or -1. */
static i64 find_eocd(gz_src *m, u8 **pbuf, u32 *ptail, u64 *ptail_off, int *err)
{
    u64 size = m->size;
    *pbuf = 0;
    *err = GZ_E_FORMAT;
    if (size < 22) return -1;
    u32 tail = size < 65557 + 20 ? (u32)size : 65557 + 20;
    u8 *buf = (u8 *)gz_alloc(tail);
    if (!buf) { *err = GZ_E_NOMEM; return -1; }
    u64 tail_off = size - tail;
    int r = read_exact(m, tail_off, buf, tail);
    if (r) { gz_free(buf); *err = r; return -1; }
    for (i64 p = (i64)tail - 22; p >= 0; p--) {
        if (rd32(buf + p) != SIG_EOCD) continue;
        u32 clen = rd16(buf + p + 20);
        if ((u64)p + 22 + clen > tail) continue;
        u64 cds = rd32(buf + p + 12), cdo = rd32(buf + p + 16);
        /* single-disk record: the directory must fit before it (offsets of a split
         * set are relative to other parts) */
        if (!rd16(buf + p + 4) && !rd16(buf + p + 6) && cds + (cdo == 0xffffffffu ? 0 : cdo) > tail_off + (u64)p &&
            cds != 0xffffffffu && cdo != 0xffffffffu) continue;
        *pbuf = buf;
        *ptail = tail;
        *ptail_off = tail_off;
        return p;
    }
    gz_free(buf);
    return -1;
}

/* Multi-disk set: open the other parts, fill a->priv / a->vols.
 * main: the source holding the EOCD (s itself, or the ".zip" opened for a ".zNN"). */
static int open_set(gz_archive *a, gz_src *s, gz_src *main, u32 ndisks, u32 self, const gz_open_opts *o)
{
    a->vols = (gz_src **)gz_alloc((size_t)ndisks * sizeof(gz_src *));
    if (!a->vols) { if (main != s) gz_src_free(main); return GZ_E_NOMEM; }
    a->nvols = ndisks;                               /* freed by the core from here on */
    if (main != s) a->vols[ndisks - 1] = main;
    zip_priv *pv = (zip_priv *)gz_alloc(sizeof(zip_priv));
    if (!pv) return GZ_E_NOMEM;
    a->priv = pv;
    pv->ndisks = ndisks;
    pv->self = self;
    pv->size = (u64 *)gz_alloc((size_t)ndisks * sizeof(u64));
    pv->start = (u64 *)gz_alloc((size_t)ndisks * sizeof(u64));
    pv->have = (u8 *)gz_alloc(ndisks);
    if (!pv->size || !pv->start || !pv->have) return GZ_E_NOMEM;
    int up = 0;
    size_t base = o && o->file_name ? name_base(o->file_name, &up) : 0;
    int can = o && o->file_name && o->open_volume && !a->parent;
    for (u32 k = 0; k < ndisks; k++) {
        if (k == self || a->vols[k]) continue;
        if (!can) continue;
        int r = open_vol(o, o->file_name, base, k, ndisks, up, &a->vols[k]);
        if (r) return r;
    }
    u64 pos = 0;
    for (u32 k = 0; k < ndisks; k++) {
        gz_src *v = k == self ? s : a->vols[k];
        pv->have[k] = v != 0;
        pv->size[k] = v ? v->size : 0;
        pv->start[k] = pos;
        pos += pv->size[k];
    }
    return GZ_OK;
}

static int zip_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)c;
    u8 *buf;
    u32 tail;
    u64 tail_off;
    int err;
    gz_src *main = s;
    u32 zpart = 0;
    i64 eocd = find_eocd(s, &buf, &tail, &tail_off, &err);
    if (eocd < 0) {
        if (err != GZ_E_FORMAT) return err;
        /* opened at a part of a split set ("name.z01"): the directory is in "name.zip" */
        if (!o || !o->file_name || !o->open_volume || a->parent || !(zpart = zpart_number(o->file_name)))
            return GZ_E_FORMAT;
        int up;
        size_t base = name_base(o->file_name, &up);
        if ((err = open_vol(o, o->file_name, base, 0, 1, up, &main))) return err;
        if (!main) return GZ_E_VOLUME;
        eocd = find_eocd(main, &buf, &tail, &tail_off, &err);
        if (eocd < 0) { gz_src_free(main); return err; }
    }

    const u8 *E = buf + eocd;
    u64 eocd_pos = tail_off + (u64)eocd;
    u32 disk = rd16(E + 4), cd_disk = rd16(E + 6);
    u64 count = rd16(E + 10);
    u64 cd_size = rd32(E + 12), cd_off = rd32(E + 16);
    u32 clen = rd16(E + 20);
    u64 cd_end = eocd_pos;            /* where the central directory should end */
    u32 ndisks = disk + 1;

    /* ZIP64 locator directly before EOCD */
    int loc = eocd >= 20 && rd32(E - 20) == SIG_LOC64;
    u32 loc_disk = 0;
    u64 z64off = 0;
    if (loc) {
        loc_disk = rd32(E - 20 + 4);
        z64off = rd64(E - 20 + 8);
        u32 total = rd32(E - 20 + 16);
        if (total > 1 || disk == 0xFFFFu) ndisks = total ? total : 1;
    }
    if (clen) {
        a->comment_raw = (u8 *)gz_alloc(clen);
        if (a->comment_raw) { __builtin_memcpy(a->comment_raw, E + 22, clen); a->comment_len = clen; }
    }
    gz_free(buf);
    if (ndisks > ZIP_MAX_DISKS) { if (main != s) gz_src_free(main); return GZ_E_LIMIT; }
    if (zpart && (ndisks < 2 || zpart >= ndisks)) { gz_src_free(main); return GZ_E_FORMAT; }

    u64 shift = 0;
    u8 *cd = 0;
    int r;
    if (ndisks <= 1) {
        if (loc) {
            u64 loc_pos = eocd_pos - 20;
            u8 z[56];
            int ok = 0;
            if (z64off + 56 <= loc_pos && !read_exact(s, z64off, z, 56) && rd32(z) == SIG_EOCD64) ok = 1;
            if (!ok && loc_pos >= 56 && !read_exact(s, loc_pos - 56, z, 56) && rd32(z) == SIG_EOCD64) {
                z64off = loc_pos - 56; ok = 1;
            }
            if (ok) {
                disk = rd32(z + 16); cd_disk = rd32(z + 20);
                count = rd64(z + 32);
                cd_size = rd64(z + 40);
                cd_off = rd64(z + 48);
                cd_end = z64off;
            }
        }
        if (disk != 0 || cd_disk != 0) return GZ_E_FORMAT;
        if (cd_size > cd_end) return GZ_E_FORMAT;
        /* SFX / prefixed data: the real offsets are shifted */
        if (cd_end - cd_size >= cd_off) shift = (cd_end - cd_size) - cd_off;
        else return GZ_E_FORMAT;
        a->sfx_shift = shift;
        if (cd_size > (1u << 30)) return GZ_E_NOMEM;
        cd = (u8 *)gz_alloc((size_t)cd_size + 8);
        if (!cd && cd_size) return GZ_E_NOMEM;
        r = cd_size ? read_exact(s, cd_off + shift, cd, (u32)cd_size) : GZ_OK;
        if (r) { gz_free(cd); return r; }
    } else {
        /* split set: offsets are relative to the start of their disk */
        if ((r = open_set(a, s, main, ndisks, zpart ? zpart - 1 : ndisks - 1, o))) return r;
        gz_src *v;
        if (loc) {
            u8 z[56];
            v = span_new(a, s, loc_disk, z64off, 56, &err);
            if (v && !read_exact(v, 0, z, 56) && rd32(z) == SIG_EOCD64) {
                cd_disk = rd32(z + 20);
                count = rd64(z + 32);
                cd_size = rd64(z + 40);
                cd_off = rd64(z + 48);
            }
            gz_src_free(v);
        }
        if (cd_size > (1u << 30)) return GZ_E_NOMEM;
        if (!(v = span_new(a, s, cd_disk, cd_off, cd_size, &err))) return err;
        cd = (u8 *)gz_alloc((size_t)cd_size + 8);
        r = !cd ? GZ_E_NOMEM : cd_size ? read_exact(v, 0, cd, (u32)cd_size) : GZ_OK;
        gz_src_free(v);
        if (r) { gz_free(cd); return r == GZ_E_TRUNC ? GZ_E_FORMAT : r; }
    }

    a->win_names = 1;
    if (count < (1u << 24) && count > 0) {
        a->e = (gz_entry *)gz_alloc((size_t)count * sizeof(gz_entry));
        if (a->e) a->cap = (u32)count;
    }
    a->raw = 0;
    size_t p = 0;
    while (p + 46 <= cd_size) {
        const u8 *c = cd + p;
        if (rd32(c) != SIG_CENTRAL) break;
        u32 nlen = rd16(c + 28), xlen = rd16(c + 30), cmlen = rd16(c + 32);
        if (p + 46 + nlen + xlen + cmlen > cd_size) break;
        gz_entry *e;
        if (gz_arc_add_entry(a, &e)) { gz_free(cd); return GZ_E_NOMEM; }
        u32 made = rd16(c + 4) >> 8;
        e->flags = rd16(c + 8);
        e->method = rd16(c + 10);
        e->dos_time = rd16(c + 12);
        e->mtime = ((u64)rd16(c + 14) << 16) | rd16(c + 12);
        e->mtime_kind = GZ_MT_DOS;
        e->crc = rd32(c + 16);
        e->csize = rd32(c + 20);
        e->usize = rd32(c + 24);
        u32 dstart = rd16(c + 34);
        u32 ext = rd32(c + 38);
        e->off = rd32(c + 42);
        e->name_enc = (e->flags & 0x800) ? GZ_NE_UTF8 : GZ_NE_LEGACY;
        e->has_crc = 1;
        const u8 *name = c + 46;
        e->raw_len = (u16)nlen;
        e->raw_off = (u32)(name - cd);       /* temporarily relative to cd */

        u32 need = 0;
        if (e->usize == 0xffffffffu) need |= 1;
        if (e->csize == 0xffffffffu) need |= 2;
        if (e->off == 0xffffffffu) need |= 4;
        e->aux32 = dstart;
        if (dstart == 0xffffu) need |= 8;
        const u8 *uni = 0;
        u32 unin = 0;
        u32 raw_crc = gz_crc32(0, name, nlen);
        parse_extra(e, name + nlen, xlen, &need, &uni, &unin, raw_crc);
        if (uni && unin) {
            e->uni_off = (u32)(uni - cd);
            e->uni_len = (u16)unin;
        }
        if (ndisks <= 1) e->aux32 = 0;       /* disk numbers only matter for split sets */
        e->off += shift;

        if (e->flags & 1) {
            e->enc = (e->method == 99) ? GZ_ENC_AES : GZ_ENC_ZIPCRYPTO;
            if (e->flags & 0x40) e->enc = GZ_ENC_AES;     /* strong encryption: unsupported */
        }
        if (e->method == 99 && !e->aes_strength) e->aes_strength = 3;
        if (e->enc == GZ_ENC_AES && e->aes_ver == 2 && e->crc == 0) e->has_crc = 0;

        /* attributes / directory */
        if (made == 3 || made == 19) {               /* Unix / OS X */
            u32 mode = ext >> 16;
            if ((mode & 0xF000) == 0x4000) e->is_dir = 1;
            if ((mode & 0xF000) == 0xA000) e->is_link = 1;
            e->unix_mode = mode;
            if (mode && !(mode & 0200)) e->attr |= 1;
            if (ext & 0x10) e->is_dir = 1;
        } else {
            e->attr = ext & 0x27;                    /* RO, hidden, system, archive */
            if (ext & 0x10) e->is_dir = 1;
        }
        if (nlen && (name[nlen - 1] == '/' || name[nlen - 1] == '\\')) e->is_dir = 1;
        if (e->is_dir) e->attr |= 0x10;
        p += 46 + nlen + xlen + cmlen;
    }
    /* move name storage into a->raw (the whole central directory) */
    a->raw = cd;
    a->raw_len = (size_t)cd_size;
    a->raw_cap = (size_t)cd_size + 8;
    if (a->n == 0 && count != 0) return GZ_E_FORMAT;
    return GZ_OK;
}

/* ---------------- entry data ---------------- */

typedef struct {
    gz_src *src;
    u64 pos, end;
    u64 start;               /* first byte of the compressed data (after encryption headers) */
    int enc;
    gz_zipcrypto zc;
    gz_aes_ctr *aes;
    gz_hmac_sha1 *hmac;
    gz_out *out;
    u64 written, limit;
    int do_crc;              /* non-inflater methods: CRC the output here */
    u32 crc;
} ent_reader;

static int er_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    ent_reader *r = (ent_reader *)ctx;
    u64 left = r->end - r->pos;
    *got = 0;
    if (!left) return GZ_OK;
    u32 n = cap;
    if (n > left) n = (u32)left;
    u32 g = 0;
    int e = r->src->read_at(r->src, r->pos, buf, n, &g);
    if (e) return e;
    if (!g) return GZ_E_TRUNC;
    r->pos += g;
    if (r->enc == GZ_ENC_ZIPCRYPTO) gz_zc_decrypt(&r->zc, buf, g);
    else if (r->enc == GZ_ENC_AES) {
        gz_hmac_update(r->hmac, buf, g);
        gz_aes_ctr_kernel(r->aes, buf, g);
    }
    *got = g;
    return GZ_OK;
}

static int er_write(void *ctx, const u8 *p, size_t n)
{
    ent_reader *r = (ent_reader *)ctx;
    if (n > r->limit - r->written) return GZ_E_DATA;      /* more data than declared */
    r->written += n;
    if (r->do_crc) r->crc = gz_crc32(r->crc, p, n);
    return r->out->write(r->out, p, n);
}

typedef struct {
    gz_aes_ctr aes;
    gz_hmac_sha1 hmac;
} aes_ctx;

/* Locate data (local header at lho in s), verify password. On success fills reader (pos/end/enc). */
static int prepare(gz_src *s, u64 lho, gz_entry *e, const u8 *pw, size_t pwn, ent_reader *rd, aes_ctx *ac)
{
    u8 lh[30];
    int r = read_exact(s, lho, lh, 30);
    if (r) return r;
    if (rd32(lh) != SIG_LOCAL) return GZ_E_FORMAT;
    u64 data = lho + 30 + rd16(lh + 26) + rd16(lh + 28);
    rd->src = s;
    rd->pos = data;
    rd->end = data + e->csize;
    rd->enc = GZ_ENC_NONE;
    if (e->csize > s->size || rd->end > s->size) return GZ_E_TRUNC;

    if (e->enc == GZ_ENC_ZIPCRYPTO) {
        if (!pw) return GZ_E_PASSWORD;
        if (e->csize < 12) return GZ_E_DATA;
        u8 h[12];
        r = read_exact(s, data, h, 12);
        if (r) return r;
        gz_zc_init(&rd->zc, pw, pwn);
        gz_zc_decrypt(&rd->zc, h, 12);
        u8 check = (e->flags & 8) ? (u8)(e->dos_time >> 8) : (u8)(e->crc >> 24);
        if (h[11] != check) return GZ_E_PASSWORD;
        rd->pos += 12;
        rd->enc = GZ_ENC_ZIPCRYPTO;
    } else if (e->enc == GZ_ENC_AES) {
        if (e->flags & 0x40) return GZ_E_METHOD;
        if (!pw) return GZ_E_PASSWORD;
        u32 st = e->aes_strength;
        if (st < 1 || st > 3) return GZ_E_METHOD;
        u32 keylen = 8 + 8 * st, saltlen = keylen / 2;
        if (e->csize < saltlen + 2 + 10) return GZ_E_DATA;
        u8 hs[18], dk[66];
        r = read_exact(s, data, hs, saltlen + 2);
        if (r) return r;
        gz_pbkdf2_sha1(pw, pwn, hs, saltlen, 1000, dk, 2 * keylen + 2);
        if (dk[2 * keylen] != hs[saltlen] || dk[2 * keylen + 1] != hs[saltlen + 1])
            return GZ_E_PASSWORD;
        gz_aes_ctr_setup(&ac->aes, dk, (int)keylen);
        gz_hmac_init(&ac->hmac, dk + keylen, keylen);
        rd->aes = &ac->aes;
        rd->hmac = &ac->hmac;
        rd->pos += saltlen + 2;
        rd->end -= 10;
        rd->enc = GZ_ENC_AES;
    }
    rd->start = rd->pos;
    return GZ_OK;
}

static int prepare_entry(gz_archive *a, gz_src *s, gz_entry *e, const u8 *pw, size_t pwn, ent_reader *rd, aes_ctx *ac)
{
    gz_src *src;
    u64 lho;
    int r = entry_src(a, s, e, &src, &lho);
    if (r) return r;
    r = prepare(src, lho, e, pw, pwn, rd, ac);
    if (src != s) gz_src_free(src);
    return r;
}

/* Password byte encodings to try: the system code page (what WinZip/PKZIP/Explorer
 * use for ZipCrypto) and UTF-8 (7-Zip/Bandizip for AES and Unicode passwords). */
typedef struct { u8 b[2][1024]; size_t n[2]; int count; } pw_set;

static void pw_candidates(gz_ctx *c, pw_set *ps)
{
    ps->count = 0;
    if (!c->password) return;
    size_t wn = gz_wcslen(c->password);
    if (wn > 300) wn = 300;
    int an = gz_plat_wc2mb(gz_plat_acp(), c->password, (int)wn, ps->b[0], sizeof ps->b[0]);
    if (an > 0 || wn == 0) { ps->n[ps->count] = (size_t)(an > 0 ? an : 0); ps->count++; }
    int un = gz_utf16_to_utf8(c->password, wn, ps->b[ps->count]);
    if (ps->count == 0 || (size_t)un != ps->n[0] || __builtin_memcmp(ps->b[0], ps->b[ps->count], (size_t)un)) {
        ps->n[ps->count] = (size_t)un;
        ps->count++;
    }
}

static int zip_check_password(gz_archive *a, gz_src *s, u32 idx, gz_ctx *c)
{
    gz_entry *e = &a->e[idx];
    if (!e->enc || e->is_dir) return GZ_OK;
    pw_set *ps = (pw_set *)gz_alloc(sizeof(pw_set));
    aes_ctx *ac = (aes_ctx *)gz_alloc(sizeof(aes_ctx));
    if (!ps || !ac) { gz_free(ps); gz_free(ac); return GZ_E_NOMEM; }
    pw_candidates(c, ps);
    int r = GZ_E_PASSWORD;
    if (!ps->count) r = prepare_entry(a, s, e, 0, 0, &(ent_reader){0}, ac);
    for (int k = 0; k < ps->count; k++) {
        ent_reader rd;
        __builtin_memset(&rd, 0, sizeof rd);
        r = prepare_entry(a, s, e, ps->b[k], ps->n[k], &rd, ac);
        if (r != GZ_E_PASSWORD) break;
    }
    gz_free(ps);
    gz_free(ac);
    return r;
}

/* ---------------- Reduce (methods 2-5, PKZIP 0.9x) ----------------
 * APPNOTE 5.2: a byte stream coded with "follower sets" (per previous byte up
 * to 63 likely successors, an index of B(N) bits or a flagged literal) that
 * carries DLE (0x90) escaped LZ77 copies: DLE 0 = literal 0x90, DLE V [X] Y =
 * copy L(V) (+ X when L(V) is all ones) + 3 bytes from distance
 * (V >> (8 - factor)) * 256 + Y + 1; bytes before the start read as zeros.
 * Bits are LSB first; B(N) as in Info-ZIP's table (at least one bit). */

#define RED_HIST 4096u                   /* largest distance: 15 * 256 + 256 */
#define RED_BUF  (64u << 10)

typedef struct {
    const gz_stream_io *io;
    u32 ip, in_n;
    u32 nb;
    u64 bits;
    u8 fset[256][64];
    u8 fn[256];
    u8 in[4096];
    u8 win[RED_HIST + RED_BUF];
} red_state;

static int red_bits(red_state *r, u32 n, u32 *v)
{
    while (r->nb < n) {
        if (r->ip == r->in_n) {
            r->ip = r->in_n = 0;
            int e = r->io->read(r->io->ctx, r->in, sizeof r->in, &r->in_n);
            if (e) return e;
            if (!r->in_n) return GZ_E_TRUNC;
        }
        r->bits |= (u64)r->in[r->ip++] << r->nb;
        r->nb += 8;
    }
    *v = (u32)r->bits & ((1u << n) - 1);
    r->bits >>= n;
    r->nb -= n;
    return GZ_OK;
}

static int reduce_decode(const gz_stream_io *io, u64 out_size, u32 factor)
{
    red_state *r = (red_state *)gz_alloc(sizeof(red_state));
    if (!r) return GZ_E_NOMEM;
    r->io = io;
    u32 v, err = GZ_OK, mask = 0x7Fu >> (factor - 1);
    for (int j = 255; j >= 0 && !err; j--) {
        if ((err = red_bits(r, 6, &v))) break;
        r->fn[j] = (u8)v;
        for (u32 i = 0; i < r->fn[j] && !err; i++) {
            err = red_bits(r, 8, &v);
            r->fset[j][i] = (u8)v;
        }
    }
    u8 *w = r->win;
    u32 pos = RED_HIST, state = 0, last = 0, len = 0, V = 0;
    u64 left = out_size;
    while (!err && left) {
        u32 c, n = r->fn[last];
        if (!n || ((err = red_bits(r, 1, &c)) == GZ_OK && c)) {
            if (!err) err = red_bits(r, 8, &c);
        } else if (!err) {
            u32 b = n <= 2 ? 1 : 32 - (u32)__builtin_clz(n - 1);
            if (!(err = red_bits(r, b, &c))) c = r->fset[last][c];
        }
        if (err) break;
        last = c;
        u32 copy = 0, dist = 0;
        switch (state) {
        case 0:
            if (c != 0x90) { w[pos++] = (u8)c; left--; }
            else state = 1;
            break;
        case 1:
            if (c) { V = c; len = c & mask; state = len == mask ? 2 : 3; }
            else { w[pos++] = 0x90; left--; state = 0; }
            break;
        case 2:
            len += c;
            state = 3;
            break;
        default:
            dist = (V >> (8 - factor)) * 256 + c + 1;
            copy = len + 3;
            state = 0;
            break;
        }
        while (copy || pos == RED_HIST + RED_BUF) {
            if (pos == RED_HIST + RED_BUF) {             /* flush, keep the history */
                if ((err = io->write(io->ctx, w + RED_HIST, RED_BUF))) break;
                __builtin_memcpy(w, w + RED_BUF, RED_HIST);
                pos = RED_HIST;
            }
            u32 k = copy;
            if (k > RED_HIST + RED_BUF - pos) k = RED_HIST + RED_BUF - pos;
            if (k > left) k = (u32)left;
            for (u32 i = 0; i < k; i++, pos++) w[pos] = w[pos - dist];
            left -= k;
            copy = left ? copy - k : 0;
        }
    }
    if (!err && pos > RED_HIST) err = io->write(io->ctx, w + RED_HIST, pos - RED_HIST);
    gz_free(r);
    return (int)err;
}

/* ---------------- methods other than Store / Deflate / Deflate64 ---------------- */

static void *bz_create(void) { return gz_bzip2_dec_new(); }
static void bz_destroy(void *p) { gz_bzip2_dec_free((gz_bzip2_dec *)p); }
static void *zs_create(void) { return gz_zstd_dec_new(); }
static void zs_destroy(void *p) { gz_zstd_dec_free((gz_zstd_dec *)p); }

static int method_supported(u32 m)
{
    switch (m) {
    case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 8: case 9: case 12: case 14: case 93: case 95: case 98:
        return 1;
    }
    return 0;
}

static int read_full(ent_reader *rd, u8 *buf, u32 n)
{
    while (n) {
        u32 got = 0;
        int r = er_read(rd, buf, n, &got);
        if (r) return r;
        if (!got) return GZ_E_TRUNC;
        buf += got;
        n -= got;
    }
    return GZ_OK;
}

/* Decode entry data of method m with the output CRC'ed in er_write. */
static int decode_other(u32 m, const gz_entry *e, ent_reader *rd, gz_ctx *c)
{
    gz_stream_io io = { er_read, er_write, rd };
    u64 used = 0;
    int r;
    rd->do_crc = 1;
    switch (m) {
    case 1: {                                        /* Shrink */
        gz_lzw_dec *d = (gz_lzw_dec *)gz_ctx_slot(c, GZ_SLOT_MISC3, gz_lzw_slot_new, gz_lzw_slot_free);
        return d ? gz_shrink_decode(d, &io, e->usize) : GZ_E_NOMEM;
    }
    case 2: case 3: case 4: case 5:                  /* Reduce with compression factor 1..4 */
        return reduce_decode(&io, e->usize, m - 1);
    case 6: {                                        /* Implode: flags bit 1 8K window, bit 2 three trees */
        gz_implode_dec *d = (gz_implode_dec *)gz_ctx_slot(c, GZ_SLOT_MISC2, gz_implode_slot_new, gz_implode_slot_free);
        return d ? gz_implode_decode(d, &io, e->usize, (e->flags & 2) != 0, (e->flags & 4) != 0) : GZ_E_NOMEM;
    }
    case 12: {
        gz_bzip2_dec *d = (gz_bzip2_dec *)gz_ctx_slot(c, GZ_SLOT_BZIP2, bz_create, bz_destroy);
        return d ? gz_bzip2_decode(d, &io, e->usize, 1, 0) : GZ_E_NOMEM;
    }
    case 14: {                                       /* version (2), props size (2), props (5) */
        gz_lzma_dec *d = gz_xz_lzma_dec(c);
        if (!d) return GZ_E_NOMEM;
        u8 h[9];
        if ((r = read_full(rd, h, 4))) return r == GZ_E_TRUNC ? GZ_E_DATA : r;
        if (rd16(h + 2) != 5) return GZ_E_DATA;
        if ((r = read_full(rd, h + 4, 5))) return r == GZ_E_TRUNC ? GZ_E_DATA : r;
        return gz_lzma_decode(d, h + 4, &io, e->usize, 0);
    }
    case 93: {
        gz_zstd_dec *d = (gz_zstd_dec *)gz_ctx_slot(c, GZ_SLOT_ZSTD, zs_create, zs_destroy);
        return d ? gz_zstd_decode_ex(d, &io, e->usize, 0, 0) : GZ_E_NOMEM;
    }
    case 95: {
        gz_stream_io in = { er_read, 0, rd };
        return gz_xz_decode_io(&in, er_write, rd, c);
    }
    case 98: {
        gz_ppmd_cache *pc = (gz_ppmd_cache *)gz_ctx_slot(c, GZ_SLOT_PPMD, gz_ppmd_cache_new, gz_ppmd_cache_free);
        gz_ppmd8 *p = pc ? gz_ppmd_cache_8(pc) : 0;
        if (!p) return GZ_E_NOMEM;
        r = gz_ppmd8_zip_decode_ex(p, &io, e->usize, &used);
        if (!r && used != rd->end - rd->start) r = GZ_E_DATA;   /* all packed data must be used (as 7-Zip) */
        return r;
    }
    }
    return GZ_E_METHOD;
}

static int extract_once(gz_archive *a, gz_src *s, u32 idx, gz_out *out, const u8 *pw, size_t pwn,
                        gz_ctx *c, int *opened)
{
    gz_entry *e = &a->e[idx];
    u16 m = e->method == 99 ? e->aes_method : e->method;
    if (!method_supported(m)) return GZ_E_METHOD;
    int fast = m == 0 || m == 8 || m == 9;
    gz_inflater *z = 0;
    if (fast && !(z = gz_ctx_inflater(c))) return GZ_E_NOMEM;

    gz_src *src;
    u64 lho;
    int r = entry_src(a, s, e, &src, &lho);
    if (r) return r;
    ent_reader rd;
    __builtin_memset(&rd, 0, sizeof rd);
    aes_ctx *ac = 0;
    if (e->enc == GZ_ENC_AES && !(ac = (aes_ctx *)gz_alloc(sizeof(aes_ctx)))) r = GZ_E_NOMEM;
    if (!r) r = prepare(src, lho, e, pw, pwn, &rd, ac);
    if (!r) r = out->open(out, idx);
    if (r) {
        gz_free(ac);
        if (src != s) gz_src_free(src);
        return r;
    }
    *opened = 1;
    rd.out = out;
    rd.limit = e->usize;
    gz_stream_io io = { er_read, er_write, &rd };
    int st;
    u64 total;
    u32 crc;
    if (fast) {
        st = m == 0 ? gz_store_run(z, &io) : gz_inflate_run(z, &io, m == 9);
        total = z->total_out;
        crc = z->crc;
    } else {
        st = decode_other(m, e, &rd, c);
        total = rd.written;
        crc = rd.crc;
    }

    if (!st && total != e->usize) st = GZ_E_DATA;
    if (!st && e->has_crc && crc != e->crc)
        st = (e->enc == GZ_ENC_ZIPCRYPTO) ? GZ_E_PASSWORD : GZ_E_CRC;
    if (!st && e->enc == GZ_ENC_AES) {
        u8 code[10], mac[20];
        int rr = read_exact(src, rd.end, code, 10);
        if (rr) st = rr;
        else {
            /* the reader may stop early when the decoder ends: hash the rest */
            u8 tmp[4096];
            while (rd.pos < rd.end) {
                u32 n = (u32)((rd.end - rd.pos) < sizeof tmp ? (rd.end - rd.pos) : sizeof tmp);
                if (read_exact(src, rd.pos, tmp, n)) break;
                gz_hmac_update(&ac->hmac, tmp, n);
                rd.pos += n;
            }
            gz_hmac_final(&ac->hmac, mac);
            if (__builtin_memcmp(code, mac, 10)) st = GZ_E_AUTH;
        }
    }
    gz_free(ac);
    if (src != s) gz_src_free(src);
    return st;
}

static int null_open(gz_out *o, u32 idx) { (void)o; (void)idx; return GZ_OK; }
static int null_write(gz_out *o, const u8 *p, size_t n) { (void)o; (void)p; (void)n; return GZ_OK; }
static int null_close(gz_out *o, u32 idx, int st) { (void)o; (void)idx; (void)st; return GZ_OK; }

static int zip_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    gz_entry *e = &a->e[idx];
    if (e->is_dir) {
        int r = out->open(out, idx);
        if (r) return r;
        return out->close(out, idx, GZ_OK);
    }
    const u8 *pw = 0;
    size_t pwn = 0;
    pw_set *ps = 0;
    if (e->enc) {
        ps = (pw_set *)gz_alloc(sizeof(pw_set));
        aes_ctx *ac = (aes_ctx *)gz_alloc(sizeof(aes_ctx));
        if (!ps || !ac) { gz_free(ps); gz_free(ac); return GZ_E_NOMEM; }
        pw_candidates(c, ps);
        /* encodings that pass the header check */
        int pass[2], np = 0, err = GZ_E_PASSWORD;
        for (int k = 0; k < ps->count; k++) {
            ent_reader rd;
            __builtin_memset(&rd, 0, sizeof rd);
            int r = prepare_entry(a, s, e, ps->b[k], ps->n[k], &rd, ac);
            if (!r) pass[np++] = k;
            else if (r != GZ_E_PASSWORD) err = r;
        }
        gz_free(ac);
        if (!np) { gz_free(ps); return err; }
        int pick = pass[0];
        if (np > 1) {
            /* both pass the 1-byte ZipCrypto check: find the one with the right CRC */
            gz_out nul = { null_open, null_write, null_close, 0 };
            for (int k = 0; k < np; k++) {
                int op = 0;
                if (!extract_once(a, s, idx, &nul, ps->b[pass[k]], ps->n[pass[k]], c, &op)) { pick = pass[k]; break; }
            }
        }
        pw = ps->b[pick];
        pwn = ps->n[pick];
    }
    int opened = 0;
    int st = extract_once(a, s, idx, out, pw, pwn, c, &opened);
    gz_free(ps);
    if (!opened) return st;
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static void zip_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    u16 m = e->method == 99 ? e->aes_method : e->method;
    const char *n = "?";
    switch (m) {
    case 0: n = "Store"; break;
    case 1: n = "Shrink"; break;
    case 2: case 3: case 4: case 5: n = "Reduce"; break;
    case 6: n = "Implode"; break;
    case 8: n = "Deflate"; break;
    case 9: n = "Deflate64"; break;
    case 12: n = "BZip2"; break;
    case 14: n = "LZMA"; break;
    case 93: n = "Zstd"; break;
    case 95: n = "XZ"; break;
    case 96: n = "JPEG"; break;
    case 97: n = "WavPack"; break;
    case 98: n = "PPMd"; break;
    }
    const char *enc = e->enc == GZ_ENC_AES ? (e->aes_strength == 1 ? " AES-128" : e->aes_strength == 2 ? " AES-192" : " AES-256")
                    : e->enc == GZ_ENC_ZIPCRYPTO ? " ZipCrypto" : "";
    u32 i = 0;
    for (; *n && i + 1 < cap; n++) buf[i++] = *n;
    for (; *enc && i + 1 < cap; enc++) buf[i++] = *enc;
    if (cap) buf[i] = 0;
}

/* stored, unencrypted entries can be read in place */
static gz_src *zip_view(gz_archive *a, gz_src *s, u32 idx)
{
    gz_entry *e = &a->e[idx];
    if (e->is_dir || e->enc || e->method != 0) return 0;
    gz_src *src;
    u64 lho;
    if (entry_src(a, s, e, &src, &lho)) return 0;
    u8 lh[30];
    gz_src *v = 0;
    if (!read_exact(src, lho, lh, 30) && rd32(lh) == SIG_LOCAL) {
        u64 data = lho + 30 + rd16(lh + 26) + rd16(lh + 28);
        if (src == s) {
            if (e->usize <= s->size && data <= s->size - e->usize) v = gz_src_sub(s, data, e->usize);
        } else {
            /* split set: a view that runs across the parts */
            span_src *sp = (span_src *)src;
            int err;
            v = span_new(a, s, sp->d0, e->off + data, e->usize, &err);
            if (v && v->size != e->usize) { gz_src_free(v); v = 0; }
        }
    }
    if (src != s) gz_src_free(src);
    return v;
}

static int zip_probe(gz_src *s, const u8 *h, u32 n)
{
    if (n >= 4 && h[0] == 'P' && h[1] == 'K' && (h[2] == 3 || h[2] == 5 || h[2] == 7) && h[3] == h[2] + 1)
        return 95;
    if (n >= 8 && rd32(h) == 0x30304b50u && rd32(h + 4) == SIG_LOCAL) return 95;   /* "PK00" spanned marker */
    /* SFX or data before the archive: look for the end record */
    if (s->size < 22) return 0;
    u32 tail = s->size < 65557 ? (u32)s->size : 65557;
    u8 *buf = (u8 *)gz_alloc(tail);
    if (!buf) return 0;
    int score = 0;
    if (!read_exact(s, s->size - tail, buf, tail)) {
        for (i64 p = (i64)tail - 22; p >= 0; p--) {
            if (rd32(buf + p) == SIG_EOCD && (u64)p + 22 + rd16(buf + p + 20) <= tail) { score = 40; break; }
        }
    }
    gz_free(buf);
    return score;
}

GZ_FORMAT(gz_fmt_zip)
const gz_format gz_fmt_zip = {
    "ZIP", "zip zipx jar war ear apk xpi odt ods odp docx xlsx pptx epub ipa appx nupkg whl z01",
    0, zip_probe, zip_open, zip_close, zip_extract, 0, zip_check_password, zip_method, zip_view, 0
};
