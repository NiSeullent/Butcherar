/*
 * 고깃ZIP - UDF reader (ECMA-167 / OSTA UDF 1.02 - 2.60)
 *
 *   Anchor at sector 256, N-256 or N-1 (sector sizes 512 - 4096), main and reserve
 *   volume descriptor sequences (with descriptor pointers), partition descriptors,
 *   logical volume with partition maps: type 1, sparable (sparing tables), virtual
 *   (VAT 1.50 and 2.00+) and the metadata partition of UDF 2.50+ (mirror fallback).
 *   File set descriptor, ICB strategy 4 and 4096 (indirect entries), file entries
 *   and extended file entries, short / long / extended / embedded allocation
 *   descriptors with allocation extent chains, unrecorded and sparse extents (zeros),
 *   files > 4 GiB, CS0 8/16-bit names, hidden / deleted / parent FIDs, symlinks
 *   (path components), permissions and times.
 *
 * Every byte of file data is resolved to image offsets at open time, so extraction is
 * a plain copy of runs (see isoudf.h). Tag checksums are required, CRCs are only used
 * to prefer the intact copy of the anchor and of the metadata file.
 *
 * Hostile input: directory ICBs are visited once, depth / path / entry counts, ICB and
 * allocation extent chains, partition mapping depth and the total amount of directory
 * data are bounded; tables (VAT, sparing, directories) have size caps.
 */
#include "arc.h"
#include "isoudf.h"

#define MAX_PARTS  8u
#define MAX_MAPS   8u
#define MAX_DEPTH  256u
#define MAX_PATH   16384u              /* raw UTF-16LE path bytes                 */
#define MAX_DIR    (64u << 20)         /* one directory's FIDs                     */
#define MAX_ENTRIES (1u << 24)
#define MAX_AED    4096u               /* allocation extent descriptors per entry  */
#define MAX_ICB_HOPS 16u
#define MAX_VAT    (16u << 20)         /* VAT entries (64 MiB)                     */
#define MAX_SPARE  (1u << 16)          /* sparing table entries                    */
#define MAX_LINK   4096u

enum { F_MULTI = 1, F_BAD = 2 };       /* gz_entry.flags */
enum { PM_NONE = 0, PM_PHYS, PM_SPAR, PM_VIRT, PM_META };

/* tag identifiers */
enum { TAG_PVD = 1, TAG_AVDP = 2, TAG_VDP = 3, TAG_PD = 5, TAG_LVD = 6, TAG_TD = 8,
       TAG_FSD = 256, TAG_FID = 257, TAG_AED = 258, TAG_IE = 259, TAG_FE = 261, TAG_EFE = 266 };

typedef struct { xrun_list runs; } udf_priv;

typedef struct { u16 number; u32 start, len, seq; } udf_part;

typedef struct {
    int type;
    u16 pnum;
    i32 part;             /* PHYS / SPAR: partition descriptor index               */
    i32 under;            /* VIRT / META: map the table / file lives in            */
    u32 pkt;              /* SPAR: packet length                                    */
    u32 nst, stsize, stloc[4];
    u64 *spare; u32 nspare;   /* SPAR: (original << 32 | mapped), sorted            */
    u32 *vat; u32 nvat;   /* VIRT: virtual block -> block of under                 */
    u32 mloc[2];          /* META: metadata file / mirror locations in under        */
    xrun_list meta;       /* META: metadata file data (image offsets)              */
} udf_map;

typedef struct { u32 b, m, depth; i32 entry; } dir_item;

typedef struct {
    u32 ftype, flags, perm, m, ad_off, ad_len;
    u64 info, mtime, phys;
} udf_fe;

typedef struct {
    gz_archive *a;
    gz_src *s;
    gz_ctx *c;
    udf_priv *p;
    u64 size, budget, done;
    u32 bs, nsec;
    udf_part parts[MAX_PARTS]; u32 nparts;
    udf_map maps[MAX_MAPS]; u32 nmaps;
    u8 *lvd; int have_lvd; u32 lvd_seq;
    u8 *blk, *blk2;        /* entry block, allocation extent block                 */
    u8 *dbuf; u32 dcap;    /* directory data                                       */
    xrun_list tmp;         /* runs of directories / symlinks / tables              */
    u64 *vis; u32 vis_n, vis_cap;
    dir_item *q; u32 qh, qn, qcap;
    u32 root_b, root_m;
    u8 path[MAX_PATH + 1024];
    u8 name[1024];
    u8 link[MAX_LINK];
} udf_rd;

/* ---------------- descriptor tags ---------------- */

static int tag_ok(const u8 *p, u32 id)
{
    u32 s = 0;
    for (u32 i = 0; i < 16; i++) if (i != 4) s += p[i];
    return (u8)s == p[4] && rd16(p) == id;
}

static int crc_ok(const u8 *p, u32 n)
{
    u32 len = rd16(p + 10), c = 0;
    if (len > n - 16) return 0;
    for (u32 i = 0; i < len; i++) {
        c ^= (u32)p[16 + i] << 8;
        for (u32 k = 0; k < 8; k++) c = (c & 0x8000) ? (c << 1) ^ 0x1021 : c << 1;
    }
    return (u16)c == rd16(p + 8);
}

/* UDF timestamp (ECMA 1/7.3) */
static u64 udf_time(const u8 *p)
{
    u32 tt = rd16(p);
    i32 tz = (i32)(tt & 0xfff);
    if (tz & 0x800) tz -= 0x1000;
    if ((tt >> 12) != 1 || tz < -1440 || tz > 1440) tz = 0;
    i32 y = (i16)rd16(p + 2);
    u32 cs = p[9], hu = p[10], us = p[11];
    u32 ticks = (cs < 100 && hu < 100 && us < 100) ? cs * 100000 + hu * 1000 + us * 10 : 0;
    return isoudf_civil(y, p[4], p[5], p[6], p[7], p[8], tz, ticks);
}

/* CS0 d-characters (compression id 8/254: Latin-1, 16/255: UTF-16BE) -> UTF-16LE.
 * Stops at NUL like other readers. out needs 2 * n bytes. Returns bytes written. */
static u32 cs0_utf16le(const u8 *p, u32 n, u8 *out)
{
    if (!n) return 0;
    u32 cid = p[0], o = 0;
    p++; n--;
    if (cid == 8 || cid == 254) {
        for (u32 i = 0; i < n && p[i]; i++) { out[o++] = p[i]; out[o++] = 0; }
    } else if (cid == 16 || cid == 255) {
        for (u32 i = 0; i + 1 < n; i += 2) {
            u32 c = rd16be(p + i);
            if (!c) break;
            wr16(out + o, (u16)c);
            o += 2;
        }
    }
    return o;
}

/* ---------------- block mapping ---------------- */

static int map_block(udf_rd *u, u32 m, u32 b, u64 *sec, u32 *run, u32 depth)
{
    if (m >= u->nmaps || depth > 3) return GZ_E_FORMAT;
    udf_map *mp = &u->maps[m];
    switch (mp->type) {
    case PM_PHYS: case PM_SPAR: {
        const udf_part *pt = &u->parts[mp->part];
        if (pt->len && b >= pt->len) return GZ_E_FORMAT;
        u32 rem = pt->len ? pt->len - b : 0xffffffffu - b;
        if (!rem) return GZ_E_FORMAT;
        if (mp->type == PM_SPAR && mp->pkt) {
            u32 in = b % mp->pkt, pk = b - in, left = mp->pkt - in;
            if (left < rem) rem = left;
            u32 lo = 0, hi = mp->nspare;              /* remapped packet? */
            while (lo < hi) {
                u32 mid = (lo + hi) / 2;
                u32 o = (u32)(mp->spare[mid] >> 32);
                if (o == pk) { *sec = (u64)(u32)mp->spare[mid] + in; *run = rem; return GZ_OK; }
                if (o < pk) lo = mid + 1; else hi = mid;
            }
        }
        *sec = (u64)pt->start + b;
        *run = rem;
        return GZ_OK;
    }
    case PM_VIRT: {
        if (b >= mp->nvat || mp->vat[b] == 0xffffffffu) return GZ_E_FORMAT;
        u32 ub = mp->vat[b], n = 1, r2;
        while (b + n < mp->nvat && mp->vat[b + n] == ub + n && n < (1u << 20)) n++;
        int rc = map_block(u, (u32)mp->under, ub, sec, &r2, depth + 1);
        if (rc) return rc;
        *run = n < r2 ? n : r2;
        return GZ_OK;
    }
    case PM_META: {
        u64 pos = (u64)b * u->bs;
        const xrun_list *l = &mp->meta;
        u32 lo = 0, hi = l->n;
        while (hi - lo > 1) {
            u32 mid = (lo + hi) / 2;
            if (l->r[mid].fpos <= pos) lo = mid; else hi = mid;
        }
        if (!l->n) return GZ_E_FORMAT;
        const xrun *x = &l->r[lo];
        if (pos < x->fpos || pos - x->fpos >= x->len || x->off == XRUN_ZERO) return GZ_E_FORMAT;
        u64 at = x->off + (pos - x->fpos), left = x->len - (pos - x->fpos);
        if (at % u->bs) return GZ_E_FORMAT;
        *sec = at / u->bs;
        u64 nb = (left + u->bs - 1) / u->bs;
        *run = nb > 0xffffffffu ? 0xffffffffu : (u32)nb;
        return GZ_OK;
    }
    default:
        return GZ_E_FORMAT;
    }
}

/* Image runs of one allocation descriptor (len bytes from block b of map m). */
static int ad_runs(udf_rd *u, xrun_list *l, u64 fpos, u32 m, u32 b, u32 len, u32 type)
{
    if (type == 1 || type == 2) return xrun_add(l, fpos, XRUN_ZERO, len);
    while (len) {
        u64 sec;
        u32 run;
        int rc = map_block(u, m, b, &sec, &run, 0);
        if (rc) return rc;
        u64 bytes = (u64)run * u->bs;
        if (bytes > len) bytes = len;
        rc = xrun_add(l, fpos, sec * u->bs, bytes);
        if (rc) return rc;
        fpos += bytes;
        len -= (u32)bytes;
        b += run;
    }
    return GZ_OK;
}

static int read_block(udf_rd *u, u32 m, u32 b, u8 *buf, u64 *phys)
{
    u64 sec;
    u32 run;
    int rc = map_block(u, m, b, &sec, &run, 0);
    if (rc) return rc;
    u64 off = sec * u->bs;
    if (off >= u->size || u->bs > u->size - off) return GZ_E_TRUNC;
    if (phys) *phys = off;
    return gz_src_read_exact(u->s, off, buf, u->bs);
}

/* ---------------- file entries ---------------- */

static int parse_fe(udf_rd *u, const u8 *blk, u32 m, u64 phys, udf_fe *fe)
{
    int ext = rd16(blk) == TAG_EFE;
    u32 base = ext ? 216 : 176;
    u32 lea = rd32(blk + base - 8), lad = rd32(blk + base - 4);
    if (lea > u->bs - base || lad > u->bs - base - lea) return GZ_E_FORMAT;
    fe->ftype = blk[27];
    fe->flags = rd16(blk + 34);
    fe->perm = rd32(blk + 44);
    fe->info = rd64(blk + 56);
    fe->mtime = udf_time(blk + (ext ? 92 : 84));
    fe->m = m;
    fe->phys = phys;
    fe->ad_off = base + lea;
    fe->ad_len = lad;
    return GZ_OK;
}

/* Read the (newest) file entry of the ICB at block b of map m into blk. */
static int read_fe(udf_rd *u, u32 m, u32 b, u8 *blk, udf_fe *fe)
{
    u32 good_m = 0, good_b = 0;
    int have_good = 0;
    for (u32 hop = 0; hop < MAX_ICB_HOPS; hop++) {
        u64 phys = 0;
        int rc = read_block(u, m, b, blk, &phys);
        int id = rc ? -1 : (int)rd16(blk);
        if (!rc && id == TAG_IE && tag_ok(blk, TAG_IE) && (rd32(blk + 36) & 0x3fffffff)) {
            b = rd32(blk + 40);
            m = rd16(blk + 44);
            continue;
        }
        if (rc || (id != TAG_FE && id != TAG_EFE) || !tag_ok(blk, (u32)id)) {
            if (!have_good) return rc ? rc : GZ_E_FORMAT;
            break;                                         /* newer ICB unusable: keep the last */
        }
        have_good = 1;
        good_m = m;
        good_b = b;
        if (rd16(blk + 20) != 4096) return parse_fe(u, blk, m, phys, fe);
        /* strategy 4096: an indirect entry after the direct entry points to a newer ICB */
        u8 *ie = u->blk2;
        if (read_block(u, m, b + 1, ie, 0) || !tag_ok(ie, TAG_IE) || !(rd32(ie + 36) & 0x3fffffff))
            return parse_fe(u, blk, m, phys, fe);
        b = rd32(ie + 40);
        m = rd16(ie + 44);
    }
    if (!have_good) return GZ_E_FORMAT;
    u64 phys = 0;
    int rc = read_block(u, good_m, good_b, blk, &phys);
    if (rc) return rc;
    return parse_fe(u, blk, good_m, phys, fe);
}

/* Data runs of an entry (allocation descriptors and their extent chain), clipped to the
 * information length. *len = data length found. */
static int fe_runs(udf_rd *u, const udf_fe *fe, const u8 *blk, xrun_list *l, u64 *len)
{
    u64 limit = fe->info, fpos = 0;
    u32 adt = fe->flags & 7;
    *len = 0;
    if (adt == 3) {                                        /* data embedded in the entry */
        u64 n = limit < fe->ad_len ? limit : fe->ad_len;
        *len = n;
        return xrun_add(l, 0, fe->phys + fe->ad_off, n);
    }
    if (adt > 2) return GZ_E_METHOD;
    u32 asz = adt == 0 ? 8 : adt == 1 ? 16 : 20;
    const u8 *p = blk + fe->ad_off;
    u32 n = fe->ad_len, hops = 0;
    for (;;) {
        int next = 0;
        u32 nm = 0, nb = 0;
        for (u32 i = 0; i + asz <= n && fpos < limit; i += asz) {
            const u8 *d = p + i;
            u32 lf = rd32(d), ty = lf >> 30, el = lf & 0x3fffffff, b, m;
            if (adt == 0) { b = rd32(d + 4); m = fe->m; }
            else if (adt == 1) { b = rd32(d + 4); m = rd16(d + 8); }
            else { b = rd32(d + 12); m = rd16(d + 16); }
            if (!el) break;
            if (ty == 3) { next = 1; nm = m; nb = b; break; }
            if (el > limit - fpos) el = (u32)(limit - fpos);
            int rc = ad_runs(u, l, fpos, m, b, el, ty);
            if (rc) return rc;
            fpos += el;
        }
        if (!next || fpos >= limit) break;
        if (++hops > MAX_AED || u->budget < u->bs) return GZ_E_LIMIT;
        u->budget -= u->bs;
        u8 *aed = u->blk2;
        int rc = read_block(u, nm, nb, aed, 0);
        if (rc) return rc;
        if (!tag_ok(aed, TAG_AED)) return GZ_E_FORMAT;
        n = rd32(aed + 20);
        if (n > u->bs - 24) n = u->bs - 24;
        p = aed + 24;
    }
    *len = fpos;
    return GZ_OK;
}

/* Read the data of runs into buf (n bytes, zeros for sparse runs). */
static int read_runs(udf_rd *u, const xrun_list *l, u8 *buf, u64 n)
{
    for (u32 i = 0; i < l->n && n; i++) {
        const xrun *x = &l->r[i];
        if (x->fpos >= n) break;
        u64 k = x->len < n - x->fpos ? x->len : n - x->fpos;
        if (x->off == XRUN_ZERO) __builtin_memset(buf + x->fpos, 0, (size_t)k);
        else {
            if (x->off > u->size || k > u->size - x->off) return GZ_E_TRUNC;
            int rc = gz_src_read_exact(u->s, x->off, buf + x->fpos, (u32)k);
            if (rc) return rc;
        }
    }
    return GZ_OK;
}

/* ---------------- volume structure ---------------- */

/* Anchor volume descriptor pointer: sector size and the two VDS extents. */
static int find_anchor(gz_src *s, int deep, u32 *ss, u32 vds[4])
{
    static const u32 sizes[] = { 2048, 512, 4096, 1024 };
    u8 b[512];
    int found = 0;
    for (u32 pass = 0; pass < (deep ? 2u : 1u); pass++) {
        for (u32 k = 0; k < 4; k++) {
            u32 z = sizes[k];
            u64 nsec = s->size / z;
            if (nsec <= 257) continue;
            u64 loc[2] = { 256, 0 };
            u32 nl = 1;
            if (pass) { loc[0] = nsec - 1; loc[1] = nsec - 256; nl = nsec > 512 ? 2 : 1; }
            for (u32 j = 0; j < nl; j++) {
                if (loc[j] > 0xffffffffu || gz_src_read_exact(s, loc[j] * z, b, 512)) continue;
                if (!tag_ok(b, TAG_AVDP) || rd32(b + 12) != (u32)loc[j]) continue;
                if (!found || crc_ok(b, 512)) {
                    *ss = z;
                    vds[0] = rd32(b + 16); vds[1] = rd32(b + 20);    /* main: length, location */
                    vds[2] = rd32(b + 24); vds[3] = rd32(b + 28);    /* reserve */
                    if (crc_ok(b, 512)) return 1;
                    found = 1;
                }
            }
        }
        if (found) return 1;
    }
    return found;
}

static int read_vds(udf_rd *u, u32 len, u32 loc)
{
    u32 n = len / u->bs, hops = 0;
    if (n > 1024) n = 1024;
    u8 *b = u->blk;
    for (u32 i = 0; i < n; i++) {
        u64 off = ((u64)loc + i) * u->bs;
        if (off >= u->size || u->bs > u->size - off || gz_src_read_exact(u->s, off, b, u->bs)) break;
        u32 id = rd16(b);
        if (!tag_ok(b, id)) break;
        if (id == TAG_TD) break;
        if (id == TAG_VDP && hops < 8) {                   /* continue in another extent */
            hops++;
            n = rd32(b + 20) / u->bs;
            if (n > 1024) n = 1024;
            loc = rd32(b + 24);
            i = (u32)-1;
            continue;
        }
        if (id == TAG_PD) {
            u16 num = rd16(b + 22);
            u32 seq = rd32(b + 16), j;
            for (j = 0; j < u->nparts && u->parts[j].number != num; j++) {}
            if (j == u->nparts) {
                if (u->nparts == MAX_PARTS) continue;
                u->nparts++;
            } else if (u->parts[j].seq > seq) continue;
            udf_part *pt = &u->parts[j];
            pt->number = num;
            pt->seq = seq;
            pt->start = rd32(b + 188);
            pt->len = rd32(b + 192);
        } else if (id == TAG_LVD) {
            u32 seq = rd32(b + 16);
            if (u->have_lvd && seq < u->lvd_seq) continue;
            __builtin_memcpy(u->lvd, b, u->bs);
            u->have_lvd = 1;
            u->lvd_seq = seq;
        }
    }
    return u->have_lvd && u->nparts ? GZ_OK : GZ_E_FORMAT;
}

static void sift(u64 *a, u32 i, u32 n)
{
    for (;;) {
        u32 c = 2 * i + 1;
        if (c >= n) return;
        if (c + 1 < n && a[c + 1] > a[c]) c++;
        if (a[i] >= a[c]) return;
        u64 t = a[i]; a[i] = a[c]; a[c] = t;
        i = c;
    }
}

static void sort_u64(u64 *a, u32 n)            /* heap sort: no recursion, O(n log n) */
{
    for (u32 k = n / 2; k > 0; k--) sift(a, k - 1, n);
    for (u32 e = n; e > 1; e--) {
        u64 t = a[0]; a[0] = a[e - 1]; a[e - 1] = t;
        sift(a, 0, e - 1);
    }
}

static int load_sparing(udf_rd *u, udf_map *mp)
{
    u32 bytes = mp->stsize;
    if (bytes < 56) return GZ_OK;
    if (bytes > 56 + MAX_SPARE * 8) bytes = 56 + MAX_SPARE * 8;
    u8 *t = (u8 *)gz_alloc(bytes);
    if (!t) return GZ_E_NOMEM;
    for (u32 k = 0; k < mp->nst && k < 4; k++) {
        u64 off = (u64)mp->stloc[k] * u->bs;
        if (off >= u->size || bytes > u->size - off || gz_src_read_exact(u->s, off, t, bytes)) continue;
        if (!tag_ok(t, 0) || __builtin_memcmp(t + 17, "*UDF Sparing Table", 18)) continue;
        u32 ne = rd16(t + 48);
        if (ne > (bytes - 56) / 8) ne = (bytes - 56) / 8;
        mp->spare = (u64 *)gz_alloc((size_t)ne * 8 + 8);
        if (!mp->spare) { gz_free(t); return GZ_E_NOMEM; }
        u32 c = 0;
        for (u32 i = 0; i < ne; i++) {
            u32 o = rd32(t + 56 + i * 8), mloc = rd32(t + 60 + i * 8);
            if (o >= 0xfffffff0u) continue;               /* available / defective */
            mp->spare[c++] = (u64)o << 32 | mloc;
        }
        sort_u64(mp->spare, c);
        mp->nspare = c;
        break;
    }
    gz_free(t);
    return GZ_OK;
}

/* Virtual allocation table: the VAT ICB is the last recorded block of the image. */
static int load_vat(udf_rd *u, udf_map *mp)
{
    const udf_map *um = &u->maps[mp->under];
    const udf_part *pt = &u->parts[um->part];
    udf_fe fe;
    for (u32 back = 0; back < 256 && back < u->nsec; back++) {
        u32 sec = u->nsec - 1 - back;
        if (sec < pt->start) break;
        if (read_fe(u, (u32)mp->under, sec - pt->start, u->blk, &fe)) continue;
        if (fe.ftype != 248 && fe.ftype != 0) continue;
        u->tmp.n = 0;
        u64 len;
        if (fe_runs(u, &fe, u->blk, &u->tmp, &len) || len < 36 || len > (u64)MAX_VAT * 4 + 4096 || len > u->size) continue;
        u8 *d = (u8 *)gz_alloc((size_t)len);
        if (!d) return GZ_E_NOMEM;
        u32 hdr = 0, end = (u32)len;
        int ok = !read_runs(u, &u->tmp, d, len);
        if (ok && fe.ftype == 248) {                       /* UDF 2.00+: header first */
            hdr = rd16(d);
            ok = hdr >= 152 && hdr <= end;
        } else if (ok) {                                   /* UDF 1.50: regid at the end */
            end -= 36;
            ok = !__builtin_memcmp(d + end + 1, "*UDF Virtual Alloc Tbl", 22);
        }
        if (!ok) { gz_free(d); continue; }
        mp->nvat = (end - hdr) / 4;
        mp->vat = (u32 *)gz_alloc((size_t)mp->nvat * 4 + 4);
        if (!mp->vat) { gz_free(d); return GZ_E_NOMEM; }
        for (u32 i = 0; i < mp->nvat; i++) mp->vat[i] = rd32(d + hdr + i * 4);
        gz_free(d);
        return GZ_OK;
    }
    return GZ_E_FORMAT;
}

/* Metadata partition: data runs of the metadata file (or its mirror). */
static int load_meta(udf_rd *u, udf_map *mp)
{
    int pick = -1, crc_pick = -1;
    udf_fe fe;
    for (int k = 0; k < 2; k++) {
        if (read_fe(u, (u32)mp->under, mp->mloc[k], u->blk, &fe)) continue;
        if (fe.ftype != 250 && fe.ftype != 251) continue;
        if (pick < 0) pick = k;
        if (crc_pick < 0 && crc_ok(u->blk, u->bs)) crc_pick = k;
    }
    if (crc_pick >= 0) pick = crc_pick;
    if (pick < 0) return GZ_E_FORMAT;
    for (int k = pick; k < 2; k++) {
        if (read_fe(u, (u32)mp->under, mp->mloc[k], u->blk, &fe)) continue;
        mp->meta.n = 0;
        u64 len;
        if (!fe_runs(u, &fe, u->blk, &mp->meta, &len) && mp->meta.n) return GZ_OK;
    }
    return GZ_E_FORMAT;
}

static int setup_maps(udf_rd *u)
{
    const u8 *l = u->lvd;
    u32 mtl = rd32(l + 264), nm = rd32(l + 268);
    if (mtl > u->bs - 440) mtl = u->bs - 440;
    if (nm > MAX_MAPS) nm = MAX_MAPS;
    const u8 *p = l + 440, *end = p + mtl;
    u32 i;
    for (i = 0; i < nm && p + 2 <= end; i++) {
        udf_map *mp = &u->maps[i];
        u32 ty = p[0], ml = p[1];
        if (ml < 6 || ml > (u32)(end - p)) break;
        mp->part = mp->under = -1;
        if (ty == 1) {
            mp->type = PM_PHYS;
            mp->pnum = rd16(p + 4);
        } else if (ty == 2 && ml >= 64) {
            const u8 *id = p + 5;
            mp->pnum = rd16(p + 38);
            if (!__builtin_memcmp(id, "*UDF Virtual Partition", 22)) mp->type = PM_VIRT;
            else if (!__builtin_memcmp(id, "*UDF Sparable Partition", 23)) {
                mp->type = PM_SPAR;
                mp->pkt = rd16(p + 40);
                mp->nst = p[42];
                mp->stsize = rd32(p + 44);
                for (u32 k = 0; k < 4 && k < mp->nst; k++) mp->stloc[k] = rd32(p + 48 + k * 4);
            } else if (!__builtin_memcmp(id, "*UDF Metadata Partition", 23)) {
                mp->type = PM_META;
                mp->mloc[0] = rd32(p + 40);
                mp->mloc[1] = rd32(p + 44);
            }
        }
        p += ml;
    }
    u->nmaps = i;
    if (!u->nmaps) return GZ_E_FORMAT;
    /* partitions and underlying maps */
    for (i = 0; i < u->nmaps; i++) {
        udf_map *mp = &u->maps[i];
        if (mp->type != PM_PHYS && mp->type != PM_SPAR) continue;
        for (u32 j = 0; j < u->nparts; j++) if (u->parts[j].number == mp->pnum) mp->part = (i32)j;
        if (mp->part < 0) {
            if (u->nparts != 1) { mp->type = PM_NONE; continue; }
            mp->part = 0;
        }
    }
    for (i = 0; i < u->nmaps; i++) {
        udf_map *mp = &u->maps[i];
        if (mp->type != PM_VIRT && mp->type != PM_META) continue;
        i32 phys = -1, virt = -1;
        for (u32 j = 0; j < u->nmaps; j++) {
            const udf_map *o = &u->maps[j];
            if ((o->type == PM_PHYS || o->type == PM_SPAR) && (phys < 0 || o->pnum == mp->pnum)) phys = (i32)j;
            if (o->type == PM_VIRT && j != i && (virt < 0 || o->pnum == mp->pnum)) virt = (i32)j;
        }
        mp->under = phys;
        if (phys < 0) mp->type = PM_NONE;
        if (mp->type == PM_META && virt >= 0) mp->under = virt;     /* metadata on a VAT disc */
    }
    for (i = 0; i < u->nmaps; i++)
        if (u->maps[i].type == PM_SPAR) { int rc = load_sparing(u, &u->maps[i]); if (rc) return rc; }
    for (i = 0; i < u->nmaps; i++)
        if (u->maps[i].type == PM_VIRT) {
            int rc = load_vat(u, &u->maps[i]);
            if (rc == GZ_E_NOMEM) return rc;
            if (rc) u->maps[i].type = PM_NONE;
        }
    for (i = 0; i < u->nmaps; i++)
        if (u->maps[i].type == PM_META) {
            udf_map *mp = &u->maps[i];
            int rc = load_meta(u, mp);
            if (rc && mp->under >= 0 && u->maps[mp->under].type != PM_PHYS && u->maps[mp->under].type != PM_SPAR) {
                /* not found through the VAT (or the VAT is unusable): try the physical partition */
                for (u32 j = 0; j < u->nmaps; j++)
                    if (u->maps[j].type == PM_PHYS || u->maps[j].type == PM_SPAR) { mp->under = (i32)j; break; }
                rc = load_meta(u, mp);
            }
            if (rc == GZ_E_NOMEM) return rc;
            if (rc) mp->type = PM_NONE;
        }
    return GZ_OK;
}

/* File set descriptor -> root directory ICB. */
static int find_root(udf_rd *u)
{
    const u8 *l = u->lvd;
    u32 len = rd32(l + 248) & 0x3fffffff, b = rd32(l + 252), m = rd16(l + 256);
    u32 n = len / u->bs;
    if (n < 1) n = 1;
    if (n > 16) n = 16;
    for (u32 i = 0; i < n; i++) {
        if (read_block(u, m, b + i, u->blk, 0)) break;
        if (tag_ok(u->blk, TAG_TD)) break;
        if (!tag_ok(u->blk, TAG_FSD)) continue;
        u->root_b = rd32(u->blk + 404);
        u->root_m = rd16(u->blk + 408);
        udf_fe fe;
        if (!read_fe(u, u->root_m, u->root_b, u->blk, &fe) && fe.ftype == 4) return GZ_OK;
    }
    return GZ_E_FORMAT;
}

/* ---------------- directory tree ---------------- */

static int visit(udf_rd *u, u32 m, u32 b)
{
    u64 key = ((u64)m << 32 | b) + 1;
    if ((u->vis_n + 1) * 2 > u->vis_cap) {
        u32 nc = u->vis_cap ? u->vis_cap * 2 : 1024;
        u64 *nv = (u64 *)gz_alloc((size_t)nc * sizeof(u64));
        if (!nv) return GZ_E_NOMEM;
        for (u32 i = 0; i < u->vis_cap; i++) {
            u64 k = u->vis[i];
            if (!k) continue;
            u32 h = (u32)((k * 0x9E3779B97F4A7C15ull) >> 32) & (nc - 1);
            while (nv[h]) h = (h + 1) & (nc - 1);
            nv[h] = k;
        }
        gz_free(u->vis);
        u->vis = nv;
        u->vis_cap = nc;
    }
    u32 h = (u32)((key * 0x9E3779B97F4A7C15ull) >> 32) & (u->vis_cap - 1);
    while (u->vis[h]) {
        if (u->vis[h] == key) return 1;
        h = (h + 1) & (u->vis_cap - 1);
    }
    u->vis[h] = key;
    u->vis_n++;
    return 0;
}

static int push_dir(udf_rd *u, u32 m, u32 b, u32 depth, i32 entry)
{
    if (u->qn == u->qcap) {
        if (u->qcap >= (1u << 26)) return GZ_E_LIMIT;
        u32 nc = u->qcap ? u->qcap * 2 : 256;
        dir_item *nq = (dir_item *)gz_realloc(u->q, (size_t)nc * sizeof(dir_item));
        if (!nq) return GZ_E_NOMEM;
        u->q = nq;
        u->qcap = nc;
    }
    dir_item *d = &u->q[u->qn++];
    d->m = m;
    d->b = b;
    d->depth = depth;
    d->entry = entry;
    return GZ_OK;
}

static void link_put(udf_rd *u, u32 *n, const u8 *p, u32 k)
{
    if (k > MAX_LINK - *n) k = MAX_LINK - *n;
    __builtin_memcpy(u->link + *n, p, k);
    *n += k;
}

/* ECMA 4/14.16 path components -> UTF-8 target in u->link. */
static u32 symlink_target(udf_rd *u, const u8 *d, u32 n)
{
    u32 o = 0, pos = 0;
    gzch w[256];
    while (pos + 4 <= n) {
        u32 ty = d[pos], lci = d[pos + 1];
        if (lci > n - pos - 4) break;
        const u8 *id = d + pos + 4;
        pos += 4 + lci;
        if ((ty == 1 && !lci) || ty == 2) { o = 0; link_put(u, &o, (const u8 *)"/", 1); continue; }
        if (ty < 3 || ty > 5) continue;
        if (o && u->link[o - 1] != '/') link_put(u, &o, (const u8 *)"/", 1);
        if (ty == 3) link_put(u, &o, (const u8 *)"..", 2);
        else if (ty == 4) link_put(u, &o, (const u8 *)".", 1);
        else {
            u32 nb = cs0_utf16le(id, lci, u->name);
            u32 nw = nb / 2;
            if (nw > 255) nw = 255;
            for (u32 i = 0; i < nw; i++) w[i] = rd16(u->name + 2 * i);
            u8 utf[256 * 3];
            int k = gz_utf16_to_utf8(w, nw, utf);
            link_put(u, &o, utf, (u32)k);
        }
    }
    return o;
}

static gz_entry *ent(udf_rd *u, u32 i) { return &u->a->e[i]; }

/* One FID: add the entry it names. */
static int add_child(udf_rd *u, const dir_item *d, const u8 *f, u32 plen)
{
    u32 chars = f[18], lfi = f[19], liu = rd16(f + 36);
    u32 cb = rd32(f + 24), cm = rd16(f + 28);
    if (u->a->n >= MAX_ENTRIES) return GZ_E_LIMIT;
    u32 nn = cs0_utf16le(f + 38 + liu, lfi, u->name);
    if (!nn) { u->name[0] = '_'; u->name[1] = 0; nn = 2; }
    u32 sep = plen ? 2 : 0;
    if (plen + sep + nn > MAX_PATH) return GZ_OK;          /* path too long: skip */
    if (sep) { u->path[plen] = '/'; u->path[plen + 1] = 0; }
    __builtin_memcpy(u->path + plen + sep, u->name, nn);
    u32 len = plen + sep + nn;

    udf_fe fe;
    int frc = read_fe(u, cm, cb, u->blk, &fe);
    if (frc == GZ_E_NOMEM) return frc;
    gz_entry *e;
    int rc = gz_arc_add_named(u->a, u->path, len, GZ_NE_UTF16LE, &e);
    if (rc) return rc;
    u32 idx = u->a->n - 1;
    if (chars & 1) e->attr |= 2;                           /* hidden */
    if (frc) {                                             /* unreadable entry: listed, fails to extract */
        e->is_dir = (u8)((chars & 2) != 0);
        if (e->is_dir) e->attr |= 0x10;
        else e->flags = F_BAD;
        return GZ_OK;
    }
    int is_dir = fe.ftype == 4, is_link = fe.ftype == 12;
    u32 pm = fe.perm;
    e->unix_mode = ((pm >> 10) & 7) << 6 | ((pm >> 5) & 7) << 3 | (pm & 7);
    if (fe.flags & 0x40) e->unix_mode |= 04000;
    if (fe.flags & 0x80) e->unix_mode |= 02000;
    if (fe.flags & 0x100) e->unix_mode |= 01000;
    e->unix_mode |= is_dir ? 0040000u : is_link ? 0120000u : 0100000u;
    if (fe.flags & 0x400) e->attr |= 4;                    /* system */
    e->mtime = fe.mtime;
    e->mtime_kind = fe.mtime ? GZ_MT_FILETIME : GZ_MT_NONE;
    if (is_dir) {
        e->is_dir = 1;
        e->attr |= 0x10;
        if (d->depth + 1 < MAX_DEPTH) return push_dir(u, cm, cb, d->depth + 1, (i32)idx);
        return GZ_OK;
    }
    if (is_link) {
        e->is_link = 1;
        u->tmp.n = 0;
        u64 n;
        if (fe_runs(u, &fe, u->blk, &u->tmp, &n)) return GZ_OK;
        if (n > MAX_LINK) n = MAX_LINK;
        u8 *buf = (u8 *)gz_alloc((size_t)n + 1);
        if (!buf) return GZ_E_NOMEM;
        u32 tl = 0;
        if (!read_runs(u, &u->tmp, buf, n)) tl = symlink_target(u, buf, (u32)n);
        gz_free(buf);
        if (tl) {
            u32 lo;
            rc = gz_arc_raw_append(u->a, u->link, tl, &lo);
            if (rc) return rc;
            e = ent(u, idx);
            e->link_off = lo;
            e->link_len = tl;
        }
        return GZ_OK;
    }
    /* regular file (and anything else with data) */
    xrun_list *rl = &u->p->runs;
    u32 start = rl->n;
    u64 n;
    rc = fe_runs(u, &fe, u->blk, rl, &n);
    e = ent(u, idx);
    if (rc == GZ_E_NOMEM) return rc;
    if (rc) { rl->n = start; e->flags = F_BAD; return GZ_OK; }
    e->usize = e->csize = n;
    if (rl->n == start) return GZ_OK;                      /* empty */
    if (rl->n == start + 1 && rl->r[start].off != XRUN_ZERO) {
        e->off = rl->r[start].off;                         /* one contiguous extent */
        rl->n = start;
        return GZ_OK;
    }
    e->flags = F_MULTI;
    e->aux = start;
    e->aux32 = rl->n - start;
    return GZ_OK;
}

static int scan_dir(udf_rd *u, const dir_item *d)
{
    udf_fe fe;
    if (read_fe(u, d->m, d->b, u->blk, &fe) || fe.ftype != 4) return GZ_OK;
    u->tmp.n = 0;
    u64 len;
    int rc = fe_runs(u, &fe, u->blk, &u->tmp, &len);
    if (rc) return rc == GZ_E_NOMEM ? rc : GZ_OK;
    if (len > MAX_DIR) return GZ_OK;
    if (len > u->budget) return GZ_E_LIMIT;
    u->budget -= len;
    if (len > u->dcap) {
        u8 *nb = (u8 *)gz_realloc(u->dbuf, (size_t)len);
        if (!nb) return GZ_E_NOMEM;
        u->dbuf = nb;
        u->dcap = (u32)len;
    }
    u32 n = (u32)len;
    if (read_runs(u, &u->tmp, u->dbuf, n)) return GZ_OK;
    u->done += n;
    u32 plen = 0;
    if (d->entry >= 0) {
        const gz_entry *pe = ent(u, (u32)d->entry);
        plen = pe->raw_len;
        __builtin_memcpy(u->path, u->a->raw + pe->raw_off, plen);
    }
    const u8 *b = u->dbuf;
    u32 pos = 0;
    while (pos + 38 <= n) {
        const u8 *f = b + pos;
        if (!tag_ok(f, TAG_FID)) { pos += 4; continue; }  /* damaged: resynchronise */
        u32 lfi = f[19], liu = rd16(f + 36);
        u32 tot = (38 + liu + lfi + 3) & ~3u;
        if (38 + liu + lfi > n - pos) break;
        pos += tot;
        u32 chars = f[18];
        if (chars & 0x0c) continue;                        /* deleted, parent */
        if (!(rd32(f + 20) & 0x3fffffff)) continue;        /* no ICB */
        rc = add_child(u, d, f, plen);
        if (rc) return rc;
        if (gz_cancelled(u->c)) return GZ_E_CANCEL;
    }
    return GZ_OK;
}

/* ---------------- open / close ---------------- */

static void free_maps(udf_rd *u)
{
    for (u32 i = 0; i < MAX_MAPS; i++) {
        gz_free(u->maps[i].spare);
        gz_free(u->maps[i].vat);
        gz_free(u->maps[i].meta.r);
    }
    __builtin_memset(u->maps, 0, sizeof u->maps);
    u->nmaps = 0;
}

static int try_volume(udf_rd *u, u32 len, u32 loc)
{
    free_maps(u);
    u->nparts = 0;
    u->have_lvd = 0;
    int rc = read_vds(u, len, loc);
    if (!rc) rc = setup_maps(u);
    if (!rc) rc = find_root(u);
    return rc;
}

static void udf_close(gz_archive *a)
{
    udf_priv *p = (udf_priv *)a->priv;
    if (!p) return;
    gz_free(p->runs.r);
    gz_free(p);
    a->priv = 0;
}

static int has_iso9660(gz_src *s)
{
    u8 d[8];
    return s->size > 17 * 2048 && !gz_src_read_exact(s, 16 * 2048, d, 8) && !__builtin_memcmp(d + 1, "CD001", 5);
}

static int udf_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    u32 ss, vds[4];
    if (!find_anchor(s, 1, &ss, vds)) return GZ_E_FORMAT;
    udf_rd *u = (udf_rd *)gz_alloc(sizeof(udf_rd));
    if (!u) return GZ_E_NOMEM;
    u->a = a; u->s = s; u->c = c;
    u->size = s->size;
    u->bs = ss;
    u->nsec = s->size / ss > 0xffffffffu ? 0xffffffffu : (u32)(s->size / ss);
    u->budget = 2 * s->size + (64u << 20);
    u->lvd = (u8 *)gz_alloc(ss);
    u->blk = (u8 *)gz_alloc(ss);
    u->blk2 = (u8 *)gz_alloc(ss);
    udf_priv *p = (udf_priv *)gz_alloc(sizeof(udf_priv));
    int rc = GZ_E_NOMEM;
    if (!u->lvd || !u->blk || !u->blk2 || !p) { gz_free(p); goto out; }
    a->priv = p;
    u->p = p;

    rc = try_volume(u, vds[0], vds[1]);
    if (rc && rc != GZ_E_NOMEM) rc = try_volume(u, vds[2], vds[3]);
    if (rc) goto out;
    gz_arc_set_type(a, "UDF");

    rc = visit(u, u->root_m, u->root_b);
    if (rc > 1) goto out;
    rc = push_dir(u, u->root_m, u->root_b, 0, -1);
    while (!rc && u->qh < u->qn) {
        dir_item d = u->q[u->qh++];
        if (d.entry >= 0) {
            int seen = visit(u, d.m, d.b);
            if (seen > 1) { rc = seen; break; }
            if (seen) continue;                            /* loop or hard-linked directory */
        }
        if (gz_cancelled(c)) { rc = GZ_E_CANCEL; break; }
        rc = scan_dir(u, &d);
        if (c && c->progress && !(u->qh & 63)) c->progress(c->progress_user, u->done, u->size);
    }
    if (rc == GZ_E_LIMIT && a->n) rc = GZ_OK;
    /* an empty UDF side of a bridge disc: let the ISO 9660 reader show its files */
    if (!rc && !a->n && has_iso9660(s)) rc = GZ_E_FORMAT;
out:
    free_maps(u);
    gz_free(u->lvd);
    gz_free(u->blk);
    gz_free(u->blk2);
    gz_free(u->dbuf);
    gz_free(u->tmp.r);
    gz_free(u->vis);
    gz_free(u->q);
    gz_free(u);
    return rc;
}

/* ---------------- extraction ---------------- */

static gz_src *udf_view(gz_archive *a, gz_src *s, u32 idx)
{
    gz_entry *e = &a->e[idx];
    if (e->is_dir || e->is_link || (e->flags & F_BAD)) return 0;
    if (!(e->flags & F_MULTI)) return gz_src_sub(s, e->off, e->usize);
    udf_priv *p = (udf_priv *)a->priv;
    if (e->aux + e->aux32 > p->runs.n) return 0;
    return xrun_view(s, p->runs.r + e->aux, e->aux32, e->usize);
}

static int udf_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    gz_entry *e = &a->e[idx];
    if (e->flags & F_BAD) return GZ_E_FORMAT;
    if (!(e->flags & F_MULTI) || e->is_dir || e->is_link) return gz_extract_stored(a, s, idx, e->off, out, c);
    gz_src *v = udf_view(a, s, idx);
    if (!v) return GZ_E_NOMEM;
    int r = gz_extract_stored(a, v, idx, 0, out, c);
    gz_src_free(v);
    return r;
}

static int udf_probe(gz_src *s, const u8 *head, u32 n)
{
    int nsr = 0;
    for (u32 o = 32768; o + 7 <= n && o < 32768 + 64 * 2048; o += 2048) {
        const u8 *d = head + o;
        if (d[0] || d[6] != 1) continue;
        if (!__builtin_memcmp(d + 1, "NSR02", 5) || !__builtin_memcmp(d + 1, "NSR03", 5)) nsr = 1;
        else if (!__builtin_memcmp(d + 1, "TEA01", 5)) break;
    }
    u32 ss, vds[4];
    if (find_anchor(s, 0, &ss, vds)) return nsr ? 88 : 65;
    if (nsr && find_anchor(s, 1, &ss, vds)) return 85;
    return 0;
}

GZ_FORMAT(gz_fmt_udf)
const gz_format gz_fmt_udf = {
    "UDF", "udf iso img", 0, udf_probe, udf_open, udf_close, udf_extract, 0, 0, 0, udf_view, 0
};
