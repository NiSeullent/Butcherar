/*
 * 고깃ZIP - ISO 9660 reader (CD / DVD images)
 *
 *   Volume descriptor set: primary, Joliet (UCS-2, escape %/@ %/C %/E), ISO 9660:1999
 *   (enhanced) and the El Torito boot record. Names: Rock Ridge > Joliet > 9660:1999 >
 *   primary (";1" version and trailing '.' stripped).
 *   Rock Ridge / SUSP: SP (LEN_SKP, also after a CD-XA record), CE continuation areas,
 *   ST, NM (continued), PX, SL (symlink components), TF (short and long dates), CL/PL/RE
 *   (relocated deep directories; an rr_moved holding nothing else is hidden).
 *   Multi-extent files (level 3, > 4 GiB), interleaved files, extended attribute
 *   records, hidden (existence bit) and associated files (is_aux), El Torito boot
 *   images listed as "[BOOT]/Boot-NoEmul.img" etc. like 7-Zip.
 *
 * Hostile input: every directory extent is read once (loops), depth, path length,
 * CE chains, total directory bytes and entry count are bounded; extents outside the
 * image list as empty directories or fail with GZ_E_TRUNC on extraction.
 */
#include "arc.h"
#include "isoudf.h"

#define SEC        2048u
#define VD_MAX     64u                 /* volume descriptors scanned               */
#define MAX_DEPTH  256u
#define MAX_PATH   8192u               /* raw path bytes of one entry              */
#define MAX_NM     1024u               /* Rock Ridge name bytes                    */
#define MAX_SL     4096u               /* Rock Ridge symlink target bytes          */
#define MAX_CE     32u                 /* continuation areas per record            */
#define MAX_CE_LEN (64u << 10)
#define MAX_ENTRIES (1u << 24)
#define MAX_RUNS   (1u << 20)          /* runs of one interleaved file             */
#define DIRBUF     (64u << 10)

enum { T_PRIMARY = 0, T_V2, T_JOLIET, T_RR };
enum { F_MULTI = 1, F_UNSUP = 2, F_BOOT = 4 };   /* gz_entry.flags */

typedef struct { xrun_list runs; } iso_priv;

typedef struct { u32 lba, size, depth; i32 entry; } dir_item;

typedef struct {
    u32 nm_len, sl_len, mode, cl;
    u64 mtime;
    u8 has_nm, has_sl, has_px, has_tf, has_cl, re, seen, sl_sep;
    u8 nm_done, sl_done;      /* NM / SL without the CONTINUE flag ends the name / target */
    u8 nm[MAX_NM];
    u8 sl[MAX_SL];
} rr_info;

typedef struct {
    gz_archive *a;
    gz_src *s;
    gz_ctx *c;
    iso_priv *p;
    u64 size;                 /* image size                                   */
    u64 budget;               /* directory + continuation bytes still allowed */
    u64 done;                 /* directory bytes processed (progress)         */
    u32 bs;                   /* logical block size                           */
    int tree;
    u32 skip;                 /* SUSP LEN_SKP                                 */
    u8 *buf;                  /* DIRBUF directory window                      */
    u8 *ce;                   /* continuation area (MAX_CE_LEN)               */
    u32 ce_lba;               /* block cached in ce (+1, 0 = none)            */
    u32 *vis; u32 vis_n, vis_cap;          /* visited directory extents (lba+1) */
    dir_item *q; u32 qh, qn, qcap;
    i32 multi;                /* entry of an unfinished multi-extent file     */
    u32 multi_len;
    u8 multi_id[256];
    i32 rr_moved;             /* relocation directory entry, -1 = none        */
    u32 rr_moved_kids;
    u32 cur_entry_kids;
    rr_info rr;
    u8 path[MAX_PATH + 2 * MAX_NM + 8];
} iso_rd;

/* ---------------- small helpers ---------------- */

static u32 digits(const u8 *p, u32 n, int *ok)
{
    u32 v = 0;
    for (u32 i = 0; i < n; i++) {
        u32 c = p[i];
        if (c == ' ' || c == 0) c = '0';
        if (c < '0' || c > '9') { *ok = 0; return 0; }
        v = v * 10 + (c - '0');
    }
    return v;
}

/* 7-byte directory record date (years since 1900, GMT offset in 15 minute units) */
static u64 rec_time(const u8 *p)
{
    if (!p[0] && !p[1] && !p[2]) return 0;
    i32 tz = (i8)p[6];
    if (tz < -48 || tz > 52) tz = 0;
    return isoudf_civil(1900 + (i64)p[0], p[1], p[2], p[3], p[4], p[5], tz * 15, 0);
}

/* 17-byte "YYYYMMDDHHMMSScc" + offset date (volume descriptors, TF long form) */
static u64 dec_time(const u8 *p)
{
    int ok = 1;
    u32 y = digits(p, 4, &ok), mo = digits(p + 4, 2, &ok), d = digits(p + 6, 2, &ok);
    u32 h = digits(p + 8, 2, &ok), mi = digits(p + 10, 2, &ok), s = digits(p + 12, 2, &ok);
    u32 cs = digits(p + 14, 2, &ok);
    if (!ok || !y) return 0;
    i32 tz = (i8)p[16];
    if (tz < -48 || tz > 52) tz = 0;
    return isoudf_civil(y, mo, d, h, mi, s, tz * 15, cs * 100000u);
}

static int read_at(iso_rd *r, u64 off, void *buf, u32 n)
{
    if (off > r->size || n > r->size - off) return GZ_E_TRUNC;
    return gz_src_read_exact(r->s, off, buf, n);
}

/* visited directory extents (open addressing set of lba+1): 0 new, 1 seen, GZ_E_NOMEM */
static int visit(iso_rd *r, u32 lba)
{
    u32 key = lba + 1;
    if (!key) key = 1;
    if ((r->vis_n + 1) * 2 > r->vis_cap) {
        u32 nc = r->vis_cap ? r->vis_cap * 2 : 1024;
        u32 *nv = (u32 *)gz_alloc((size_t)nc * sizeof(u32));
        if (!nv) return GZ_E_NOMEM;
        for (u32 i = 0; i < r->vis_cap; i++) {
            u32 k = r->vis[i];
            if (!k) continue;
            u32 h = (k * 2654435761u) & (nc - 1);
            while (nv[h]) h = (h + 1) & (nc - 1);
            nv[h] = k;
        }
        gz_free(r->vis);
        r->vis = nv;
        r->vis_cap = nc;
    }
    u32 h = (key * 2654435761u) & (r->vis_cap - 1);
    while (r->vis[h]) {
        if (r->vis[h] == key) return 1;
        h = (h + 1) & (r->vis_cap - 1);
    }
    r->vis[h] = key;
    r->vis_n++;
    return 0;
}

static int push_dir(iso_rd *r, u32 lba, u32 size, u32 depth, i32 entry)
{
    if (r->qn == r->qcap) {
        if (r->qcap >= (1u << 26)) return GZ_E_LIMIT;
        u32 nc = r->qcap ? r->qcap * 2 : 256;
        dir_item *nq = (dir_item *)gz_realloc(r->q, (size_t)nc * sizeof(dir_item));
        if (!nq) return GZ_E_NOMEM;
        r->q = nq;
        r->qcap = nc;
    }
    dir_item *d = &r->q[r->qn++];
    d->lba = lba;
    d->size = size;
    d->depth = depth;
    d->entry = entry;
    return GZ_OK;
}

/* ---------------- Rock Ridge / SUSP ---------------- */

static void sl_put(rr_info *ri, const u8 *p, u32 n)
{
    if (n > MAX_SL - ri->sl_len) n = MAX_SL - ri->sl_len;
    __builtin_memcpy(ri->sl + ri->sl_len, p, n);
    ri->sl_len += n;
}

static void parse_sl(rr_info *ri, const u8 *d, u32 len)
{
    u32 i = 5;
    ri->has_sl = 1;
    while (i + 2 <= len) {
        u32 cf = d[i], cl = d[i + 1];
        if (cl > len - i - 2) break;
        const u8 *ct = d + i + 2;
        if (ri->sl_sep) { sl_put(ri, (const u8 *)"/", 1); ri->sl_sep = 0; }
        if (cf & 8) {                                   /* root */
            if (!ri->sl_len) sl_put(ri, (const u8 *)"/", 1);
        } else {
            if (cf & 2) sl_put(ri, (const u8 *)".", 1);
            else if (cf & 4) sl_put(ri, (const u8 *)"..", 2);
            else if (!(cf & 0x30)) sl_put(ri, ct, cl);
            ri->sl_sep = !(cf & 1);                     /* component continues: no '/' */
        }
        i += 2 + cl;
    }
}

static void parse_tf(rr_info *ri, const u8 *d, u32 len)
{
    u32 fl = d[4], step = (fl & 0x80) ? 17 : 7, pos = 5;
    for (u32 b = 0; b < 7; b++) {
        if (!(fl & (1u << b))) continue;
        if (pos + step > len) return;
        if (b == 1) {                                   /* modification */
            u64 t = step == 17 ? dec_time(d + pos) : rec_time(d + pos);
            if (t) { ri->mtime = t; ri->has_tf = 1; }
            return;
        }
        pos += step;
    }
}

static int er_is_rr(const u8 *d, u32 len)
{
    if (len < 8) return 0;
    u32 n = d[4];
    if (n > len - 8) return 0;
    const u8 *id = d + 8;
    return (n == 10 && (!__builtin_memcmp(id, "RRIP_1991A", 10) || !__builtin_memcmp(id, "IEEE_P1282", 10))) ||
           (n == 9 && !__builtin_memcmp(id, "IEEE_1282", 9));
}

/* One system use area. Returns 1 when ST was found. Sets *ce when a CE entry points on. */
static int susp_area(rr_info *ri, const u8 *p, u32 n, u32 ce[3], int *has_ce)
{
    u32 i = 0;
    while (i + 4 <= n) {
        const u8 *d = p + i;
        u32 len = d[2];
        if (len < 4 || len > n - i) break;
        u32 sig = (u32)d[0] << 8 | d[1];
        switch (sig) {
        case 'C' << 8 | 'E':
            if (len >= 28) { ce[0] = rd32(d + 4); ce[1] = rd32(d + 12); ce[2] = rd32(d + 20); *has_ce = 1; }
            break;
        case 'S' << 8 | 'T':
            return 1;
        case 'N' << 8 | 'M':
            ri->seen = 1;
            if (len >= 5 && !(d[4] & 6) && !ri->nm_done) {  /* not "." / ".." */
                u32 k = len - 5;
                if (k > MAX_NM - ri->nm_len) k = MAX_NM - ri->nm_len;
                __builtin_memcpy(ri->nm + ri->nm_len, d + 5, k);
                ri->nm_len += k;
                ri->has_nm = 1;
                ri->nm_done = !(d[4] & 1);
            }
            break;
        case 'P' << 8 | 'X':
            ri->seen = 1;
            if (len >= 12) { ri->mode = rd32(d + 4); ri->has_px = 1; }
            break;
        case 'S' << 8 | 'L':
            ri->seen = 1;
            if (len >= 5 && !ri->sl_done) {
                parse_sl(ri, d, len);
                ri->sl_done = !(d[4] & 1);
            }
            break;
        case 'T' << 8 | 'F':
            ri->seen = 1;
            if (len >= 5) parse_tf(ri, d, len);
            break;
        case 'C' << 8 | 'L':
            ri->seen = 1;
            if (len >= 12) { ri->cl = rd32(d + 4); ri->has_cl = 1; }
            break;
        case 'R' << 8 | 'E':
            ri->seen = 1;
            ri->re = 1;
            break;
        case 'R' << 8 | 'R': case 'P' << 8 | 'N': case 'P' << 8 | 'L': case 'S' << 8 | 'F':
            ri->seen = 1;
            break;
        case 'E' << 8 | 'R':
            if (er_is_rr(d, len)) ri->seen = 1;
            break;
        default:
            break;
        }
        i += len;
    }
    return 0;
}

/* Collect the Rock Ridge fields of one record (system use area + continuation areas). */
static int rr_collect(iso_rd *r, const u8 *su, u32 sun, u32 skip)
{
    rr_info *ri = &r->rr;
    ri->nm_len = ri->sl_len = 0;
    ri->has_nm = ri->has_sl = ri->has_px = ri->has_tf = ri->has_cl = ri->re = ri->seen = ri->sl_sep = 0;
    ri->nm_done = ri->sl_done = 0;
    if (sun <= skip) return GZ_OK;
    u32 ce[3], seen_lba[MAX_CE], seen_off[MAX_CE];
    int has_ce = 0;
    if (susp_area(ri, su + skip, sun - skip, ce, &has_ce)) return GZ_OK;
    for (u32 hop = 0; has_ce && hop < MAX_CE; hop++) {
        has_ce = 0;
        u32 lba = ce[0], off = ce[1], len = ce[2];
        if (!len || len > MAX_CE_LEN) break;
        u32 k = 0;
        while (k < hop && (seen_lba[k] != lba || seen_off[k] != off)) k++;
        if (k < hop) break;                               /* continuation loop */
        seen_lba[hop] = lba;
        seen_off[hop] = off;
        const u8 *area;
        if ((u64)off + len <= r->bs) {
            /* areas of neighbouring records share blocks: cache the block */
            if (r->ce_lba != lba + 1) {
                if (r->budget < r->bs) return GZ_E_LIMIT;
                r->budget -= r->bs;
                r->ce_lba = 0;
                if (read_at(r, (u64)lba * r->bs, r->ce, r->bs)) break;
                r->ce_lba = lba + 1;
            }
            area = r->ce + off;
        } else {
            if (r->budget < len) return GZ_E_LIMIT;
            r->budget -= len;
            r->ce_lba = 0;
            if (read_at(r, (u64)lba * r->bs + off, r->ce, len)) break;
            area = r->ce;
        }
        if (susp_area(ri, area, len, ce, &has_ce)) break;
    }
    return GZ_OK;
}

/* SP at the start of the root "." system use area (or after a 14-byte CD-XA record). */
static int find_sp(const u8 *su, u32 n, u32 *skip)
{
    for (u32 o = 0; o <= 14; o += 14) {
        if (n >= o + 7 && su[o] == 'S' && su[o + 1] == 'P' && su[o + 2] == 7 && su[o + 4] == 0xBE && su[o + 5] == 0xEF) {
            *skip = su[o + 6];
            return 1;
        }
    }
    return 0;
}

/* ---------------- names ---------------- */

/* Strip ";version" and one trailing '.' from an ISO identifier (unit = 1 or 2 bytes, BE). */
static u32 unit_at(const u8 *p, u32 i, u32 unit) { return unit == 2 ? rd16be(p + i) : p[i]; }

static u32 clean_name(const u8 *p, u32 n, u32 unit)
{
    n -= n % unit;
    u32 k = n;
    while (k >= unit && unit_at(p, k - unit, unit) >= '0' && unit_at(p, k - unit, unit) <= '9') k -= unit;
    if (k >= unit && unit_at(p, k - unit, unit) == ';') n = k - unit;
    if (n >= unit && unit_at(p, n - unit, unit) == '.') n -= unit;
    return n;
}

/* Append "/" + name to r->path at plen; returns the new length or 0 when too long. */
static u32 path_join(iso_rd *r, u32 plen, const u8 *nm, u32 n, int wide)
{
    u32 sep = plen ? (wide ? 2u : 1u) : 0u;
    if (!n) { nm = wide ? (const u8 *)"\0_" : (const u8 *)"_"; n = wide ? 2 : 1; }
    if (plen + sep + n > MAX_PATH) return 0;
    u8 *o = r->path + plen;
    if (sep == 2) { o[0] = 0; o[1] = '/'; }
    else if (sep == 1) o[0] = '/';
    __builtin_memcpy(o + sep, nm, n);
    if (wide) {                                         /* NUL units would cut the name */
        for (u32 i = 0; i + 1 < n; i += 2)
            if (!o[sep + i] && !o[sep + i + 1]) o[sep + i + 1] = '_';
    }
    return plen + sep + n;
}

/* ---------------- directory records ---------------- */

static gz_entry *ent(iso_rd *r, i32 i) { return &r->a->e[i]; }

/* Turn entry idx into a run list (first extent) if it is still a single extent. */
static int to_runs(iso_rd *r, gz_entry *e)
{
    if (e->flags & F_MULTI) return GZ_OK;
    e->aux = r->p->runs.n;
    e->flags |= F_MULTI;
    int rc = xrun_add(&r->p->runs, 0, e->off, e->usize);
    e->aux32 = r->p->runs.n - (u32)e->aux;
    return rc;
}

/* Add the data of one extent at file position fpos (interleaved: units of fus blocks, gap blocks apart). */
static int add_extent(iso_rd *r, gz_entry *e, u64 off, u32 len, u32 fus, u32 gap)
{
    u64 fpos = e->usize;
    if (!fus || !gap) {
        if (!(e->flags & F_MULTI) && !fpos) { e->off = off; e->usize = e->csize = len; return GZ_OK; }
        int rc = to_runs(r, e);
        if (!rc) rc = xrun_add(&r->p->runs, fpos, off, len);
        e->usize += len;
        e->csize = e->usize;
        e->aux32 = r->p->runs.n - (u32)e->aux;
        return rc;
    }
    int rc = to_runs(r, e);
    u64 unit = (u64)fus * r->bs, step = unit + (u64)gap * r->bs;
    u32 left = len;
    while (!rc && left) {
        if (r->p->runs.n - (u32)e->aux >= MAX_RUNS) { e->flags |= F_UNSUP; break; }
        u32 take = left < unit ? left : (u32)unit;
        rc = xrun_add(&r->p->runs, fpos, off, take);
        fpos += take; off += step; left -= take;
    }
    e->usize += len;
    e->csize = e->usize;
    e->aux32 = r->p->runs.n - (u32)e->aux;
    return rc;
}

/* A finished multi-extent file whose extents are back to back becomes a single extent. */
static void finish_multi(iso_rd *r)
{
    if (r->multi < 0) return;
    gz_entry *e = ent(r, r->multi);
    r->multi = -1;
    if ((e->flags & (F_MULTI | F_UNSUP)) == F_MULTI && e->aux32 == 1 && e->aux + 1 == r->p->runs.n) {
        e->off = r->p->runs.r[e->aux].off;
        r->p->runs.n--;
        e->aux = 0;
        e->aux32 = 0;
        e->flags &= (u16)~F_MULTI;
    }
}

/* Size of the directory at lba from its "." record (Rock Ridge CL targets). */
static u32 dot_size(iso_rd *r, u32 lba)
{
    u8 rec[34];
    if (read_at(r, (u64)lba * r->bs, rec, 34)) return 0;
    if (rec[0] < 34 || rec[32] != 1 || rec[33] != 0 || rd32(rec + 2) != lba) return 0;
    return rd32(rec + 10);
}

static int do_record(iso_rd *r, const dir_item *d, const u8 *p, u32 rl, u32 plen)
{
    u32 nl = p[32];
    if (33 + nl > rl) return GZ_OK;                       /* corrupt record */
    const u8 *id = p + 33;
    if (nl == 1 && (id[0] == 0 || id[0] == 1)) return GZ_OK;    /* "." and ".." */
    u32 fl = p[25], ear = p[1], lba = rd32(p + 2), dlen = rd32(p + 10);
    u32 suo = 33 + nl + !(nl & 1);
    const u8 *su = p + suo;
    u32 sun = suo < rl ? rl - suo : 0;
    int is_dir = (fl & 2) != 0;
    rr_info *ri = &r->rr;

    if (r->tree == T_RR) {
        int rc = rr_collect(r, su, sun, r->skip);
        if (rc) return rc;
        if (ri->re) return GZ_OK;                         /* shown under its real parent (CL) */
        if (ri->has_cl) { is_dir = 1; lba = ri->cl; ear = 0; dlen = dot_size(r, lba); }
    } else {
        ri->has_nm = ri->has_sl = ri->has_px = ri->has_tf = ri->has_cl = 0;
    }

    /* next extent of a multi-extent file */
    if (r->multi >= 0) {
        if (!is_dir && nl == r->multi_len && !__builtin_memcmp(id, r->multi_id, nl)) {
            gz_entry *e = ent(r, r->multi);
            int rc = add_extent(r, e, ((u64)lba + ear) * r->bs, dlen, p[26], p[27]);
            if (rc) return rc;
            if (!(fl & 0x80)) finish_multi(r);
            return GZ_OK;
        }
        finish_multi(r);
    }

    if (r->a->n >= MAX_ENTRIES) return GZ_E_LIMIT;
    int wide = r->tree == T_JOLIET;
    const u8 *nm = id;
    u32 nn;
    if (ri->has_nm && ri->nm_len) { nm = ri->nm; nn = ri->nm_len; }
    else nn = clean_name(id, nl, wide ? 2 : 1);
    u32 len = path_join(r, plen, nm, nn, wide);
    if (!len) return GZ_OK;                               /* path too long: skip */

    gz_entry *e;
    int rc = gz_arc_add_named(r->a, r->path, len, wide ? GZ_NE_UTF16BE : GZ_NE_LEGACY, &e);
    if (rc) return rc;
    i32 idx = (i32)(r->a->n - 1);
    r->cur_entry_kids++;
    e->is_dir = (u8)is_dir;
    e->is_aux = (u8)((fl & 4) != 0);                      /* associated file */
    e->mtime = ri->has_tf ? ri->mtime : rec_time(p + 18);
    e->mtime_kind = e->mtime ? GZ_MT_FILETIME : GZ_MT_NONE;
    if (fl & 1) e->attr |= 2;                             /* existence bit: hidden */
    if (is_dir) e->attr |= 0x10;
    int link = !is_dir && ri->has_sl && (!ri->has_px || (ri->mode & 0170000) == 0120000);
    if (ri->has_px) {
        u32 t = is_dir ? 0040000u : link ? 0120000u : 0100000u;
        e->unix_mode = (ri->mode & 07777) | t;
    }
    if (is_dir) {
        e->usize = e->csize = 0;
        e->off = (u64)lba * r->bs;
        if (d->depth + 1 < MAX_DEPTH && dlen) {
            rc = push_dir(r, lba + ear, dlen, d->depth + 1, idx);
            if (rc) return rc;
        }
        if (r->tree == T_RR && d->entry < 0 && r->rr_moved < 0 && ri->has_nm &&
            ((ri->nm_len == 8 && !__builtin_memcmp(ri->nm, "rr_moved", 8)) ||
             (ri->nm_len == 9 && !__builtin_memcmp(ri->nm, ".rr_moved", 9))))
            r->rr_moved = idx;
        return GZ_OK;
    }
    if (link) {
        e->is_link = 1;
        u32 lo;
        if (ri->sl_len) {
            rc = gz_arc_raw_append(r->a, ri->sl, ri->sl_len, &lo);
            if (rc) return rc;
            e = ent(r, idx);
            e->link_off = lo;
            e->link_len = ri->sl_len;
        }
        e->usize = e->csize = 0;
        return GZ_OK;
    }
    e->usize = 0;
    rc = add_extent(r, e, ((u64)lba + ear) * r->bs, dlen, p[26], p[27]);
    e->csize = e->usize;
    if (rc) return rc;
    if ((fl & 0x80) || (e->flags & F_MULTI)) {
        r->multi = idx;
        r->multi_len = nl;
        __builtin_memcpy(r->multi_id, id, nl);
        if (!(fl & 0x80)) finish_multi(r);
    }
    return GZ_OK;
}

static int scan_dir(iso_rd *r, const dir_item *d)
{
    u64 start = (u64)d->lba * r->bs, len = d->size;
    if (start >= r->size) return GZ_OK;                   /* outside the image: empty */
    if (len > r->size - start) len = r->size - start;
    if (len > r->budget) return GZ_E_LIMIT;
    r->budget -= len;
    u32 plen = 0;
    if (d->entry >= 0) {
        const gz_entry *pe = ent(r, d->entry);
        plen = pe->raw_len;
        __builtin_memcpy(r->path, r->a->raw + pe->raw_off, plen);
    }
    r->multi = -1;
    r->cur_entry_kids = 0;
    u64 pos = 0;
    while (pos < len) {
        if (gz_cancelled(r->c)) return GZ_E_CANCEL;
        u64 abs = start + pos, end = abs + DIRBUF;
        end -= end % SEC;                                 /* windows end on sector boundaries */
        if (end > start + len) end = start + len;
        u32 n = (u32)(end - abs);
        int rc = gz_src_read_exact(r->s, abs, r->buf, n);
        if (rc) return rc == GZ_E_TRUNC ? GZ_OK : rc;
        u32 i = 0;
        while (i < n) {
            u32 se = i + (SEC - (u32)((abs + i) % SEC));  /* records never cross sectors */
            if (se > n) se = n;
            while (i < se) {
                u32 rl = r->buf[i];
                if (rl < 34 || rl > se - i) break;        /* 0 = padding, else corrupt: next sector */
                rc = do_record(r, d, r->buf + i, rl, plen);
                if (rc) return rc;
                i += rl;
            }
            i = se;
        }
        pos += n;
        r->done += n;
    }
    finish_multi(r);
    if (d->entry >= 0 && d->entry == r->rr_moved) r->rr_moved_kids += r->cur_entry_kids;
    return GZ_OK;
}

/* ---------------- El Torito ---------------- */

static const char *const k_media[] = { "NoEmul", "1.2M", "1.44M", "2.88M", "HardDisk" };

typedef struct { u8 boot, media; u16 count; u32 rba; u8 vendor[20]; } boot_ent;

static int boot_parse(const u8 *p, boot_ent *b)
{
    if (p[5] != 0 || (p[0] != 0x88 && p[0] != 0)) return 0;
    b->boot = p[0] == 0x88;
    b->media = p[1];
    b->count = rd16(p + 6);
    b->rba = rd32(p + 8);
    __builtin_memcpy(b->vendor, p + 12, 20);
    return 1;
}

static int add_boot(iso_rd *r, u32 cat_lba)
{
    u64 off = (u64)cat_lba * SEC;
    if (off >= r->size) return GZ_OK;
    u32 n = r->size - off < 4 * SEC ? (u32)(r->size - off) : 4 * SEC;
    u8 *cat = r->buf;
    if (n < 64 || gz_src_read_exact(r->s, off, cat, n)) return GZ_OK;
    if (cat[0] != 1 || cat[2] || cat[3] || cat[30] != 0x55 || cat[31] != 0xAA) return GZ_OK;
    u32 sum = 0;
    for (u32 i = 0; i < 32; i += 2) sum += rd16(cat + i);
    if (sum & 0xffff) return GZ_OK;
    boot_ent be[64];
    u32 nb = 0;
    if (!boot_parse(cat + 32, &be[0])) return GZ_OK;
    nb = 1;
    u32 pos = 64;
    while (pos + 32 <= n && nb < 64) {
        u32 hdr = cat[pos];
        if (hdr != 0x90 && hdr != 0x91) break;
        u32 num = rd16(cat + pos + 2);
        pos += 32;
        for (u32 k = 0; k < num && pos + 32 <= n && nb < 64; k++) {
            if (!boot_parse(cat + pos, &be[nb])) { pos = n; break; }
            pos += 32;
            if (be[nb].media & 0x20) {                    /* extension records */
                for (u32 j = 0; pos + 32 <= n; j++) {
                    const u8 *x = cat + pos;
                    pos += 32;
                    if (j > 32 || x[0] != 0x44 || !(x[1] & 0x20)) break;
                }
            }
            nb++;
        }
        if (hdr != 0x90) break;
    }
    for (u32 i = 0; i < nb; i++) {
        char nm[96];
        u32 k = 0;
        const char *s = "[BOOT]/";
        while (*s) nm[k++] = *s++;
        if (nb != 1) {
            u32 v = i + 1;
            char t[4];
            u32 m = 0;
            do { t[m++] = (char)('0' + v % 10); v /= 10; } while (v);
            while (m) nm[k++] = t[--m];
            nm[k++] = '-';
        }
        s = be[i].boot ? "Boot-" : "NotBoot-";
        while (*s) nm[k++] = *s++;
        if (be[i].media < 5) {
            s = k_media[be[i].media];
            while (*s) nm[k++] = *s++;
        } else {
            u32 v = be[i].media;
            char t[4];
            u32 m = 0;
            do { t[m++] = (char)('0' + v % 10); v /= 10; } while (v);
            while (m) nm[k++] = t[--m];
        }
        if (be[i].vendor[0] == 1) {                       /* IBM language / version string */
            u32 j = 1;
            while (j < 20 && be[i].vendor[j] <= 0x7f) j++;
            if (j == 20) {
                nm[k++] = '-';
                for (j = 1; j < 20 && be[i].vendor[j]; j++) {
                    char c = (char)be[i].vendor[j];
                    nm[k++] = (c == '/' || c == '\\') ? '_' : c;
                }
            }
        }
        s = ".img";
        while (*s) nm[k++] = *s++;
        u64 size = (u64)be[i].count * 512;
        if (be[i].media == 1) size = 1200u << 10;
        else if (be[i].media == 2) size = 1440u << 10;
        else if (be[i].media == 3) size = 2880u << 10;
        u64 start = (u64)be[i].rba * SEC;
        if (start >= r->size) size = 0;
        else if (r->size - start < size) size = r->size - start;
        gz_entry *e;
        int rc = gz_arc_add_named(r->a, nm, k, GZ_NE_LEGACY, &e);
        if (rc) return rc;
        e->off = start;
        e->usize = e->csize = size;
        e->flags = F_BOOT;
    }
    return GZ_OK;
}

/* ---------------- open ---------------- */

static void iso_close(gz_archive *a)
{
    iso_priv *p = (iso_priv *)a->priv;
    if (!p) return;
    gz_free(p->runs.r);
    gz_free(p);
    a->priv = 0;
}

/* Rock Ridge in use: SP in the root "." record and RRIP entries there. */
static int detect_rr(iso_rd *r, u32 root_lba)
{
    u8 rec[256];
    u64 off = (u64)root_lba * r->bs;
    if (off >= r->size) return 0;
    u32 n = r->size - off < sizeof rec ? (u32)(r->size - off) : (u32)sizeof rec;
    if (gz_src_read_exact(r->s, off, rec, n)) return 0;
    u32 rl = rec[0];
    if (rl < 34 || rl > n || rec[32] != 1 || rec[33] != 0) return 0;
    const u8 *su = rec + 34;
    u32 sun = rl - 34, skip;
    if (!find_sp(su, sun, &skip)) return 0;
    if (rr_collect(r, su, sun, 0)) return 0;
    if (!r->rr.seen) return 0;
    r->skip = skip;
    return 1;
}

static int iso_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    if (s->size < 17 * SEC) return GZ_E_FORMAT;
    iso_rd *r = (iso_rd *)gz_alloc(sizeof(iso_rd));
    if (!r) return GZ_E_NOMEM;
    r->a = a; r->s = s; r->c = c; r->size = s->size;
    r->multi = -1;
    r->rr_moved = -1;
    r->buf = (u8 *)gz_alloc(DIRBUF);
    r->ce = (u8 *)gz_alloc(MAX_CE_LEN);
    iso_priv *p = (iso_priv *)gz_alloc(sizeof(iso_priv));
    int rc = GZ_E_NOMEM;
    if (!r->buf || !r->ce || !p) { gz_free(p); goto out; }
    a->priv = p;
    r->p = p;
    r->budget = 2 * r->size + (64u << 20);

    /* volume descriptor set */
    u8 *vd = r->buf;                                       /* [0] pvd [1] joliet [2] v2 [3] scratch */
    int have[3] = { 0, 0, 0 };
    u32 boot_cat = 0;
    int have_boot = 0;
    for (u32 i = 0; i < VD_MAX; i++) {
        u64 off = (u64)(16 + i) * SEC;
        u8 *d = vd + 3 * SEC;
        if (off + SEC > r->size || gz_src_read_exact(s, off, d, SEC)) break;
        if (__builtin_memcmp(d + 1, "CD001", 5)) break;
        if (d[0] == 255) break;
        if (d[0] == 0 && !have_boot && !__builtin_memcmp(d + 7, "EL TORITO SPECIFICATION", 23)) {
            boot_cat = rd32(d + 0x47);
            have_boot = 1;
        } else if (d[0] == 1 && !have[0]) {
            __builtin_memcpy(vd, d, SEC);
            have[0] = 1;
        } else if (d[0] == 2) {
            int joliet = !(d[7] & 1) && d[88] == '%' && d[89] == '/' && (d[90] == '@' || d[90] == 'C' || d[90] == 'E');
            if (joliet && !have[1]) { __builtin_memcpy(vd + SEC, d, SEC); have[1] = 1; }
            else if (!joliet && d[6] == 2 && !have[2]) { __builtin_memcpy(vd + 2 * SEC, d, SEC); have[2] = 1; }
        }
    }
    rc = GZ_E_FORMAT;
    if (!have[0] && !have[1] && !have[2]) goto out;

    /* choose the tree */
    int pick = -1;
    if (have[0]) {
        u32 bs = rd16(vd + 128);
        r->bs = (bs == 512 || bs == 1024 || bs == 2048) ? bs : SEC;
        if (detect_rr(r, rd32(vd + 156 + 2) + vd[156 + 1])) { pick = 0; r->tree = T_RR; }
    }
    if (pick < 0 && have[1]) { pick = 1; r->tree = T_JOLIET; }
    if (pick < 0 && have[2]) { pick = 2; r->tree = T_V2; }
    if (pick < 0) { pick = 0; r->tree = T_PRIMARY; }
    const u8 *v = vd + (u32)pick * SEC;
    u32 bs = rd16(v + 128);
    r->bs = (bs == 512 || bs == 1024 || bs == 2048) ? bs : SEC;
    const u8 *root = v + 156;
    if (root[0] < 34) goto out;
    u32 root_lba = rd32(root + 2) + root[1], root_size = rd32(root + 10);
    if ((u64)root_lba * r->bs >= r->size) goto out;
    gz_arc_set_type(a, "ISO");

    rc = visit(r, root_lba);
    if (rc > 1) goto out;
    rc = push_dir(r, root_lba, root_size, 0, -1);
    while (!rc && r->qh < r->qn) {
        dir_item d = r->q[r->qh++];
        if (d.entry >= 0) {
            int seen = visit(r, d.lba);
            if (seen > 1) { rc = seen; break; }
            if (seen) continue;                           /* loop or shared directory */
        }
        rc = scan_dir(r, &d);
        if (c && c->progress && !(r->qh & 63)) c->progress(c->progress_user, r->done, r->size);
    }
    if (rc == GZ_E_LIMIT && a->n) rc = GZ_OK;             /* keep what was listed */
    if (rc) goto out;
    if (have_boot) rc = add_boot(r, boot_cat);
    if (rc) goto out;

    /* hide the Rock Ridge relocation directory when everything in it was moved back */
    if (r->rr_moved >= 0 && !r->rr_moved_kids) {
        u32 k = (u32)r->rr_moved;
        __builtin_memmove(&a->e[k], &a->e[k + 1], (size_t)(a->n - k - 1) * sizeof(gz_entry));
        a->n--;
    }
    rc = GZ_OK;
out:
    if (r) {
        gz_free(r->buf);
        gz_free(r->ce);
        gz_free(r->vis);
        gz_free(r->q);
        gz_free(r);
    }
    return rc;
}

/* ---------------- extraction ---------------- */

static gz_src *iso_view(gz_archive *a, gz_src *s, u32 idx)
{
    gz_entry *e = &a->e[idx];
    if (e->is_dir || e->is_link || (e->flags & F_UNSUP)) return 0;
    if (!(e->flags & F_MULTI)) return gz_src_sub(s, e->off, e->usize);
    iso_priv *p = (iso_priv *)a->priv;
    if (e->aux + e->aux32 > p->runs.n) return 0;
    return xrun_view(s, p->runs.r + e->aux, e->aux32, e->usize);
}

static int iso_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    gz_entry *e = &a->e[idx];
    if (e->flags & F_UNSUP) return GZ_E_METHOD;
    if (!(e->flags & F_MULTI) || e->is_dir || e->is_link) return gz_extract_stored(a, s, idx, e->off, out, c);
    gz_src *v = iso_view(a, s, idx);
    if (!v) return GZ_E_NOMEM;
    int r = gz_extract_stored(a, v, idx, 0, out, c);
    gz_src_free(v);
    return r;
}

static int iso_probe(gz_src *s, const u8 *head, u32 n)
{
    (void)s;
    if (n < 16 * SEC + 7) return 0;
    const u8 *d = head + 16 * SEC;
    if (__builtin_memcmp(d + 1, "CD001", 5) || d[6] > 2) return 0;
    return 80;
}

GZ_FORMAT(gz_fmt_iso)
const gz_format gz_fmt_iso = {
    "ISO", "iso img", 0, iso_probe, iso_open, iso_close, iso_extract, 0, 0, 0, iso_view, 0
};
