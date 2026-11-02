/*
 * 고깃ZIP - Mac OS file systems: HFS+ / HFSX (also inside an HFS wrapper)
 * and classic HFS
 *
 *   volume header at 1024 -> extents overflow B-tree (loaded whole: fragmented
 *   forks), catalog B-tree (leaf nodes walked through their forward links:
 *   folder and file records keyed by parent CNID + UTF-16 name), attributes
 *   B-tree (com.apple.decmpfs records of compressed files).
 *
 *   Entries are listed like 7-Zip: the root folder (volume name) on top, every
 *   path below it. Names stay NFD except Hangul (the core composes it); '/' in
 *   a name becomes ':' as in the macOS POSIX layer. Hidden: the hard link
 *   stores ("\0\0\0\0HFS+ Private Data", ".HFS+ Private Directory Data\r"), the
 *   journal files and the FSEvents log (.fseventsd). File hard links show the iNode file's data, directory
 *   hard links show the target's contents (under the first link to it).
 *   Symlinks (mode 0120000) keep their target from the data fork. Resource
 *   forks are aux entries "name:rsrc".
 *
 *   decmpfs (transparent compression): types 1/9 stored, 3 / 4 zlib, 7 / 8
 *   LZVN, 11 / 12 LZFSE (inline in the attribute / 64 KiB blocks in the
 *   resource fork). The journal is not replayed.
 *
 *   Classic HFS: 512-byte B-tree nodes, Pascal names in Mac Roman, 3 extents
 *   per record, 16-bit block numbers; dates are local time.
 *
 * Hostile volumes: every block range is checked against the volume, B-tree
 * nodes are bounds-checked and visited once (bitmap), extents overflow chains
 * must advance, paths have a depth limit (cycles are dropped) and the number
 * of records is bounded by the catalog size.
 *
 * Entry fields: off = catalog record location (node << 16 | offset in node) of
 * the file whose data is shown, aux32 = its CNID, aux = only extent (start <<
 * 32 | count) when F_ONEEXT, method = decmpfs type, flags = F_*.
 */
#include "fs1.h"
#include "vdisk.h"
#include "hfs.h"
#include "lzfse.h"

#define HFS_EPOCH      2082844800u    /* 1904-01-01 -> 1970-01-01 */
#define MAX_DEPTH      512u
#define MAX_XRECS      (4u << 20)
#define MAX_CMP_INLINE (64u << 20)    /* decoded inline decmpfs data */
#define CMP_BLOCK      65536u
#define LINK_MAX       4095u
#define MAX_PATHS      (96u << 20)    /* gzch units of folder paths kept while listing */

enum {
    F_ONEEXT = 1,      /* aux holds the only extent of the fork               */
    F_RSRC = 2,        /* entry is a resource fork                            */
    F_CMP = 4,         /* decmpfs compressed, method = type                   */
    F_BROKEN = 8,      /* hard link without its iNode                         */
};

typedef struct { u32 start, count; } hfs_ext;

typedef struct {
    u64 size;          /* logical bytes                     */
    u32 blocks;        /* allocated blocks                  */
    u32 fileid;
    u8 fork;           /* 0 data, 0xFF resource             */
    hfs_ext e[8];      /* first extents (classic: 3)        */
} hfs_fork;

typedef struct { u32 fileid, start; u8 fork; hfs_ext e[8]; } hfs_xrec;

typedef struct {
    u32 fileid, type;  /* decmpfs compression type, 0 = attribute is not inline */
    u64 usize;
    u32 node;          /* location of the attribute record                      */
    u32 asize;         /* attribute value bytes (header + inline data)          */
    u16 off;
} hfs_cmp;

typedef struct {
    int classic, hfsx;
    u64 base;          /* byte offset of allocation block 0 */
    u32 bs, nblocks;
    hfs_fork ext, cat, attr;
    u32 cat_ns, attr_ns;
    hfs_xrec *xr;
    u32 nxr;
    hfs_cmp *cmp;
    u32 ncmp;
} hfs_vol;

const u16 gz_macroman_hi[128] = {
    0xC4, 0xC5, 0xC7, 0xC9, 0xD1, 0xD6, 0xDC, 0xE1, 0xE0, 0xE2, 0xE4, 0xE3, 0xE5, 0xE7, 0xE9, 0xE8,
    0xEA, 0xEB, 0xED, 0xEC, 0xEE, 0xEF, 0xF1, 0xF3, 0xF2, 0xF4, 0xF6, 0xF5, 0xFA, 0xF9, 0xFB, 0xFC,
    0x2020, 0xB0, 0xA2, 0xA3, 0xA7, 0x2022, 0xB6, 0xDF, 0xAE, 0xA9, 0x2122, 0xB4, 0xA8, 0x2260, 0xC6, 0xD8,
    0x221E, 0xB1, 0x2264, 0x2265, 0xA5, 0xB5, 0x2202, 0x2211, 0x220F, 0x3C0, 0x222B, 0xAA, 0xBA, 0x3A9, 0xE6, 0xF8,
    0xBF, 0xA1, 0xAC, 0x221A, 0x192, 0x2248, 0x2206, 0xAB, 0xBB, 0x2026, 0xA0, 0xC0, 0xC3, 0xD5, 0x152, 0x153,
    0x2013, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0xF7, 0x25CA, 0xFF, 0x178, 0x2044, 0x20AC, 0x2039, 0x203A, 0xFB01, 0xFB02,
    0x2021, 0xB7, 0x201A, 0x201E, 0x2030, 0xC2, 0xCA, 0xC1, 0xCB, 0xC8, 0xCD, 0xCE, 0xCF, 0xCC, 0xD3, 0xD4,
    0xF8FF, 0xD2, 0xDA, 0xDB, 0xD9, 0x131, 0x2C6, 0x2DC, 0xAF, 0x2D8, 0x2D9, 0x2DA, 0xB8, 0x2DD, 0x2DB, 0x2C7,
};

/* ---------------- forks ---------------- */

/* HFS+ fork data (80 bytes) */
static void fork_plus(hfs_fork *f, const u8 *p, u32 fileid, u8 fork)
{
    f->size = rd64be(p);
    f->blocks = rd32be(p + 12);
    f->fileid = fileid;
    f->fork = fork;
    for (u32 i = 0; i < 8; i++) { f->e[i].start = rd32be(p + 16 + 8 * i); f->e[i].count = rd32be(p + 20 + 8 * i); }
}

/* classic extent record: 3 x {u16 start, u16 count} */
static void ext_classic(hfs_ext *e, const u8 *p)
{
    for (u32 i = 0; i < 8; i++) {
        e[i].start = i < 3 ? rd16be(p + 4 * i) : 0;
        e[i].count = i < 3 ? rd16be(p + 4 * i + 2) : 0;
    }
}

static void fork_classic(const hfs_vol *v, hfs_fork *f, u32 lsize, u32 psize, const u8 *ext, u32 fileid, u8 fork)
{
    f->size = lsize;
    f->blocks = (u32)(((u64)psize + v->bs - 1) / v->bs);
    f->fileid = fileid;
    f->fork = fork;
    ext_classic(f->e, ext);
}

static const hfs_xrec *find_xrec(const hfs_vol *v, u32 fileid, u8 fork, u32 start)
{
    u32 lo = 0, hi = v->nxr;
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        const hfs_xrec *x = &v->xr[mid];
        int lt = x->fileid != fileid ? x->fileid < fileid : x->fork != fork ? x->fork < fork : x->start < start;
        if (lt) lo = mid + 1; else hi = mid;
    }
    if (lo < v->nxr) {
        const hfs_xrec *x = &v->xr[lo];
        if (x->fileid == fileid && x->fork == fork && x->start == start) return x;
    }
    return 0;
}

/* Emit the byte runs of a fork (clipped to its logical size by the sink limit). */
static int fork_runs(const hfs_vol *v, const hfs_fork *f, gz_fs1_sink *k)
{
    const hfs_ext *e = f->e;
    u32 done = 0;
    for (u32 round = 0; round <= v->nxr; round++) {
        for (u32 i = 0; i < 8; i++) {
            u32 st = e[i].start, n = e[i].count;
            if (!n) return k->pos >= k->limit ? GZ_OK : GZ_E_DATA;
            if (st >= v->nblocks || n > v->nblocks - st) return GZ_E_DATA;
            int r = gz_fs1_emit(k, v->base + (u64)st * v->bs, (u64)n * v->bs);
            if (r) return r == GZ_FS1_FULL ? GZ_OK : r;
            if (n > 0xFFFFFFFFu - done) return GZ_E_DATA;
            done += n;
        }
        const hfs_xrec *x = find_xrec(v, f->fileid, f->fork, done);
        if (!x) break;
        e = x->e;
    }
    return k->pos >= k->limit ? GZ_OK : GZ_E_DATA;
}

/* Random-access source over a fork (NULL on error, *err set). */
static gz_src *fork_src(const hfs_vol *v, gz_src *s, const hfs_fork *f, int *err)
{
    gz_fs1_list l;
    gz_fs1_list_init(&l, f->size, 1u << 20);
    int r = fork_runs(v, f, &l.k);
    if (!r) r = gz_fs1_flush(&l.k, 1);
    if (r) { gz_fs1_list_free(&l); *err = r; return 0; }
    gz_src *src = gz_fs1_list_src(s, &l);
    if (!src) *err = GZ_E_NOMEM;
    return src;
}

/* Read a whole small fork into memory (limit bytes at most). */
static int fork_read(const hfs_vol *v, gz_src *s, const hfs_fork *f, u64 limit, u8 **out, u32 *n)
{
    *out = 0;
    *n = 0;
    if (f->size > limit) return GZ_E_LIMIT;
    gz_fs1_mem m;
    gz_fs1_mem_init(&m, s, f->size);
    int r = fork_runs(v, f, &m.k);
    if (!r) r = gz_fs1_flush(&m.k, 1);
    if (r || m.k.flushed != f->size) { gz_free(m.p); return r ? r : GZ_E_DATA; }
    *out = m.p;
    *n = (u32)f->size;
    return GZ_OK;
}

/* ---------------- B-trees ---------------- */

typedef struct {
    gz_src *src;          /* the fork                                 */
    u32 ns, nnodes;
    u32 first_leaf;
    u8 key_cmp;           /* catalog: 0xBC binary (case-sensitive HFSX) */
    u8 *win;              /* read-ahead window of whole nodes          */
    u64 win_node;
    u32 win_n, win_cap;   /* nodes in the window / capacity             */
    u8 *seen;             /* visited leaves                              */
} hfs_bt;

static void bt_close(hfs_bt *b)
{
    gz_src_free(b->src);
    gz_free(b->win);
    gz_free(b->seen);
    __builtin_memset(b, 0, sizeof *b);
}

static int bt_open(hfs_bt *b, const hfs_vol *v, gz_src *s, const hfs_fork *f)
{
    __builtin_memset(b, 0, sizeof *b);
    int r = GZ_OK;
    if (!f->size) return GZ_E_FORMAT;
    if (!(b->src = fork_src(v, s, f, &r))) return r;
    u8 h[512];
    if (b->src->size < 512 || (r = gz_src_read_exact(b->src, 0, h, 512))) return r ? r : GZ_E_FORMAT;
    if (h[8] != 1) return GZ_E_FORMAT;                                /* header node */
    const u8 *hr = h + 14;
    u32 ns = rd16be(hr + 18);
    if (ns < 512 || ns > 32768 || (ns & (ns - 1)) || (v->classic && ns != 512)) return GZ_E_FORMAT;
    u64 total = b->src->size / ns;                    /* nodes the fork really has */
    if (s->size / ns < total) total = s->size / ns;   /* ... and the volume can hold */
    if (rd32be(hr + 22) < total) total = rd32be(hr + 22);
    b->ns = ns;
    b->nnodes = (u32)total;
    b->first_leaf = rd32be(hr + 10);
    b->key_cmp = hr[37];
    b->win_cap = ns >= (128u << 10) ? 1 : (128u << 10) / ns;
    b->win = (u8 *)gz_alloc((size_t)b->win_cap * ns);
    b->seen = (u8 *)gz_alloc(total / 8 + 1);
    if (!b->win || !b->seen) return GZ_E_NOMEM;
    return GZ_OK;
}

static int bt_node(hfs_bt *b, u32 idx, const u8 **nd)
{
    if (idx >= b->nnodes) return GZ_E_FORMAT;
    if (!b->win_n || idx < b->win_node || idx >= b->win_node + b->win_n) {
        u32 n = b->nnodes - idx < b->win_cap ? b->nnodes - idx : b->win_cap;
        b->win_n = 0;
        int r = gz_src_read_exact(b->src, (u64)idx * b->ns, b->win, n * b->ns);
        if (r) return r;
        b->win_node = idx;
        b->win_n = n;
    }
    *nd = b->win + (size_t)(idx - b->win_node) * b->ns;
    return GZ_OK;
}

/* Number of valid records of a node (record offsets ascending inside the node). */
static u32 node_recs(const u8 *nd, u32 ns)
{
    u32 n = rd16be(nd + 10);
    if (14 + 2 * (n + 1) > ns) return 0;
    u32 lim = ns - 2 * (n + 1), prev = 13;
    for (u32 i = 0; i <= n; i++) {
        u32 o = rd16be(nd + ns - 2 * (i + 1));
        if (o <= prev || o > lim) return i ? i - 1 : 0;              /* keep the intact prefix */
        prev = o;
    }
    return n;
}

static void node_rec(const u8 *nd, u32 ns, u32 i, const u8 **p, u32 *len)
{
    u32 o = rd16be(nd + ns - 2 * (i + 1)), e = rd16be(nd + ns - 2 * (i + 2));
    *p = nd + o;
    *len = e - o;
}

/* Next leaf node of the forward chain: 1 = got one, 0 = end. */
static int bt_next(hfs_bt *b, u32 *cur, const u8 **nd, u32 *nrec, int *err)
{
    *err = GZ_OK;
    u32 idx = *cur;
    if (!idx || idx >= b->nnodes || (b->seen[idx >> 3] & (1u << (idx & 7)))) return 0;
    b->seen[idx >> 3] |= (u8)(1u << (idx & 7));
    int r = bt_node(b, idx, nd);
    if (r) { *err = r; return 0; }
    if ((*nd)[8] != 0xFF) return 0;                                   /* not a leaf */
    *cur = rd32be(*nd);
    *nrec = node_recs(*nd, b->ns);
    return 1;
}

/* Key and data of a leaf record. HFS+: u16 key length; classic: u8, data padded to even. */
static int rec_split(int classic, const u8 *p, u32 len, u32 *klen, const u8 **d, u32 *dlen)
{
    u32 kl, doff;
    if (classic) {
        if (len < 2 || !p[0]) return 0;
        kl = p[0];
        doff = (kl + 2) & ~1u;
    } else {
        if (len < 2) return 0;
        kl = rd16be(p);
        doff = (kl + 3) & ~1u;
    }
    if (doff > len) return 0;
    *klen = kl;
    *d = p + doff;
    *dlen = len - doff;
    return 1;
}

/* ---------------- extents overflow / attributes ---------------- */

static int load_xrecs(hfs_vol *v, gz_src *s, gz_ctx *c)
{
    if (!v->ext.size) return GZ_OK;
    hfs_bt b;
    int r = bt_open(&b, v, s, &v->ext), err = GZ_OK;
    if (r) { bt_close(&b); return r == GZ_E_NOMEM ? r : GZ_OK; }     /* volume still listable */
    u32 cur = b.first_leaf, cap = 0, nrec;
    const u8 *nd;
    while (bt_next(&b, &cur, &nd, &nrec, &err)) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        for (u32 i = 0; i < nrec; i++) {
            const u8 *p, *d;
            u32 len, kl, dl;
            node_rec(nd, b.ns, i, &p, &len);
            if (!rec_split(v->classic, p, len, &kl, &d, &dl)) continue;
            hfs_xrec x;
            if (v->classic) {
                if (kl < 7 || dl < 12) continue;
                x.fork = p[1]; x.fileid = rd32be(p + 2); x.start = rd16be(p + 6);
                ext_classic(x.e, d);
            } else {
                if (kl < 10 || dl < 64) continue;
                x.fork = p[2]; x.fileid = rd32be(p + 4); x.start = rd32be(p + 8);
                for (u32 j = 0; j < 8; j++) { x.e[j].start = rd32be(d + 8 * j); x.e[j].count = rd32be(d + 8 * j + 4); }
            }
            if (v->nxr >= MAX_XRECS) { r = GZ_E_LIMIT; break; }
            if (v->nxr == cap) {
                u32 nc = cap ? cap * 2 : 64;
                hfs_xrec *nx = (hfs_xrec *)gz_realloc(v->xr, (size_t)nc * sizeof(hfs_xrec));
                if (!nx) { r = GZ_E_NOMEM; break; }
                v->xr = nx;
                cap = nc;
            }
            v->xr[v->nxr++] = x;
        }
        if (r) break;
    }
    bt_close(&b);
    return r;
}

static int is_decmpfs(const u8 *name, u32 n)
{
    static const char t[] = "com.apple.decmpfs";
    if (n != 17) return 0;
    for (u32 i = 0; i < 17; i++) if (rd16be(name + 2 * i) != (u8)t[i]) return 0;
    return 1;
}

/* collect the com.apple.decmpfs attributes (sorted by file ID like the tree) */
static int load_cmp(hfs_vol *v, gz_src *s, gz_ctx *c)
{
    if (v->classic || !v->attr.size) return GZ_OK;
    hfs_bt b;
    int r = bt_open(&b, v, s, &v->attr), err = GZ_OK;
    if (r) { bt_close(&b); return r == GZ_E_NOMEM ? r : GZ_OK; }
    v->attr_ns = b.ns;
    u32 cur = b.first_leaf, cap = 0, nrec, node = cur;
    const u8 *nd;
    while (bt_next(&b, &cur, &nd, &nrec, &err)) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        for (u32 i = 0; i < nrec; i++) {
            const u8 *p, *d;
            u32 len, kl, dl;
            node_rec(nd, b.ns, i, &p, &len);
            if (!rec_split(0, p, len, &kl, &d, &dl) || kl < 12) continue;
            u32 nl = rd16be(p + 12);
            if (14 + 2 * nl > kl + 2 || !is_decmpfs(p + 14, nl) || dl < 4) continue;
            hfs_cmp m;
            m.fileid = rd32be(p + 4);
            m.type = 0;
            m.usize = 0;
            m.node = node;
            m.asize = 0;
            m.off = (u16)(p - nd);
            if (rd32be(d) == 0x10 && dl >= 16 + 16) {
                u32 asz = rd32be(d + 12);
                const u8 *h = d + 16;
                if (asz >= 16 && asz <= dl - 16 && rd32(h) == 0x636D7066u) {        /* "fpmc" */
                    m.type = rd32(h + 4);
                    m.usize = rd64(h + 8);
                    m.asize = asz;
                }
            }
            if (v->ncmp && v->cmp[v->ncmp - 1].fileid >= m.fileid) continue;   /* keep sorted */
            if (v->ncmp >= MAX_XRECS) { r = GZ_E_LIMIT; break; }
            if (v->ncmp == cap) {
                u32 nc = cap ? cap * 2 : 64;
                hfs_cmp *nx = (hfs_cmp *)gz_realloc(v->cmp, (size_t)nc * sizeof(hfs_cmp));
                if (!nx) { r = GZ_E_NOMEM; break; }
                v->cmp = nx;
                cap = nc;
            }
            v->cmp[v->ncmp++] = m;
        }
        node = cur;
        if (r) break;
    }
    bt_close(&b);
    return r;
}

static const hfs_cmp *find_cmp(const hfs_vol *v, u32 fileid)
{
    u32 lo = 0, hi = v->ncmp;
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        if (v->cmp[mid].fileid < fileid) lo = mid + 1; else hi = mid;
    }
    return lo < v->ncmp && v->cmp[lo].fileid == fileid ? &v->cmp[lo] : 0;
}

static int cmp_supported(u32 t)
{
    return t == 1 || t == 3 || t == 4 || t == 7 || t == 8 || t == 9 || t == 11 || t == 12;
}

static int cmp_in_rsrc(u32 t) { return t == 4 || t == 8 || t == 12; }

/* ---------------- listing ---------------- */

typedef struct {
    u32 cnid, parent;
    u32 name_off;             /* gzch units in w->names                        */
    u16 name_len;
    u8 folder;                /* folder record (or directory hard link)         */
    u8 state;                 /* path: 0 todo, 1 busy, 2 done, 3 hidden         */
    u8 special;               /* 1/2 file / directory hard link store, 3 journal file, 4 .fseventsd */
    u8 lkind;                 /* 1 file hard link, 2 directory hard link        */
    u8 rsrc;                  /* file has a resource fork (listed as an aux entry) */
    u32 link;                 /* inode number of a hard link                    */
    u32 rblocks;              /* resource fork: allocated blocks, logical size   */
    u64 rsize;
    u32 path_off, path_len;   /* folders: full path in w->paths                 */
    i32 alias;                /* dir_N folder: item of the first link to it     */
} hfs_item;

typedef struct {
    gz_archive *a;
    hfs_vol *v;
    gz_src *s;
    gz_ctx *c;
    hfs_item *it;
    u32 nit, capit;
    gzch *names;
    u32 nnames, capnames;
    gzch *paths;
    u32 npaths, cappaths;
    u32 *hk, *hv, hcap;       /* folder CNID -> item + 1 */
    u32 priv_file, priv_dir;  /* CNIDs of the hard link stores (0 = none) */
    u64 link_budget;          /* symlink target bytes still read at open      */
    hfs_bt cat;
} hfs_walk;

static int grow(void **p, u32 *cap, u32 need, size_t esz)
{
    if (need <= *cap) return GZ_OK;
    if (need > (1u << 28)) return GZ_E_LIMIT;
    u32 nc = *cap ? *cap : 256;
    while (nc < need) nc *= 2;
    void *np = gz_realloc(*p, (size_t)nc * esz);
    if (!np) return GZ_E_NOMEM;
    *p = np;
    *cap = nc;
    return GZ_OK;
}

static int hmap_put(hfs_walk *w, u32 key, u32 val)
{
    if ((w->nit + 1) * 2 > w->hcap) {
        u32 nc = w->hcap ? w->hcap * 2 : 1024;
        u32 *nk = (u32 *)gz_alloc((size_t)nc * 4), *nv = (u32 *)gz_alloc((size_t)nc * 4);
        if (!nk || !nv) { gz_free(nk); gz_free(nv); return GZ_E_NOMEM; }
        for (u32 i = 0; i < w->hcap; i++) {
            if (!w->hv[i]) continue;
            u32 h = (w->hk[i] * 0x9E3779B1u) & (nc - 1);
            while (nv[h]) h = (h + 1) & (nc - 1);
            nk[h] = w->hk[i];
            nv[h] = w->hv[i];
        }
        gz_free(w->hk);
        gz_free(w->hv);
        w->hk = nk;
        w->hv = nv;
        w->hcap = nc;
    }
    u32 h = (key * 0x9E3779B1u) & (w->hcap - 1);
    while (w->hv[h]) {
        if (w->hk[h] == key) return GZ_OK;            /* first record wins */
        h = (h + 1) & (w->hcap - 1);
    }
    w->hk[h] = key;
    w->hv[h] = val + 1;
    return GZ_OK;
}

static i32 hmap_get(const hfs_walk *w, u32 key)
{
    if (!w->hcap) return -1;
    u32 h = (key * 0x9E3779B1u) & (w->hcap - 1);
    while (w->hv[h]) {
        if (w->hk[h] == key) return (i32)w->hv[h] - 1;
        h = (h + 1) & (w->hcap - 1);
    }
    return -1;
}

/* seconds since 1904 (HFS+: UTC; classic HFS: local time, shown as UTC) */
static void set_time(gz_entry *e, u32 t)
{
    if (!t) return;
    e->mtime = gz_unix_to_filetime((i64)t - HFS_EPOCH);
    e->mtime_kind = GZ_MT_FILETIME;
}

static int name_is(const gzch *n, u32 len, const char *s)
{
    u32 i = 0;
    for (; s[i]; i++) if (i >= len || n[i] != (u8)s[i]) return 0;
    return i == len;
}

/* "iNode123" / "dir_123" -> 123 (0 when not that form) */
static u32 name_num(const gzch *n, u32 len, const char *pre)
{
    u32 i = 0, v = 0;
    for (; pre[i]; i++) if (i >= len || n[i] != (u8)pre[i]) return 0;
    if (i == len) return 0;
    for (; i < len; i++) {
        if (n[i] < '0' || n[i] > '9' || v > 400000000u) return 0;
        v = v * 10 + (n[i] - '0');
    }
    return v;
}

/* Symlink target from the data fork into a->raw (else the target stays the entry data). */
static void read_link(hfs_walk *w, gz_entry *e, const hfs_fork *f)
{
    if (!f->size || f->size > LINK_MAX || f->size > w->link_budget) return;
    w->link_budget -= f->size;
    u8 *p;
    u32 n, off;
    if (fork_read(w->v, w->s, f, LINK_MAX, &p, &n)) return;
    if (!gz_arc_raw_append(w->a, p, n, &off)) {
        e->link_off = off;
        e->link_len = n;
        e->usize = e->csize = 0;
    }
    gz_free(p);
}

static int add_record(hfs_walk *w, const u8 *key, u32 klen, const u8 *d, u32 dl, u32 node, u32 roff)
{
    hfs_vol *v = w->v;
    int classic = v->classic;
    u32 parent, nlen, type, cnid;
    const u8 *nm;
    if (classic) {
        if (klen < 6) return GZ_OK;
        parent = rd32be(key + 2);
        nlen = key[6];
        nm = key + 7;
        if (6 + nlen > klen || dl < 2) return GZ_OK;
        type = d[0];
        if (type == 1 && dl >= 70) cnid = rd32be(d + 6);
        else if (type == 2 && dl >= 102) cnid = rd32be(d + 20);
        else return GZ_OK;
    } else {
        if (klen < 6) return GZ_OK;
        parent = rd32be(key + 2);
        nlen = rd16be(key + 6);
        nm = key + 8;
        if (nlen > 255 || 6 + 2 * nlen > klen || dl < 2) return GZ_OK;
        type = rd16be(d);
        if (type == 1 && dl >= 88) cnid = rd32be(d + 8);
        else if (type == 2 && dl >= 248) cnid = rd32be(d + 8);
        else return GZ_OK;
    }
    int r;
    if ((r = grow((void **)&w->it, &w->capit, w->nit + 1, sizeof(hfs_item)))) return r;
    if ((r = grow((void **)&w->names, &w->capnames, w->nnames + nlen + 1, sizeof(gzch)))) return r;
    hfs_item *it = &w->it[w->nit];
    __builtin_memset(it, 0, sizeof *it);
    it->cnid = cnid;
    it->parent = parent;
    it->name_off = w->nnames;
    it->name_len = (u16)nlen;
    it->folder = type == 1;
    it->alias = -1;
    gzch *o = w->names + w->nnames;
    int zeros = 0;
    for (u32 i = 0; i < nlen; i++) {
        u32 ch = classic ? (nm[i] < 0x80 ? nm[i] : gz_macroman_hi[nm[i] - 0x80]) : rd16be(nm + 2 * i);
        if (!ch) { zeros++; ch = '_'; }
        else if (ch == '/') ch = ':';
        o[i] = (gzch)ch;
    }
    w->nnames += nlen;
    if (parent == 2) {
        if (!classic && type == 1 && zeros == 4 && name_is(o + 4, nlen - 4, "HFS+ Private Data")) {
            it->special = 1;
            w->priv_file = cnid;
        } else if (type == 1 && name_is(o, nlen, ".HFS+ Private Directory Data\r")) {
            it->special = 2;
            w->priv_dir = cnid;
        } else if (type == 2 && (name_is(o, nlen, ".journal") || name_is(o, nlen, ".journal_info_block"))) {
            it->special = 3;
        } else if (type == 1 && name_is(o, nlen, ".fseventsd")) {
            it->special = 4;                                       /* FSEvents log: metadata */
        }
    }

    gz_entry *e;
    if ((r = gz_arc_add_entry(w->a, &e))) return r;
    w->nit++;
    e->off = (u64)node << 16 | roff;
    e->aux32 = cnid;
    e->name_enc = GZ_NE_UTF16LE;
    if (type == 1) {
        if ((r = hmap_put(w, cnid, w->nit - 1))) return r;
        e->is_dir = 1;
        e->attr = 0x10;
        e->unix_mode = 040755;
        if (classic) set_time(e, rd32be(d + 14));
        else {
            set_time(e, rd32be(d + 16));
            u32 mode = rd16be(d + 32 + 10);
            if ((mode & 0170000) == 040000) e->unix_mode = mode;
            if (rd16be(d + 48 + 8) & 0x4000) e->attr |= 2;            /* Finder: invisible */
        }
        return GZ_OK;
    }

    /* file record */
    hfs_fork df, rf;
    e->attr = 0;
    e->unix_mode = 0100644;
    if (classic) {
        if (d[2] & 1) e->attr |= 1;                                    /* locked */
        if (rd16be(d + 4 + 8) & 0x4000) e->attr |= 2;
        set_time(e, rd32be(d + 48));
        fork_classic(v, &df, rd32be(d + 26), rd32be(d + 30), d + 74, cnid, 0);
        fork_classic(v, &rf, rd32be(d + 36), rd32be(d + 40), d + 86, cnid, 0xFF);
    } else {
        u16 fl = rd16be(d + 2);
        const u8 *perm = d + 32, *fi = d + 48;
        u32 mode = rd16be(perm + 10);
        if (fl & 1) e->attr |= 1;
        if (rd16be(fi + 8) & 0x4000) e->attr |= 2;                    /* Finder: invisible */
        if ((mode & 0170000) == 0100000 || (mode & 0170000) == 0120000) e->unix_mode = mode;
        set_time(e, rd32be(d + 16));
        fork_plus(&df, d + 88, cnid, 0);
        fork_plus(&rf, d + 168, cnid, 0xFF);
        u32 ftype = rd32be(fi), creator = rd32be(fi + 4);
        if (ftype == 0x686C6E6Bu && creator == 0x6866732Bu) {                /* hlnk/hfs+ */
            it->lkind = 1;
            it->link = rd32be(perm + 12);
        } else if (ftype == 0x66647270u && creator == 0x4D414353u && (fl & 0x20)) {   /* fdrp/MACS */
            it->lkind = 2;
            it->link = rd32be(perm + 12);
            e->is_dir = 1;
            e->attr = 0x10;
            e->unix_mode = 040755;
            return GZ_OK;
        }
        if (perm[9] & 0x20) {                                          /* UF_COMPRESSED */
            const hfs_cmp *m = find_cmp(v, cnid);
            if (m) {
                e->flags |= F_CMP;
                e->method = (u16)(m->type ? m->type : 0xFFFF);
                e->usize = m->usize;
                e->csize = cmp_in_rsrc(m->type) ? rf.size : m->asize;
                if ((e->unix_mode & 0170000) == 0120000) e->is_link = 1;  /* target = data */
                return GZ_OK;
            }
        }
    }
    e->usize = df.size;
    e->csize = (u64)df.blocks * v->bs;
    if (df.e[0].count && df.e[0].count == df.blocks && df.e[0].count >= (df.size + v->bs - 1) / v->bs) {
        e->flags |= F_ONEEXT;
        e->aux = (u64)df.e[0].start << 32 | df.e[0].count;
    }
    if ((e->unix_mode & 0170000) == 0120000) {
        e->is_link = 1;
        read_link(w, e, &df);
    }
    /* a resource fork: aux entry added once the paths are known */
    if (rf.size && !it->lkind) { it->rsrc = 1; it->rsize = rf.size; it->rblocks = rf.blocks; }
    return GZ_OK;
}

static int scan_catalog(hfs_walk *w)
{
    hfs_bt *b = &w->cat;
    u32 cur = b->first_leaf, nrec, node = cur, nodes = 0;
    const u8 *nd;
    int err = GZ_OK, r = GZ_OK;
    while (bt_next(b, &cur, &nd, &nrec, &err)) {
        if (gz_cancelled(w->c)) return GZ_E_CANCEL;
        if (w->c && w->c->progress && !(++nodes & 255)) w->c->progress(w->c->progress_user, nodes, b->nnodes);
        for (u32 i = 0; i < nrec && !r; i++) {
            const u8 *p, *d;
            u32 len, kl, dl;
            node_rec(nd, b->ns, i, &p, &len);
            if (!rec_split(w->v->classic, p, len, &kl, &d, &dl)) continue;
            /* nd stays valid: only bt_next moves the catalog window (symlink
             * targets are read from the volume directly) */
            r = add_record(w, p, kl, d, dl, node, (u32)(p - nd));
        }
        if (r) return r;
        node = cur;
    }
    return err;
}

/* Full path of folder item i0 into w->paths (memoised). 0 = ok, -1 hidden / orphan,
 * > 0 error. A dir_N folder (directory hard link target) takes the parent and name
 * of its first link. */
static int folder_path(hfs_walk *w, u32 i0)
{
    u32 chain[MAX_DEPTH + 1];
    u32 n = 0, i = i0;
    int hidden = 0;
    /* walk up to the root or a folder whose path is known */
    for (;;) {
        hfs_item *it = &w->it[i];
        if (it->state == 2) break;
        if (it->state != 0 || n > MAX_DEPTH) { hidden = 1; break; }
        it->state = 1;
        chain[n++] = i;
        if (it->alias < 0 && (it->special == 1 || it->special == 2 || it->special == 4)) { hidden = 1; break; }
        if (it->alias < 0 && it->cnid == 2) { i = 0xFFFFFFFFu; break; }   /* root folder */
        const hfs_item *src = it->alias >= 0 ? &w->it[(u32)it->alias] : it;
        i32 p = hmap_get(w, src->parent);
        if (p < 0) { hidden = 1; break; }
        i = (u32)p;
    }
    if (hidden) {
        while (n) w->it[chain[--n]].state = 3;
        return -1;
    }
    /* build the paths downwards */
    while (n) {
        hfs_item *it = &w->it[chain[--n]];
        const hfs_item *src = it->alias >= 0 ? &w->it[(u32)it->alias] : it;
        u32 base_off = 0, base_len = 0;
        if (i != 0xFFFFFFFFu) { base_off = w->it[i].path_off; base_len = w->it[i].path_len; }
        u32 need = base_len + 1 + src->name_len;
        if (w->npaths + need > MAX_PATHS) return GZ_E_LIMIT;
        int r = grow((void **)&w->paths, &w->cappaths, w->npaths + need, sizeof(gzch));
        if (r) return r;
        gzch *o = w->paths + w->npaths;
        u32 k = 0;
        for (u32 j = 0; j < base_len; j++) o[k++] = w->paths[base_off + j];
        if (base_len) o[k++] = '/';
        for (u32 j = 0; j < src->name_len; j++) o[k++] = w->names[src->name_off + j];
        it->path_off = w->npaths;
        it->path_len = k;
        it->state = 2;
        w->npaths += k;
        i = (u32)(it - w->it);
    }
    return 0;
}

static int set_name(hfs_walk *w, gz_entry *e, const gzch *dir, u32 dl, const gzch *nm, u32 nl, const char *suffix)
{
    u32 sl = 0;
    while (suffix && suffix[sl]) sl++;
    u32 total = (dl ? dl + 1 : 0) + nl + sl;
    gzch tmp[640];
    u32 off, k = 0;
    int r;
    if (total <= GZ_COUNTOF(tmp)) {
        for (u32 j = 0; j < dl; j++) tmp[k++] = dir[j];
        if (dl) tmp[k++] = '/';
        for (u32 j = 0; j < nl; j++) tmp[k++] = nm[j];
        for (u32 j = 0; j < sl; j++) tmp[k++] = (u8)suffix[j];
        r = gz_arc_raw_append(w->a, tmp, (size_t)k * 2, &off);
    } else {
        /* deep path: append the pieces directly (adjacent in a->raw) */
        u32 o2;
        r = gz_arc_raw_append(w->a, dir, (size_t)dl * 2, &off);
        if (!r && dl) r = gz_arc_raw_append(w->a, u"/", 2, &o2);
        if (!r) r = gz_arc_raw_append(w->a, nm, (size_t)nl * 2, &o2);
        for (u32 j = 0; !r && j < sl; j++) { gzch ch = (u8)suffix[j]; r = gz_arc_raw_append(w->a, &ch, 2, &o2); }
        k = total;
    }
    if (r) return r;
    e->raw_off = off;
    e->raw_len = k * 2;
    e->name_enc = GZ_NE_UTF16LE;
    return GZ_OK;
}

/* hard links: copy what describes the data from the iNode file */
static int resolve_links(hfs_walk *w)
{
    gz_archive *a = w->a;
    if (!w->priv_file && !w->priv_dir) return GZ_OK;
    /* inode number -> item, in a second map built over the same table */
    u32 cap = 64;
    while (cap < w->nit * 2) cap *= 2;
    u32 *k = (u32 *)gz_alloc((size_t)cap * 4), *val = (u32 *)gz_alloc((size_t)cap * 4);
    if (!k || !val) { gz_free(k); gz_free(val); return GZ_E_NOMEM; }
    for (u32 i = 0; i < w->nit; i++) {
        const hfs_item *it = &w->it[i];
        u32 num = 0, kind = 0;
        if (w->priv_file && it->parent == w->priv_file && !it->folder) {
            num = name_num(w->names + it->name_off, it->name_len, "iNode");
            kind = 1;
        } else if (w->priv_dir && it->parent == w->priv_dir && it->folder) {
            num = name_num(w->names + it->name_off, it->name_len, "dir_");
            kind = 2;
        }
        if (!num) continue;
        u32 key = num << 1 | (kind - 1), h = (key * 0x9E3779B1u) & (cap - 1);
        while (val[h] && k[h] != key) h = (h + 1) & (cap - 1);
        if (!val[h]) { k[h] = key; val[h] = i + 1; }
    }
    for (u32 i = 0; i < w->nit; i++) {
        hfs_item *it = &w->it[i];
        if (!it->lkind || !it->link || it->link > 0x7FFFFFFFu) continue;
        u32 key = it->link << 1 | (it->lkind - 1u), h = (key * 0x9E3779B1u) & (cap - 1);
        while (val[h] && k[h] != key) h = (h + 1) & (cap - 1);
        gz_entry *e = &a->e[i];
        if (!val[h]) {
            if (it->lkind == 1) { e->flags |= F_BROKEN; e->usize = 0; }
            continue;
        }
        u32 t = val[h] - 1;
        if (it->lkind == 2) {
            if (w->it[t].alias < 0) w->it[t].alias = (i32)i;   /* first link shows the contents */
            continue;
        }
        const gz_entry *src = &a->e[t];
        e->usize = src->usize;
        e->csize = src->csize;
        e->off = src->off;
        e->aux = src->aux;
        e->aux32 = src->aux32;
        e->method = src->method;
        e->flags = src->flags;
        e->unix_mode = src->unix_mode;
        e->mtime = src->mtime;
        e->mtime_kind = src->mtime_kind;
        e->attr = src->attr;
        e->is_link = src->is_link;
        e->link_off = src->link_off;
        e->link_len = src->link_len;
        it->rsrc = w->it[t].rsrc;                            /* the iNode's resource fork */
        it->rsize = w->it[t].rsize;
        it->rblocks = w->it[t].rblocks;
    }
    gz_free(k);
    gz_free(val);
    return GZ_OK;
}

static int build_names(hfs_walk *w)
{
    gz_archive *a = w->a;
    u32 nmain = w->nit;
    int r;
    u8 *keep = (u8 *)gz_alloc(nmain + 1);
    if (!keep) return GZ_E_NOMEM;
    for (u32 i = 0; i < nmain; i++) {
        if (!(i & 4095) && gz_cancelled(w->c)) { r = GZ_E_CANCEL; goto out; }
        hfs_item *it = &w->it[i];
        if (it->special == 3) continue;
        const gzch *dir = 0;
        u32 dl = 0;
        if (it->folder) {
            if (it->alias >= 0) continue;                  /* shown at its link */
            r = folder_path(w, i);
            if (r > 0) goto out;
            if (r < 0) continue;
            r = set_name(w, &a->e[i], w->paths + it->path_off, it->path_len, 0, 0, 0);
            if (r) goto out;
            keep[i] = 1;
            continue;
        }
        i32 p = hmap_get(w, it->parent);
        if (p < 0) continue;
        if (w->it[p].state != 2) {
            r = folder_path(w, (u32)p);
            if (r > 0) goto out;
            if (r < 0) continue;
        }
        dir = w->paths + w->it[p].path_off;
        dl = w->it[p].path_len;
        if (it->lkind == 2) {
            /* directory hard link: the target's path is this path */
            r = set_name(w, &a->e[i], dir, dl, w->names + it->name_off, it->name_len, 0);
            if (r) goto out;
            keep[i] = 1;
            continue;
        }
        r = set_name(w, &a->e[i], dir, dl, w->names + it->name_off, it->name_len, 0);
        if (r) goto out;
        keep[i] = 1;
        if (it->rsrc) {
            /* resource fork: aux entry "name:rsrc" reading the same catalog record */
            gz_entry *re;
            if ((r = gz_arc_add_entry(a, &re))) goto out;
            const gz_entry *fe = &a->e[i];
            re->off = fe->off;
            re->aux32 = fe->aux32;
            re->mtime = fe->mtime;
            re->mtime_kind = fe->mtime_kind;
            re->unix_mode = 0100644;
            re->is_aux = 1;
            re->flags = F_RSRC;
            re->usize = it->rsize;
            re->csize = (u64)it->rblocks * w->v->bs;
            if ((r = set_name(w, re, dir, dl, w->names + it->name_off, it->name_len, ":rsrc"))) goto out;
        }
    }
    r = GZ_OK;
    /* drop hidden entries (main records without a name); aux entries come after */
    u32 j = 0;
    for (u32 i = 0; i < a->n; i++) {
        if (i < nmain && !keep[i]) continue;
        if (j != i) a->e[j] = a->e[i];
        j++;
    }
    a->n = j;
out:
    gz_free(keep);
    return r;
}

/* ---------------- record access at extraction ---------------- */

/* Re-read the catalog record of an entry: file record data (HFS+: 248, classic: 102 bytes). */
static int read_record(const hfs_vol *v, gz_src *s, const gz_entry *e, u8 *rec)
{
    int r = GZ_OK;
    gz_src *cs = fork_src(v, s, &v->cat, &r);
    if (!cs) return r;
    u32 node = (u32)(e->off >> 16), off = (u32)(e->off & 0xFFFF), ns = v->cat_ns;
    u8 *nd = (u8 *)gz_alloc(ns);
    if (!nd) { gz_src_free(cs); return GZ_E_NOMEM; }
    r = (u64)node * ns >= cs->size ? GZ_E_FORMAT : gz_src_read_exact(cs, (u64)node * ns, nd, ns);
    gz_src_free(cs);
    if (!r) {
        r = GZ_E_FORMAT;
        u32 nrec = node_recs(nd, ns);
        for (u32 i = 0; i < nrec; i++) {
            const u8 *p, *d;
            u32 len, kl, dl;
            node_rec(nd, ns, i, &p, &len);
            if ((u32)(p - nd) != off || !rec_split(v->classic, p, len, &kl, &d, &dl)) continue;
            u32 want = v->classic ? 102 : 248;
            int isfile = v->classic ? d[0] == 2 : rd16be(d) == 2;
            u32 id = dl >= 24 ? (v->classic ? rd32be(d + 20) : rd32be(d + 8)) : 0;
            if (dl >= want && isfile && id == e->aux32) {
                __builtin_memcpy(rec, d, want);
                r = GZ_OK;
            }
            break;
        }
    }
    gz_free(nd);
    return r;
}

static int entry_fork(const hfs_vol *v, gz_src *s, const gz_entry *e, int rsrc, hfs_fork *f)
{
    __builtin_memset(f, 0, sizeof *f);
    if (!rsrc && (e->flags & F_ONEEXT)) {
        f->size = e->usize;
        f->blocks = (u32)e->aux;
        f->fileid = e->aux32;
        f->e[0].start = (u32)(e->aux >> 32);
        f->e[0].count = (u32)e->aux;
        return GZ_OK;
    }
    u8 rec[248];
    int r = read_record(v, s, e, rec);
    if (r) return r;
    if (v->classic) {
        if (rsrc) fork_classic(v, f, rd32be(rec + 36), rd32be(rec + 40), rec + 86, e->aux32, 0xFF);
        else fork_classic(v, f, rd32be(rec + 26), rd32be(rec + 30), rec + 74, e->aux32, 0);
    } else {
        fork_plus(f, rec + (rsrc ? 168 : 88), e->aux32, rsrc ? 0xFF : 0);
    }
    return GZ_OK;
}

/* ---------------- decmpfs ---------------- */

typedef struct {
    u32 type;
    u64 usize;
    u32 bsize;                /* decoded bytes per block (inline: usize)      */
    u32 nblk;
    u8 *attr;                 /* attribute value (header + inline payload)    */
    u32 alen;
    gz_src *rf;               /* resource fork                                 */
    u64 *boff;                /* block offsets / lengths in the fork          */
    u32 *blen;
    u8 *in;
    u32 in_cap;
    gz_inflater *z;
    int own_z;
    gz_lzfse_dec *lz;
} hfs_cmp_rd;

static void cmp_close(hfs_cmp_rd *r)
{
    gz_free(r->attr);
    gz_src_free(r->rf);
    gz_free(r->boff);
    gz_free(r->blen);
    gz_free(r->in);
    if (r->own_z && r->z) gz_inflater_free(r->z);
    if (r->lz) gz_lzfse_dec_free(r->lz);
    __builtin_memset(r, 0, sizeof *r);
}

/* attribute value of the decmpfs record of fileid */
static int read_attr(const hfs_vol *v, gz_src *s, const hfs_cmp *m, u8 **out, u32 *n)
{
    int r = GZ_OK;
    gz_src *as = fork_src(v, s, &v->attr, &r);
    if (!as) return r;
    u32 ns = v->attr_ns;
    u8 *nd = (u8 *)gz_alloc(ns);
    if (!nd) { gz_src_free(as); return GZ_E_NOMEM; }
    r = (u64)m->node * ns >= as->size ? GZ_E_FORMAT : gz_src_read_exact(as, (u64)m->node * ns, nd, ns);
    gz_src_free(as);
    if (!r) {
        r = GZ_E_FORMAT;
        u32 nrec = node_recs(nd, ns);
        for (u32 i = 0; i < nrec; i++) {
            const u8 *p, *d;
            u32 len, kl, dl;
            node_rec(nd, ns, i, &p, &len);
            if ((u32)(p - nd) != m->off || !rec_split(0, p, len, &kl, &d, &dl) || kl < 12) continue;
            if (rd32be(p + 4) != m->fileid || dl < 16 || rd32be(d) != 0x10) break;
            u32 asz = rd32be(d + 12);
            if (asz < 16 || asz > dl - 16) break;
            u8 *b = (u8 *)gz_alloc(asz);
            if (!b) { r = GZ_E_NOMEM; break; }
            __builtin_memcpy(b, d + 16, asz);
            *out = b;
            *n = asz;
            r = GZ_OK;
            break;
        }
    }
    gz_free(nd);
    return r;
}

static int cmp_open(hfs_cmp_rd *r, const hfs_vol *v, gz_src *s, const gz_entry *e, gz_inflater *z)
{
    __builtin_memset(r, 0, sizeof *r);
    const hfs_cmp *m = find_cmp(v, e->aux32);
    if (!m || !cmp_supported(m->type)) return GZ_E_METHOD;
    r->type = m->type;
    r->usize = m->usize;
    if (z) r->z = z;
    int rc = read_attr(v, s, m, &r->attr, &r->alen);
    if (rc) return rc;
    if (!cmp_in_rsrc(r->type)) {
        if (r->usize > MAX_CMP_INLINE) return GZ_E_LIMIT;
        r->nblk = r->usize ? 1 : 0;
        r->bsize = (u32)r->usize;
        r->in_cap = 0;
        return GZ_OK;
    }
    /* compressed blocks in the resource fork */
    if (r->usize > ((u64)CMP_BLOCK << 24)) return GZ_E_LIMIT;
    r->bsize = CMP_BLOCK;
    r->nblk = (u32)((r->usize + CMP_BLOCK - 1) / CMP_BLOCK);
    hfs_fork f;
    if ((rc = entry_fork(v, s, e, 1, &f))) return rc;
    if (!(r->rf = fork_src(v, s, &f, &rc))) return rc;
    u64 fsz = r->rf->size, base;
    u32 n = r->nblk;
    r->boff = (u64 *)gz_alloc((size_t)n * 8 + 8);
    r->blen = (u32 *)gz_alloc((size_t)n * 4 + 4);
    r->in_cap = 2 * CMP_BLOCK + 1024;
    r->in = (u8 *)gz_alloc(r->in_cap);
    if (!r->boff || !r->blen || !r->in) return GZ_E_NOMEM;
    u8 *tab;
    if (r->type == 4) {
        /* resource fork header -> data -> 'cmpf' resource: count, {offset, size} LE */
        u8 h[16];
        if (fsz < 16 || (rc = gz_src_read_exact(r->rf, 0, h, 16))) return rc ? rc : GZ_E_DATA;
        u64 doff = rd32be(h);
        if (doff + 8 > fsz) return GZ_E_DATA;
        if ((rc = gz_src_read_exact(r->rf, doff + 4, h, 4))) return rc;
        if (rd32(h) != n) return GZ_E_DATA;
        base = doff + 4;
        if ((u64)n * 8 > fsz - doff - 8) return GZ_E_DATA;
        if (!(tab = (u8 *)gz_alloc((size_t)n * 8 + 1))) return GZ_E_NOMEM;
        rc = n ? gz_src_read_exact(r->rf, doff + 8, tab, n * 8) : GZ_OK;
        for (u32 i = 0; !rc && i < n; i++) {
            u64 o = base + rd32(tab + 8 * i);
            u32 l = rd32(tab + 8 * i + 4);
            if (o > fsz || l > fsz - o || l > r->in_cap) rc = GZ_E_DATA;
            r->boff[i] = o;
            r->blen[i] = l;
        }
    } else {
        /* LZVN / LZFSE: u32 LE offsets, the first one is the table size */
        u64 tsz = ((u64)n + 1) * 4;
        if (tsz > fsz) return GZ_E_DATA;
        if (!(tab = (u8 *)gz_alloc((size_t)tsz))) return GZ_E_NOMEM;
        rc = gz_src_read_exact(r->rf, 0, tab, (u32)tsz);
        if (!rc && rd32(tab) != tsz) rc = GZ_E_DATA;
        for (u32 i = 0; !rc && i < n; i++) {
            u64 o = rd32(tab + 4 * i), e2 = rd32(tab + 4 * i + 4);
            if (e2 < o || e2 > fsz || e2 - o > r->in_cap) rc = GZ_E_DATA;
            r->boff[i] = o;
            r->blen[i] = (u32)(e2 - o);
        }
    }
    gz_free(tab);
    return rc;
}

typedef struct { u8 *dst; u32 cap, n; } buf_sink;

static int buf_write(void *user, const u8 *p, size_t n)
{
    buf_sink *k = (buf_sink *)user;
    if (n > (size_t)(k->cap - k->n)) return GZ_E_DATA;
    __builtin_memcpy(k->dst + k->n, p, n);
    k->n += (u32)n;
    return GZ_OK;
}

/* Decode block i into out (bsize bytes of room). */
static int cmp_block(hfs_cmp_rd *r, u32 i, u8 *out, u32 *outn)
{
    u64 start = (u64)i * r->bsize;
    u32 want = (u32)(r->usize - start < r->bsize ? r->usize - start : r->bsize);
    const u8 *p;
    u32 n;
    int rc;
    *outn = 0;
    if (!cmp_in_rsrc(r->type)) {
        p = r->attr + 16;
        n = r->alen - 16;
    } else {
        n = r->blen[i];
        if ((rc = gz_src_read_exact(r->rf, r->boff[i], r->in, n))) return rc;
        p = r->in;
    }
    u32 t = r->type;
    size_t got = 0;
    if (t == 1 || t == 9) {
        if (n < want) return GZ_E_DATA;
        __builtin_memcpy(out, p, want);
        *outn = want;
        return GZ_OK;
    }
    if (!n) return GZ_E_DATA;
    int raw = (t == 3 || t == 4) ? (p[0] & 0x0F) == 0x0F : (t == 7 || t == 8) ? p[0] == 0x06 : p[0] == 0xFF;
    if (raw) {
        if (n - 1 < want) return GZ_E_DATA;
        __builtin_memcpy(out, p + 1, want);
        *outn = want;
        return GZ_OK;
    }
    if (t == 3 || t == 4) {
        if (n < 2 || (p[0] & 15) != 8 || ((p[0] << 8) | p[1]) % 31 || (p[1] & 0x20)) return GZ_E_DATA;
        if (!r->z) {
            if (!(r->z = gz_inflater_new())) return GZ_E_NOMEM;
            r->own_z = 1;
        }
        gz_src *ms = gz_src_mem(p + 2, n - 2, 0);
        if (!ms) return GZ_E_NOMEM;
        buf_sink k = { out, want, 0 };
        gz_pipe pp = { { ms, 0, n - 2, 0 }, buf_write, &k };
        gz_stream_io io = { gz_range_read, gz_pipe_write, &pp };
        rc = gz_inflate_run(r->z, &io, 0);
        gz_src_free(ms);
        got = k.n;
    } else if (t == 7 || t == 8) {
        rc = gz_lzvn_decode(p, n, out, want, &got, 0);
    } else {
        if (!r->lz && !(r->lz = gz_lzfse_dec_new())) return GZ_E_NOMEM;
        rc = gz_lzfse_decode_ex(r->lz, p, n, out, want, &got, 0);
    }
    if (!rc && got != want) rc = GZ_E_DATA;
    *outn = (u32)got;
    return rc;
}

/* ---------------- open ---------------- */

static void vol_free(hfs_vol *v)
{
    if (!v) return;
    gz_free(v->xr);
    gz_free(v->cmp);
    gz_free(v);
}

static void hfs_close(gz_archive *a)
{
    vol_free((hfs_vol *)a->priv);
    a->priv = 0;
}

static int vh_check(const u8 *h)
{
    u16 sig = rd16be(h), ver = rd16be(h + 2);
    u32 bs = rd32be(h + 40);
    if (sig != 0x482B && sig != 0x4858) return 0;
    if (ver != 4 && ver != 5) return 0;
    if (bs < 512 || (bs & (bs - 1)) || bs > (1u << 26) || !rd32be(h + 44)) return 0;
    return 1;
}

static int mdb_check(const u8 *m)
{
    u32 bs = rd32be(m + 20);
    if (rd16be(m) != 0x4244) return 0;                                /* "BD" */
    if (!bs || (bs & 511) || bs > (1u << 26) || !rd16be(m + 18)) return 0;
    if (m[36] > 27) return 0;                                         /* volume name length */
    return 1;
}

static int hfs_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 1536) return 0;
    if (vh_check(h + 1024)) return 80;
    if (mdb_check(h + 1024)) return rd16be(h + 1024 + 124) == 0x482B ? 80 : 55;
    return 0;
}

static int hfs_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    u8 h[512];
    int r = gz_src_read_exact(s, 1024, h, 512);
    if (r) return r;
    hfs_vol *v = (hfs_vol *)gz_alloc(sizeof(hfs_vol));
    if (!v) return GZ_E_NOMEM;
    a->priv = v;
    u64 voff = 0;
    if (mdb_check(h) && rd16be(h + 124) == 0x482B) {
        /* HFS wrapper around an HFS+ volume */
        u32 abs = rd32be(h + 20);
        voff = (u64)rd16be(h + 28) * 512 + (u64)rd16be(h + 126) * abs;
        if (voff > s->size || s->size - voff < 1536) return GZ_E_FORMAT;
        if ((r = gz_src_read_exact(s, voff + 1024, h, 512))) return r;
        if (!vh_check(h)) return GZ_E_FORMAT;
    }
    if (vh_check(h)) {
        v->hfsx = rd16be(h) == 0x4858;
        v->bs = rd32be(h + 40);
        v->nblocks = rd32be(h + 44);
        v->base = voff;
        fork_plus(&v->ext, h + 192, 3, 0);
        fork_plus(&v->cat, h + 272, 4, 0);
        fork_plus(&v->attr, h + 352, 8, 0);
        u32 at = rd32be(h + 4);
        if ((at & 0x2000) && !(at & 0x100)) GZ_VD_NOTE(a, "journal not replayed");
    } else if (mdb_check(h)) {
        v->classic = 1;
        v->bs = rd32be(h + 20);
        v->nblocks = rd16be(h + 18);
        v->base = (u64)rd16be(h + 28) * 512;
        fork_classic(v, &v->ext, rd32be(h + 130), rd32be(h + 130), h + 134, 3, 0);
        fork_classic(v, &v->cat, rd32be(h + 146), rd32be(h + 146), h + 150, 4, 0);
    } else {
        return GZ_E_FORMAT;
    }
    if ((r = load_xrecs(v, s, c))) return r;
    if ((r = load_cmp(v, s, c))) return r;

    hfs_walk w;
    __builtin_memset(&w, 0, sizeof w);
    w.a = a; w.v = v; w.s = s; w.c = c;
    w.link_budget = 64u << 20;          /* many links sharing one hostile extent */
    r = bt_open(&w.cat, v, s, &v->cat);
    if (!r) {
        v->cat_ns = w.cat.ns;
        if (!v->classic && v->hfsx && w.cat.key_cmp == 0xBC) a->case_fold = 0;
        gz_arc_set_type(a, v->classic ? "HFS" : v->hfsx ? "HFSX" : "HFS+");
        r = scan_catalog(&w);
    }
    bt_close(&w.cat);
    if (!r && !w.nit) r = GZ_E_FORMAT;
    if (!r) r = resolve_links(&w);
    if (!r) r = build_names(&w);
    gz_free(w.it);
    gz_free(w.names);
    gz_free(w.paths);
    gz_free(w.hk);
    gz_free(w.hv);
    return r;
}

/* ---------------- extract / view ---------------- */

static int hfs_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    const hfs_vol *v = (const hfs_vol *)a->priv;
    gz_entry *e = &a->e[idx];
    int data = !e->is_dir && !(e->is_link && e->link_len) && e->usize && e->usize != GZ_SIZE_UNKNOWN;
    if (data && (e->flags & F_CMP) && !cmp_supported(e->method)) return GZ_E_METHOD;
    int r = out->open(out, idx);
    if (r) return r;
    if (!data) return out->close(out, idx, (e->flags & F_BROKEN) ? GZ_E_DATA : GZ_OK);
    int st;
    if (e->flags & F_CMP) {
        hfs_cmp_rd cr;
        st = cmp_open(&cr, v, s, e, gz_ctx_inflater(c));
        u8 *buf = st ? 0 : gz_ctx_buffer(c, cr.bsize > CMP_BLOCK ? cr.bsize : CMP_BLOCK);
        if (!st && !buf) st = GZ_E_NOMEM;
        u64 total = 0;
        for (u32 i = 0; !st && i < cr.nblk; i++) {
            if (gz_cancelled(c)) { st = GZ_E_CANCEL; break; }
            u32 n;
            if (!(st = cmp_block(&cr, i, buf, &n))) st = out->write(out, buf, n);
            total += n;
        }
        if (!st && total != e->usize) st = GZ_E_DATA;
        cmp_close(&cr);
    } else {
        hfs_fork f;
        st = entry_fork(v, s, e, (e->flags & F_RSRC) != 0, &f);
        if (!st && f.size != e->usize) st = GZ_E_DATA;
        if (!st) {
            gz_fs1_copy w;
            st = gz_fs1_copy_init(&w, s, out, c, e->usize);
            if (!st) st = fork_runs(v, &f, &w.k);
            if (!st) st = gz_fs1_flush(&w.k, 0);
            if (!st && w.k.flushed != e->usize) st = GZ_E_DATA;
        }
    }
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

/* compressed file view: one decoded block cached */
typedef struct {
    gz_vd_view v;
    hfs_cmp_rd r;
    u8 *blk;
    u32 cur;                  /* block index + 1 */
} cmp_vw;

static int cmp_map(gz_vd_view *gv, u64 off, gz_vd_ext *x)
{
    cmp_vw *v = (cmp_vw *)gv;
    u32 i = (u32)(off / v->r.bsize);
    u64 in = off - (u64)i * v->r.bsize;
    if (v->cur != i + 1) {
        u32 n;
        v->cur = 0;
        int rc = cmp_block(&v->r, i, v->blk, &n);
        if (rc) return rc;
        v->cur = i + 1;
    }
    x->kind = GZ_VD_MEM;
    x->mem = v->blk + in;
    u64 end = (u64)(i + 1) * v->r.bsize;
    if (end > gv->s.size) end = gv->s.size;
    x->len = end - off;
    return GZ_OK;
}

static void cmp_fini(gz_vd_view *gv)
{
    cmp_vw *v = (cmp_vw *)gv;
    cmp_close(&v->r);
    gz_free(v->blk);
}

static gz_src *hfs_view(gz_archive *a, gz_src *s, u32 idx)
{
    const hfs_vol *v = (const hfs_vol *)a->priv;
    gz_entry *e = &a->e[idx];
    if (e->is_dir || e->is_link || (e->flags & F_BROKEN) || e->usize == GZ_SIZE_UNKNOWN) return 0;
    if (!e->usize) return gz_src_sub(s, 0, 0);
    if (e->flags & F_CMP) {
        if (!cmp_supported(e->method)) return 0;
        cmp_vw *cv = (cmp_vw *)gz_vd_view_new(sizeof(cmp_vw), s, v, e->usize, cmp_map);
        if (!cv) return 0;
        cv->v.fini = cmp_fini;
        if (cmp_open(&cv->r, v, s, e, 0) || cv->r.usize != e->usize ||
            !(cv->blk = (u8 *)gz_alloc(cv->r.bsize))) {
            gz_src_free(&cv->v.s);
            return 0;
        }
        return &cv->v.s;
    }
    hfs_fork f;
    int err = 0;
    if (entry_fork(v, s, e, (e->flags & F_RSRC) != 0, &f) || f.size != e->usize) return 0;
    return fork_src(v, s, &f, &err);
}

static void hfs_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    const char *m = "";
    if (e->flags & F_CMP) {
        switch (e->method) {
        case 1: case 9: m = "decmpfs Store"; break;
        case 3: case 4: m = "ZLIB"; break;
        case 7: case 8: m = "LZVN"; break;
        case 11: case 12: m = "LZFSE"; break;
        default: m = "decmpfs ?"; break;
        }
    }
    gz_vd_method_str(buf, cap, m);
}

GZ_FORMAT(gz_fmt_hfs)
const gz_format gz_fmt_hfs = {
    "HFS+", "hfs hfsx hfsplus img", 0,
    hfs_probe, hfs_open, hfs_close, hfs_extract, 0, 0, hfs_method, hfs_view, 0
};
