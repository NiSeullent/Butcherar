/*
 * 고깃ZIP - APFS (Apple File System) containers, read-only
 *
 *   container superblock (NXSB, block 0) -> newest superblock with a valid
 *   Fletcher-64 checksum in the checkpoint descriptor area (older checkpoints
 *   and block 0 are fallbacks) -> container object map (virtual oid -> block)
 *   -> volume superblocks (APSB) -> volume object map -> file-system tree.
 *
 *   Layout of the archive: a container with one volume shows that volume's
 *   files at the root (volume name = comment); with several volumes every
 *   volume is a top-level folder named after it (made unique, "Volume N" when
 *   unnamed). Snapshots are ignored (the live tree is read). Encrypted volumes
 *   cannot be read: GZ_E_METHOD (a single volume fails to open, in a
 *   multi-volume container its folder extracts with GZ_E_METHOD).
 *
 *   Listing: each volume's fs tree is walked once in key order collecting
 *   inodes, directory records (hashed and plain keys), xattrs (decmpfs,
 *   resource fork, symlink target) and file extents (+ the file-extent tree of
 *   sealed volumes); the folder tree is then built breadth-first from the root
 *   directory (inode 2), so the private directory and orphans are not shown.
 *   Hard links appear once per name. Only the extents are kept after open, so
 *   extraction does no tree lookups: holes, sparse extents and sparse tails read
 *   as zeros, clones simply share blocks. decmpfs (UF_COMPRESSED) files are
 *   decoded: zlib, LZVN, LZFSE and stored, inline in the xattr or in 64 KiB
 *   chunks in the resource fork.
 *
 *   Hostile images: every object is checksummed and must carry the expected
 *   oid / type / subtype and an xid not newer than the checkpoint; B-tree levels
 *   go down by exactly one per step (bounded depth); a walk reads each block at
 *   most once (shared subtrees / loops are cut); records whose keys go backwards
 *   are dropped; every table offset is checked against the node; every block
 *   address against the container; directories are visited once; record
 *   counts and in-memory decmpfs data are capped.
 */
#include "fs1.h"
#include "lzfse.h"

#define NX_MAGIC   0x4253584Eu        /* "NXSB" */
#define APSB_MAGIC 0x42535041u        /* "APSB" */
#define DEC_MAGIC  0x636D7066u        /* "fpmc" */

/* object types (o_type low 16 bits) and storage flags */
#define OT_NX      0x01u
#define OT_BTREE   0x02u
#define OT_BTNODE  0x03u
#define OT_OMAP    0x0Bu
#define OT_FS      0x0Du
#define OT_FSTREE  0x0Eu
#define OT_FEXT    0x1Fu
#define OT_MASK    0xFFFFu
#define OBJ_STORAGE  0xC0000000u
#define OBJ_PHYSICAL 0x40000000u

/* B-tree node flags, btree_info flags */
#define BTN_ROOT   1u
#define BTN_LEAF   2u
#define BTN_FIXED  4u
#define BTN_HASHED 8u                 /* index values: child oid + hash (sealed volumes) */
#define BT_INFO    40u                /* btree_info_t at the end of a root node */
#define AP_MAXDEPTH 16                /* B-tree levels */

/* object map */
#define OMV_DELETED   1u
#define OMV_ENCRYPTED 4u
#define OM_CRYPTING   6u              /* OMAP_ENCRYPTING | OMAP_DECRYPTING */

/* volume superblock */
#define FS_UNENCRYPTED  1u
#define INC_CASE_INSENS 1u
#define INC_NORM_INSENS 8u
#define INC_SEALED      0x20u

/* fs tree record types */
#define J_INODE  3u
#define J_XATTR  4u
#define J_EXTENT 8u
#define J_DREC   9u
#define J_ID_MASK 0x0FFFFFFFFFFFFFFFull

#define ROOT_DIR_ID   2u
#define UF_COMPRESSED 0x20u
#define UF_HIDDEN     0x8000u
#define XF_DSTREAM    8u               /* INO_EXT_TYPE_DSTREAM */
#define XA_STREAM     1u               /* XATTR_DATA_STREAM */
#define XA_EMBEDDED   2u

#define AP_MAXVOL    100u
#define AP_MAXREC    (1u << 26)        /* records of one kind per volume */
#define AP_DESC_MAX  8192u             /* checkpoint descriptor blocks scanned */
#define AP_NCAND     8u                /* checkpoints tried */
#define AP_LINK_MAX  4096u
#define AP_CHUNK     65536u            /* decmpfs chunk */
#define AP_CIN_MAX   (256u << 10)      /* compressed chunk */
#define AP_INLINE_MAX (64u << 20)      /* decmpfs data decoded in memory */

/* ---------------- objects ---------------- */

/* Fletcher-64 over b[8..n) (n % 4 == 0) compared with the stored checksum.
 * Sums are reduced every 4096 words, so s2 stays below 2^56. */
static int ck_ok(const u8 *b, u32 n)
{
    u64 s1 = 0, s2 = 0;
    const u8 *p = b + 8, *e = b + n;
    while (p < e) {
        const u8 *ce = (u32)(e - p) > 16384u ? p + 16384 : e;
        for (; p < ce; p += 4) { s1 += rd32(p); s2 += s1; }
        s1 %= 0xFFFFFFFFu;
        s2 %= 0xFFFFFFFFu;
    }
    u64 c1 = 0xFFFFFFFFu - (s1 + s2) % 0xFFFFFFFFu;
    u64 c2 = 0xFFFFFFFFu - (s1 + c1) % 0xFFFFFFFFu;
    return rd64(b) == (c2 << 32 | c1);
}

typedef struct {
    gz_src *s;
    gz_ctx *c;
    u32 bs, bshift;
    u64 nblocks;
    u64 xid;                           /* checkpoint: newer objects are rejected */
} ap_ctx;

/* Read one object and check its header. oid / type / sub = 0: not checked. */
static int read_obj(const ap_ctx *x, u64 pa, u8 *b, u64 oid, u32 type, u32 sub)
{
    if (!pa || pa >= x->nblocks) return GZ_E_FORMAT;
    int r = gz_src_read_exact(x->s, pa << x->bshift, b, x->bs);
    if (r) return r;
    if (!ck_ok(b, x->bs)) return GZ_E_CRC;
    if (oid && rd64(b + 8) != oid) return GZ_E_FORMAT;
    if (rd64(b + 16) > x->xid) return GZ_E_FORMAT;
    if (type && (rd32(b + 24) & OT_MASK) != type) return GZ_E_FORMAT;
    if (sub && rd32(b + 28) != sub) return GZ_E_FORMAT;
    return GZ_OK;
}

/* ---------------- growable arrays ---------------- */

static int grow(void **p, u32 *cap, u32 n, u32 esz)
{
    if (n < *cap) return GZ_OK;
    if (n >= AP_MAXREC) return GZ_E_LIMIT;
    u32 nc = *cap ? *cap * 2 : 256;
    void *np = gz_realloc(*p, (size_t)nc * esz);
    if (!np) return GZ_E_NOMEM;
    *p = np;
    *cap = nc;
    return GZ_OK;
}

/* ---------------- B-tree walk ---------------- */

typedef struct { u64 oid, paddr; u32 flags, pad_; } ap_map;     /* object map, latest <= xid */

static int om_find(const ap_map *m, u32 n, u64 oid, u64 *pa)
{
    u32 lo = 0, hi = n;
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        if (m[mid].oid < oid) lo = mid + 1; else hi = mid;
    }
    if (lo >= n || m[lo].oid != oid) return GZ_E_FORMAT;
    if (m[lo].flags & OMV_ENCRYPTED) return GZ_E_METHOD;
    if (m[lo].flags & OMV_DELETED) return GZ_E_FORMAT;
    *pa = m[lo].paddr;
    return GZ_OK;
}

typedef struct ap_bt ap_bt;
/* leaf record; w->blk / w->blk_pa: the node it lives in */
typedef int (*ap_rec_fn)(ap_bt *w, const u8 *k, u32 kl, const u8 *v, u32 vl);

struct ap_bt {
    const ap_ctx *x;
    const ap_map *om;                  /* virtual tree: object map; NULL = physical */
    u32 nom;
    u32 sub;                           /* expected object subtype */
    u32 ksz, vsz;                      /* fixed records: leaf key / value size */
    u64 root;                          /* root oid: hashed index nodes of virtual trees store
                                          child oids relative to it (as 7-Zip reads sealed volumes) */
    gz_fs1_set seen;                   /* blocks visited by this walk */
    u8 *lv[AP_MAXDEPTH];
    const u8 *blk;
    u64 blk_pa;
    u64 nodes, total;
    u32 bad;                           /* subtrees skipped */
    ap_rec_fn fn;
    void *u;
};

static int bt_node(ap_bt *w, u64 oid, u32 level, u32 depth, int rel)
{
    const ap_ctx *x = w->x;
    if (depth >= AP_MAXDEPTH) return GZ_E_FORMAT;
    if (gz_cancelled(x->c)) return GZ_E_CANCEL;
    u64 pa = oid;
    int r;
    if (w->om) {
        if (rel && !om_find(w->om, w->nom, oid + w->root, &pa)) oid += w->root;
        else if ((r = om_find(w->om, w->nom, oid, &pa))) return r;
    }
    int nw = gz_fs1_set_add(&w->seen, pa);
    if (nw < 0) return GZ_E_NOMEM;
    if (!nw || ++w->nodes > x->nblocks) return GZ_E_FORMAT;
    if (!w->lv[depth] && !(w->lv[depth] = (u8 *)gz_alloc(x->bs))) return GZ_E_NOMEM;
    u8 *b = w->lv[depth];
    if ((r = read_obj(x, pa, b, oid, depth ? OT_BTNODE : OT_BTREE, w->sub))) return r;
    if (x->c && x->c->progress && !(w->nodes & 255)) x->c->progress(x->c->progress_user, w->nodes, w->total);

    u32 fl = rd16(b + 0x20), lvl = rd16(b + 0x22), nk = rd32(b + 0x24);
    u32 bs = x->bs;
    if (depth == 0) {
        if (!(fl & BTN_ROOT) || lvl >= AP_MAXDEPTH) return GZ_E_FORMAT;
        const u8 *inf = b + bs - BT_INFO;
        w->ksz = rd32(inf + 8);
        w->vsz = rd32(inf + 12);
        w->total = rd64(inf + 32);
    } else if (lvl != level || (fl & BTN_ROOT)) {
        return GZ_E_FORMAT;
    }
    if (!(fl & BTN_LEAF) != (lvl != 0)) return GZ_E_FORMAT;
    u32 toff = rd16(b + 0x28), tlen = rd16(b + 0x2A);
    u32 vend = (fl & BTN_ROOT) ? bs - BT_INFO : bs;
    u32 kbase = 0x38 + toff + tlen;
    int fixed = (fl & BTN_FIXED) != 0;
    u32 es = fixed ? 4 : 8;
    if (kbase > vend || (u64)nk * es > tlen) return GZ_E_FORMAT;
    if (fixed && (!w->ksz || !w->vsz || w->ksz > 256 || w->vsz > 256)) return GZ_E_FORMAT;
    const u8 *t = b + 0x38 + toff;
    for (u32 i = 0; i < nk; i++, t += es) {
        u32 ko = rd16(t), kl, vo, vl;
        if (fixed) { kl = w->ksz; vo = rd16(t + 2); vl = lvl ? 8 : w->vsz; }   /* index: child oid (+ hash) */
        else { kl = rd16(t + 2); vo = rd16(t + 4); vl = rd16(t + 6); }
        if ((u64)kbase + ko + kl > vend) return GZ_E_FORMAT;
        if (vo == 0xFFFF) {                    /* ghost: key without value */
            if (lvl) return GZ_E_FORMAT;
            continue;
        }
        if (vo > vend - kbase || vl > vo) return GZ_E_FORMAT;
        const u8 *kp = b + kbase + ko, *vp = b + vend - vo;
        if (!lvl) {
            w->blk = b;
            w->blk_pa = pa;
            if ((r = w->fn(w, kp, kl, vp, vl))) return r;
            continue;
        }
        if (vl < 8) return GZ_E_FORMAT;
        r = bt_node(w, rd64(vp), lvl - 1, depth + 1, (fl & BTN_HASHED) != 0);
        if (r == GZ_E_NOMEM || r == GZ_E_CANCEL || r == GZ_E_LIMIT) return r;
        if (r) w->bad++;                       /* damaged subtree: keep the rest */
    }
    return GZ_OK;
}

/* Walk every leaf record of the tree rooted at oid (virtual through om, or physical). */
static int bt_walk(const ap_ctx *x, const ap_map *om, u32 nom, u64 oid, u32 sub, ap_rec_fn fn, void *u)
{
    ap_bt w;
    __builtin_memset(&w, 0, sizeof w);
    w.x = x;
    w.om = om;
    w.nom = nom;
    w.sub = sub;
    w.fn = fn;
    w.u = u;
    w.root = oid;
    int r = bt_node(&w, oid, 0, 0, 0);
    gz_fs1_set_free(&w.seen);
    for (int i = 0; i < AP_MAXDEPTH; i++) gz_free(w.lv[i]);
    return r;
}

/* ---------------- object maps ---------------- */

typedef struct {
    ap_map *m;
    u32 n, cap;
    u64 xid, last_oid, last_xid;
    int any;
} om_load;

static int om_rec(ap_bt *w, const u8 *k, u32 kl, const u8 *v, u32 vl)
{
    om_load *m = (om_load *)w->u;
    if (kl < 16 || vl < 16) return GZ_E_FORMAT;
    u64 oid = rd64(k), xid = rd64(k + 8);
    if (m->any && (oid < m->last_oid || (oid == m->last_oid && xid <= m->last_xid))) return GZ_OK;  /* out of order */
    m->any = 1;
    m->last_oid = oid;
    m->last_xid = xid;
    if (xid > m->xid) return GZ_OK;
    ap_map *p;
    if (m->n && m->m[m->n - 1].oid == oid) {
        p = &m->m[m->n - 1];                    /* newer version of the same object */
    } else {
        int r = grow((void **)&m->m, &m->cap, m->n, sizeof(ap_map));
        if (r) return r;
        p = &m->m[m->n++];
    }
    p->oid = oid;
    p->flags = rd32(v);
    p->paddr = rd64(v + 8);
    return GZ_OK;
}

/* Load the object map at physical address pa (entries <= the checkpoint xid).
 * *crypt: the map is being encrypted / decrypted. */
static int om_open(const ap_ctx *x, u64 pa, u8 *blk, om_load *m, int *crypt)
{
    __builtin_memset(m, 0, sizeof *m);
    m->xid = x->xid;
    int r = read_obj(x, pa, blk, pa, OT_OMAP, 0);
    if (r) return r;
    if (crypt) *crypt = (rd32(blk + 0x20) & OM_CRYPTING) != 0;
    if ((rd32(blk + 0x28) & OBJ_STORAGE) != OBJ_PHYSICAL) return GZ_E_FORMAT;
    r = bt_walk(x, 0, 0, rd64(blk + 0x30), OT_OMAP, om_rec, m);
    if (r) { gz_free(m->m); m->m = 0; m->n = 0; }
    return r;
}

/* ---------------- archive state ---------------- */

typedef struct { u64 id, laddr, len, pblk; } ap_ext;    /* len in bytes, pblk 0 = hole */

/* where an xattr value lives */
typedef struct {
    u64 loc;                           /* embedded: node block; stream: xattr object id */
    u64 size;
    u16 off;                           /* embedded: value offset in the node */
    u8 kind;                           /* XV_* */
    u8 pad_[5];
} ap_xval;
enum { XV_NONE = 0, XV_EMB = 1, XV_STREAM = 2 };

typedef struct {
    ap_xval dec, rsrc;                 /* com.apple.decmpfs, com.apple.ResourceFork */
    u64 data_id;                       /* dstream of the file data */
    u32 vol;
    u32 cmp;                           /* decmpfs type, 0 = plain data */
} ap_file;

typedef struct {
    ap_ext *x;
    u32 n;
    u8 encrypted;
} ap_vol;

typedef struct {
    u32 bs, bshift;
    u64 nblocks;
    ap_file *f;
    u32 nf, capf;
    ap_vol v[AP_MAXVOL];
    u32 nv;
} ap_priv;

static void ap_close(gz_archive *a)
{
    ap_priv *pv = (ap_priv *)a->priv;
    if (!pv) return;
    for (u32 i = 0; i < pv->nv; i++) gz_free(pv->v[i].x);
    gz_free(pv->f);
    gz_free(pv);
    a->priv = 0;
}

/* forget the entries of a checkpoint that could not be read */
static void ap_reset(gz_archive *a, ap_priv *pv)
{
    for (u32 i = 0; i < pv->nv; i++) {
        gz_free(pv->v[i].x);
        __builtin_memset(&pv->v[i], 0, sizeof pv->v[i]);
    }
    pv->nv = 0;
    pv->nf = 0;
    a->n = 0;
    a->raw_len = 0;
    gz_free(a->comment_raw);
    a->comment_raw = 0;
    a->comment_len = 0;
}

/* first extent of stream id (extents sorted by id, laddr) */
static u32 ext_first(const ap_ext *x, u32 n, u64 id)
{
    u32 lo = 0, hi = n;
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        if (x[mid].id < id) lo = mid + 1; else hi = mid;
    }
    return lo;
}

/* Emit the runs of stream id into k (caller flushes). Extents must not overlap. */
static int emit_stream(const ap_ext *x, u32 n, u64 id, u32 bshift, u64 nblocks, gz_fs1_sink *k)
{
    u64 next = 0;
    int r;
    for (u32 i = ext_first(x, n, id); i < n && x[i].id == id; i++) {
        const ap_ext *e = &x[i];
        if (e->laddr < next || e->len > ~(u64)0 - e->laddr) return GZ_E_DATA;
        if (e->laddr > next && (r = gz_fs1_emit(k, GZ_FS1_HOLE, e->laddr - next)))
            return r == GZ_FS1_FULL ? GZ_OK : r;
        next = e->laddr + e->len;
        if (!e->len) continue;
        if (e->pblk) {
            u64 nb = ((e->len - 1) >> bshift) + 1;
            if (e->pblk >= nblocks || nb > nblocks - e->pblk) return GZ_E_DATA;
            r = gz_fs1_emit(k, e->pblk << bshift, e->len);
        } else {
            r = gz_fs1_emit(k, GZ_FS1_HOLE, e->len);
        }
        if (r) return r == GZ_FS1_FULL ? GZ_OK : r;
    }
    return GZ_OK;
}

/* ---------------- fs tree scan ---------------- */

typedef struct {
    u64 id, data_id, mtime, size, alloced;
    u32 mode, uid, gid, bsd;
    ap_xval dec, rsrc;
    u32 link_off, link_len;            /* symlink target in sc->bytes */
    u32 dec_type;                      /* embedded decmpfs header (0 = none read yet) */
    u64 dec_size;
} ap_ino;

typedef struct { u64 parent, child; u32 name_off, name_len; } ap_drec;

typedef struct {
    ap_ino *ino; u32 nino, capino;
    ap_drec *dr; u32 ndr, capdr;
    ap_ext *ext; u32 next, capext;
    u8 *bytes; u32 nbytes, capbytes;   /* names and link targets */
    u64 last_id;
    u32 last_type;
    int any, hashed;
} ap_scan;

static int keep_bytes(ap_scan *sc, const u8 *p, u32 n, u32 *off)
{
    if ((u64)sc->nbytes + n > (1u << 30)) return GZ_E_LIMIT;
    if (sc->nbytes + n > sc->capbytes) {
        u32 nc = sc->capbytes ? sc->capbytes : 65536;
        while (nc < sc->nbytes + n) nc *= 2;
        u8 *np = (u8 *)gz_realloc(sc->bytes, nc);
        if (!np) return GZ_E_NOMEM;
        sc->bytes = np;
        sc->capbytes = nc;
    }
    *off = sc->nbytes;
    if (n) __builtin_memcpy(sc->bytes + sc->nbytes, p, n);
    sc->nbytes += n;
    return GZ_OK;
}

static u32 strip_nul(const u8 *p, u32 n)
{
    while (n && !p[n - 1]) n--;
    return n;
}

static int name_is(const u8 *p, u32 n, const char *s)
{
    u32 i = 0;
    for (; s[i]; i++) if (i >= n || p[i] != (u8)s[i]) return 0;
    return i == n;
}

static int inode_rec(ap_scan *sc, u64 id, const u8 *v, u32 vl)
{
    if (vl < 0x5C) return GZ_OK;
    if (sc->nino && sc->ino[sc->nino - 1].id == id) return GZ_OK;       /* duplicate */
    int r = grow((void **)&sc->ino, &sc->capino, sc->nino, sizeof(ap_ino));
    if (r) return r;
    ap_ino *n = &sc->ino[sc->nino++];
    __builtin_memset(n, 0, sizeof *n);
    n->id = id;
    n->data_id = rd64(v + 8) ? rd64(v + 8) : id;
    n->mtime = rd64(v + 0x18);
    n->bsd = rd32(v + 0x44);
    n->uid = rd32(v + 0x48);
    n->gid = rd32(v + 0x4C);
    n->mode = rd16(v + 0x50);
    /* extended fields: count, used bytes, headers, then 8-aligned values */
    if (vl >= 0x5C + 4) {
        const u8 *xf = v + 0x5C;
        u32 rem = vl - 0x5C, cnt = rd16(xf), used = rd16(xf + 2);
        if (4 + (u64)cnt * 4 + used <= rem) {
            const u8 *d = xf + 4 + cnt * 4;
            u32 doff = 0;
            for (u32 i = 0; i < cnt; i++) {
                u32 ty = xf[4 + i * 4], sz = rd16(xf + 4 + i * 4 + 2);
                if (sz > used - doff) break;
                if (ty == XF_DSTREAM && sz >= 16) {
                    n->size = rd64(d + doff);
                    n->alloced = rd64(d + doff + 8);
                }
                doff += (sz + 7) & ~7u;
                if (doff >= used) break;
            }
        }
    }
    return GZ_OK;
}

static int xattr_rec(ap_bt *w, ap_scan *sc, u64 id, const u8 *k, u32 kl, const u8 *v, u32 vl)
{
    if (!sc->nino || sc->ino[sc->nino - 1].id != id || kl < 10 || vl < 4) return GZ_OK;
    ap_ino *n = &sc->ino[sc->nino - 1];
    u32 nl = rd16(k + 8);
    if (nl > kl - 10) return GZ_OK;
    const u8 *nm = k + 10;
    nl = strip_nul(nm, nl);
    ap_xval *xv;
    int dec = 0;
    if (name_is(nm, nl, "com.apple.decmpfs")) { xv = &n->dec; dec = 1; }
    else if (name_is(nm, nl, "com.apple.ResourceFork")) xv = &n->rsrc;
    else if (name_is(nm, nl, "com.apple.fs.symlink")) xv = 0;
    else return GZ_OK;
    u32 fl = rd16(v), xl = rd16(v + 2);
    if (xl > vl - 4) return GZ_OK;
    const u8 *xd = v + 4;
    if (!xv) {                                       /* symlink target (embedded) */
        if (!(fl & XA_EMBEDDED)) return GZ_OK;
        xl = strip_nul(xd, xl);
        if (xl > AP_LINK_MAX) return GZ_OK;
        n->link_len = xl;
        return keep_bytes(sc, xd, xl, &n->link_off);
    }
    if (fl & XA_STREAM) {
        if (xl < 48) return GZ_OK;
        xv->kind = XV_STREAM;
        xv->loc = rd64(xd);
        xv->size = rd64(xd + 8);
    } else if (fl & XA_EMBEDDED) {
        xv->kind = XV_EMB;
        xv->loc = w->blk_pa;
        xv->off = (u16)(xd - w->blk);
        xv->size = xl;
        if (dec && xl >= 16 && rd32(xd) == DEC_MAGIC) {
            n->dec_type = rd32(xd + 4);
            n->dec_size = rd64(xd + 8);
        }
    }
    return GZ_OK;
}

static int extent_rec(ap_scan *sc, u64 id, u64 laddr, u64 lenf, u64 pblk)
{
    int r = grow((void **)&sc->ext, &sc->capext, sc->next, sizeof(ap_ext));
    if (r) return r;
    ap_ext *e = &sc->ext[sc->next++];
    e->id = id;
    e->laddr = laddr;
    e->len = lenf & 0x00FFFFFFFFFFFFFFull;
    e->pblk = pblk;
    return GZ_OK;
}

static int drec_rec(ap_scan *sc, u64 id, const u8 *k, u32 kl, const u8 *v, u32 vl)
{
    if (vl < 18 || kl < 10) return GZ_OK;
    /* hashed key: u32 (length in the low 10 bits, hash above); plain key: u16 length.
     * An exact key length decides (both cannot match at once), else the volume flags. */
    u32 pl = rd16(k + 8), hl = kl >= 12 ? rd32(k + 8) & 0x3FF : 0, nl;
    int hashed = kl >= 12 && (hl == kl - 12 || (sc->hashed && pl != kl - 10 && hl < kl - 12));
    const u8 *nm;
    if (hashed) { nl = hl; nm = k + 12; }
    else if (pl <= kl - 10) { nl = pl; nm = k + 10; }
    else return GZ_OK;
    nl = strip_nul(nm, nl);
    if (!nl || (nl == 1 && nm[0] == '.') || (nl == 2 && nm[0] == '.' && nm[1] == '.')) return GZ_OK;
    int r = grow((void **)&sc->dr, &sc->capdr, sc->ndr, sizeof(ap_drec));
    if (r) return r;
    ap_drec *d = &sc->dr[sc->ndr];
    d->parent = id;
    d->child = rd64(v);
    d->name_len = nl;
    if ((r = keep_bytes(sc, nm, nl, &d->name_off))) return r;
    sc->ndr++;
    return GZ_OK;
}

static int fs_rec(ap_bt *w, const u8 *k, u32 kl, const u8 *v, u32 vl)
{
    ap_scan *sc = (ap_scan *)w->u;
    if (kl < 8) return GZ_OK;
    u64 hdr = rd64(k), id = hdr & J_ID_MASK;
    u32 ty = (u32)(hdr >> 60);
    /* keys must not go backwards: keeps every collected table sorted */
    if (sc->any && (id < sc->last_id || (id == sc->last_id && ty < sc->last_type))) return GZ_OK;
    sc->any = 1;
    sc->last_id = id;
    sc->last_type = ty;
    switch (ty) {
    case J_INODE: return inode_rec(sc, id, v, vl);
    case J_XATTR: return xattr_rec(w, sc, id, k, kl, v, vl);
    case J_DREC: return drec_rec(sc, id, k, kl, v, vl);
    case J_EXTENT:
        if (kl < 16 || vl < 16) return GZ_OK;
        if (sc->next && sc->ext[sc->next - 1].id == id && sc->ext[sc->next - 1].laddr >= rd64(k + 8)) return GZ_OK;
        return extent_rec(sc, id, rd64(k + 8), rd64(v), rd64(v + 8));
    default: return GZ_OK;
    }
}

/* file-extent tree of sealed volumes: (private id, logical address) -> (length, block) */
typedef struct { ap_ext *x; u32 n, cap; } fext_load;

static int fext_rec(ap_bt *w, const u8 *k, u32 kl, const u8 *v, u32 vl)
{
    fext_load *f = (fext_load *)w->u;
    if (kl < 16 || vl < 16) return GZ_E_FORMAT;
    u64 id = rd64(k), la = rd64(k + 8);
    if (f->n && (id < f->x[f->n - 1].id || (id == f->x[f->n - 1].id && la <= f->x[f->n - 1].laddr))) return GZ_OK;
    int r = grow((void **)&f->x, &f->cap, f->n, sizeof(ap_ext));
    if (r) return r;
    ap_ext *e = &f->x[f->n++];
    e->id = id;
    e->laddr = la;
    e->len = rd64(v) & 0x00FFFFFFFFFFFFFFull;
    e->pblk = rd64(v + 8);
    return GZ_OK;
}

/* merge the sorted fext extents into the scan's extents */
static int merge_ext(ap_scan *sc, fext_load *f)
{
    if (!f->n) return GZ_OK;
    if (!sc->next) {
        sc->ext = f->x; sc->next = f->n; sc->capext = f->cap;
        f->x = 0; f->n = f->cap = 0;
        return GZ_OK;
    }
    u64 tot = (u64)sc->next + f->n;
    if (tot >= AP_MAXREC) return GZ_E_LIMIT;
    ap_ext *m = (ap_ext *)gz_alloc((size_t)tot * sizeof(ap_ext));
    if (!m) return GZ_E_NOMEM;
    u32 i = 0, j = 0, o = 0;
    while (i < sc->next || j < f->n) {
        int a = j >= f->n || (i < sc->next && (sc->ext[i].id < f->x[j].id ||
                (sc->ext[i].id == f->x[j].id && sc->ext[i].laddr <= f->x[j].laddr)));
        m[o++] = a ? sc->ext[i++] : f->x[j++];
    }
    gz_free(sc->ext);
    sc->ext = m;
    sc->next = sc->capext = o;
    return GZ_OK;
}

static void scan_free(ap_scan *sc)
{
    gz_free(sc->ino);
    gz_free(sc->dr);
    gz_free(sc->ext);
    gz_free(sc->bytes);
    __builtin_memset(sc, 0, sizeof *sc);
}

/* ---------------- entries ---------------- */

static const ap_ino *find_ino(const ap_scan *sc, u64 id)
{
    u32 lo = 0, hi = sc->nino;
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        if (sc->ino[mid].id < id) lo = mid + 1; else hi = mid;
    }
    return lo < sc->nino && sc->ino[lo].id == id ? &sc->ino[lo] : 0;
}

static u32 drec_first(const ap_scan *sc, u64 parent)
{
    u32 lo = 0, hi = sc->ndr;
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        if (sc->dr[mid].parent < parent) lo = mid + 1; else hi = mid;
    }
    return lo;
}

static void set_time(gz_entry *e, u64 ns)
{
    i64 t = (i64)ns;                                  /* ns since 1970, may be negative */
    i64 sec = t / 1000000000, rem = t % 1000000000;
    if (rem < 0) { rem += 1000000000; sec--; }
    e->mtime = gz_unix_to_filetime(sec) + (u64)rem / 100;
    e->mtime_kind = GZ_MT_FILETIME;
}

typedef struct {
    gz_archive *a;
    ap_priv *pv;
    const ap_ctx *x;
    gz_fs1_tree t;
    gz_fs1_set seen;                   /* directories (per volume) */
    i32 vtop[AP_MAXVOL];               /* volume folder nodes */
    u32 nvtop;
} ap_build;

/* read the first bytes of a stream (decmpfs header in a data-stream xattr) */
static int stream_head(const ap_ctx *x, const ap_scan *sc, u64 id, u64 size, u8 *buf, u32 n)
{
    gz_fs1_mem m;
    gz_fs1_mem_init(&m, x->s, size < n ? size : n);
    int r = emit_stream(sc->ext, sc->next, id, x->bshift, x->nblocks, &m.k);
    if (!r) r = gz_fs1_flush(&m.k, 1);
    if (!r && m.k.flushed == n) __builtin_memcpy(buf, m.p, n);
    else if (!r) r = GZ_E_DATA;
    gz_free(m.p);
    return r;
}

static int add_child(ap_build *b, const ap_scan *sc, i32 node, const ap_drec *d, u32 vol)
{
    gz_archive *a = b->a;
    const ap_ino *n = find_ino(sc, d->child);
    if (!n) return GZ_OK;                             /* dangling record */
    u32 type = n->mode & 0xF000;
    if (type != 0x4000 && type != 0x8000 && type != 0xA000) return GZ_OK;   /* devices, fifos, sockets */
    const u8 *nm = sc->bytes + d->name_off;
    gz_entry *e;
    int r = gz_fs1_add_entry(a, &b->t, node, nm, d->name_len, GZ_NE_UTF8, &e);
    if (r) return r;
    e->is_dir = type == 0x4000;
    e->unix_mode = n->mode;
    e->attr = (e->is_dir ? 0x10 : 0) | ((n->mode & 0200) ? 0 : 1) | ((n->bsd & UF_HIDDEN) ? 2 : 0);
    e->off = n->id;
    e->aux = n->uid | (u64)n->gid << 32;
    e->flags = (u16)vol;
    set_time(e, n->mtime);
    if (e->is_dir) {
        int nw = gz_fs1_set_add(&b->seen, n->id);
        if (nw < 0) return GZ_E_NOMEM;
        if (nw && gz_fs1_tree_add(&b->t, node, nm, d->name_len, GZ_NE_UTF8, n->id, 0, vol) == -1) return GZ_E_NOMEM;
        return GZ_OK;
    }
    if (type == 0xA000) {
        e->is_link = 1;
        if (n->link_len) {
            u32 lo;
            if ((r = gz_arc_raw_append(a, sc->bytes + n->link_off, n->link_len, &lo))) return r;
            e->link_off = lo;
            e->link_len = n->link_len;
            return GZ_OK;
        }
    }
    ap_priv *pv = b->pv;
    if ((r = grow((void **)&pv->f, &pv->capf, pv->nf, sizeof(ap_file)))) return r;
    ap_file *f = &pv->f[pv->nf];
    __builtin_memset(f, 0, sizeof *f);
    f->data_id = n->data_id;
    f->vol = vol;
    e->usize = n->size;
    e->csize = n->alloced;
    if ((n->bsd & UF_COMPRESSED) && type == 0x8000 && n->dec.kind) {
        u32 dt = n->dec_type;
        u64 ds = n->dec_size;
        if (n->dec.kind == XV_STREAM && n->dec.size >= 16) {
            u8 h[16];
            if (!stream_head(b->x, sc, n->dec.loc, n->dec.size, h, 16) && rd32(h) == DEC_MAGIC) {
                dt = rd32(h + 4);
                ds = rd64(h + 8);
            }
        }
        if (dt) {
            f->cmp = dt;
            f->dec = n->dec;
            f->rsrc = n->rsrc;
            e->usize = ds;
            e->csize = (dt == 4 || dt == 8 || dt == 10 || dt == 12 || dt == 14) ? n->rsrc.size : n->dec.size - 16;
            e->method = (u16)(dt > 0xFFFE ? 0xFFFE : dt);
        }
    }
    e->aux32 = ++pv->nf;
    return GZ_OK;
}

/* Breadth-first listing of one volume below tree node top (its root directory). */
static int build_volume(ap_build *b, const ap_scan *sc, i32 top, u32 vol)
{
    gz_fs1_set_free(&b->seen);
    if (gz_fs1_set_add(&b->seen, ROOT_DIR_ID) < 0) return GZ_E_NOMEM;
    for (u32 i = (u32)top; i < b->t.nn; i++) {
        if (gz_cancelled(b->x->c)) return GZ_E_CANCEL;
        u64 dir = b->t.n[i].loc;
        for (u32 k = drec_first(sc, dir); k < sc->ndr && sc->dr[k].parent == dir; k++) {
            int r = add_child(b, sc, (i32)i, &sc->dr[k], vol);
            if (r) return r;
        }
    }
    return GZ_OK;
}

/* ---------------- open ---------------- */

typedef struct { u64 xid, blk; } ap_cand;

static int ap_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 4096 || rd32(h + 32) != NX_MAGIC || (rd32(h + 24) & OT_MASK) != OT_NX) return 0;
    u32 bs = rd32(h + 36);
    if (bs < 4096 || bs > 65536 || (bs & (bs - 1)) || rd64(h + 40) < 2) return 0;
    return bs <= n && ck_ok(h, bs) ? 92 : 65;
}

/* container superblock of block size bs (the block count may change on resize) */
static int sb_valid(const u8 *b, u32 bs, u32 bshift)
{
    u64 nb = rd64(b + 40);
    return ck_ok(b, bs) && (rd32(b + 24) & OT_MASK) == OT_NX && rd32(b + 32) == NX_MAGIC &&
           rd32(b + 36) == bs && nb >= 2 && nb < ((u64)1 << (62 - bshift));
}

/* keep the AP_NCAND newest checkpoints, newest first */
static void cand_add(ap_cand *cd, u32 *nc, u64 xid, u64 blk)
{
    u32 i = *nc;
    if (i == AP_NCAND) {
        if (cd[i - 1].xid >= xid) return;
        i--;
    } else {
        (*nc)++;
    }
    cd[i].xid = xid;
    cd[i].blk = blk;
    for (; i > 0 && cd[i - 1].xid < cd[i].xid; i--) {
        ap_cand t = cd[i]; cd[i] = cd[i - 1]; cd[i - 1] = t;
    }
}

typedef struct {
    u64 pa;                            /* volume superblock block */
    u64 oid;
} ap_vref;

/* Container metadata of one checkpoint: object map + volume superblocks. */
static int load_checkpoint(ap_ctx *x, const u8 *sb, u8 *blk, ap_vref *vr, u32 *nvr)
{
    x->xid = rd64(sb + 16);
    x->nblocks = rd64(sb + 40);
    om_load m;
    int r = om_open(x, rd64(sb + 0xA0), blk, &m, 0);
    if (r) return r;
    u32 maxfs = rd32(sb + 0xB4), n = 0;
    if (!maxfs || maxfs > AP_MAXVOL) maxfs = AP_MAXVOL;
    int err = GZ_E_FORMAT;
    for (u32 i = 0; i < maxfs; i++) {
        u64 oid = rd64(sb + 0xB8 + 8 * i), pa;
        if (!oid) continue;
        if ((r = om_find(m.m, m.n, oid, &pa))) { err = r; continue; }
        if ((r = read_obj(x, pa, blk, oid, OT_FS, 0))) { err = r; continue; }
        if (rd32(blk + 32) != APSB_MAGIC) continue;
        vr[n].pa = pa;
        vr[n].oid = oid;
        n++;
    }
    gz_free(m.m);
    *nvr = n;
    return n ? GZ_OK : err;
}

/* volume folder name: volume name, made unique, or "Volume N" */
static int vol_name(ap_build *b, const u8 *vsb, u32 idx, u8 *out)
{
    u32 n = 0;
    while (n < 255 && vsb[0x2C0 + n]) n++;
    __builtin_memcpy(out, vsb + 0x2C0, n);
    for (u32 i = 0; i < n; i++) if (out[i] == '/' || out[i] < 0x20) out[i] = '_';
    if (!n) {
        __builtin_memcpy(out, "Volume ", 7);
        n = 7;
        u32 v = idx + 1;
        if (v >= 100) out[n++] = (u8)('0' + v / 100);
        if (v >= 10) out[n++] = (u8)('0' + v / 10 % 10);
        out[n++] = (u8)('0' + v % 10);
    }
    /* unique among the volume folders added so far */
    u32 base = n;
    for (u32 k = 2; k < 200; k++) {
        int dup = 0;
        for (u32 i = 0; i < b->nvtop && !dup; i++) {
            const gz_fs1_node *nd = &b->t.n[b->vtop[i]];
            if (nd->name_len == n && !__builtin_memcmp(b->t.names + nd->name_off, out, n)) dup = 1;
        }
        if (!dup) break;
        n = base;
        out[n++] = ' '; out[n++] = '(';
        if (k >= 100) out[n++] = (u8)('0' + k / 100);
        if (k >= 10) out[n++] = (u8)('0' + k / 10 % 10);
        out[n++] = (u8)('0' + k % 10);
        out[n++] = ')';
    }
    return (int)n;
}

static int open_volume(ap_build *b, ap_ctx *x, const u8 *vsb, u32 vi, int multi, u8 *blk)
{
    gz_archive *a = b->a;
    ap_priv *pv = b->pv;
    ap_vol *v = &pv->v[vi];
    i32 top = 0;
    gz_entry *ve = 0;
    int r;
    if (multi) {
        u8 nm[300];
        int nl = vol_name(b, vsb, vi, nm);
        if ((r = gz_fs1_add_entry(a, &b->t, 0, nm, (u32)nl, GZ_NE_UTF8, &ve))) return r;
        ve->is_dir = 1;
        ve->attr = 0x10;
        ve->unix_mode = 040755;
        ve->flags = (u16)vi;
        ve->method = 0xFFFF;                         /* volume folder */
        u64 mt = rd64(vsb + 0x100);
        if (mt) set_time(ve, mt);
        top = gz_fs1_tree_add(&b->t, 0, nm, (u32)nl, GZ_NE_UTF8, ROOT_DIR_ID, 0, vi);
        if (top < 0) return GZ_E_NOMEM;
        b->vtop[b->nvtop++] = top;
    } else {
        u32 n = 0;
        while (n < 255 && vsb[0x2C0 + n]) n++;
        if (n && (a->comment_raw = (u8 *)gz_alloc(n))) {
            __builtin_memcpy(a->comment_raw, vsb + 0x2C0, n);
            a->comment_len = n;
            a->comment_enc = GZ_NE_UTF8;
        }
        b->t.n[0].loc = ROOT_DIR_ID;
    }
    if (!(rd64(vsb + 0x108) & FS_UNENCRYPTED)) { v->encrypted = 1; return GZ_E_METHOD; }

    om_load m;
    int crypt = 0;
    if ((r = om_open(x, rd64(vsb + 0x80), blk, &m, &crypt))) return r;
    if (crypt) { gz_free(m.m); v->encrypted = 1; return GZ_E_METHOD; }
    u64 inc = rd64(vsb + 0x38);
    ap_scan sc;
    __builtin_memset(&sc, 0, sizeof sc);
    sc.hashed = (inc & (INC_CASE_INSENS | INC_NORM_INSENS)) != 0;
    int phys = (rd32(vsb + 0x74) & OBJ_STORAGE) == OBJ_PHYSICAL;
    r = bt_walk(x, phys ? 0 : m.m, phys ? 0 : m.n, rd64(vsb + 0x88), OT_FSTREE, fs_rec, &sc);
    gz_free(m.m);
    if (r == GZ_E_METHOD) v->encrypted = 1;
    if (!r && (inc & INC_SEALED) && rd64(vsb + 0x408)) {
        fext_load f;
        __builtin_memset(&f, 0, sizeof f);
        int fr = bt_walk(x, 0, 0, rd64(vsb + 0x408), OT_FEXT, fext_rec, &f);
        if (fr == GZ_E_NOMEM || fr == GZ_E_CANCEL || fr == GZ_E_LIMIT) r = fr;
        else r = merge_ext(&sc, &f);
        gz_free(f.x);
    }
    if (!r) r = build_volume(b, &sc, top, vi);
    if (!r) {
        v->x = sc.ext;                               /* keep the extents for extraction */
        v->n = sc.next;
        sc.ext = 0;
    }
    scan_free(&sc);
    return r;
}

static int ap_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    u8 h[4096];
    int r = gz_src_read_exact(s, 0, h, sizeof h);
    if (r) return r;
    if (rd32(h + 32) != NX_MAGIC) return GZ_E_FORMAT;
    u32 bs = rd32(h + 36);
    if (bs < 4096 || bs > 65536 || (bs & (bs - 1))) return GZ_E_FORMAT;
    u32 bshift = 12;
    while ((1u << bshift) < bs) bshift++;
    u64 nblocks = rd64(h + 40);
    if (nblocks < 2 || nblocks >= ((u64)1 << (62 - bshift))) return GZ_E_FORMAT;

    ap_priv *pv = (ap_priv *)gz_alloc(sizeof(ap_priv));
    if (!pv) return GZ_E_NOMEM;
    a->priv = pv;
    pv->bs = bs;
    pv->bshift = bshift;
    pv->nblocks = nblocks;
    ap_ctx x = { s, c, bs, bshift, nblocks, ~(u64)0 };
    u8 *sb = (u8 *)gz_alloc(bs), *blk = (u8 *)gz_alloc(bs);
    ap_vref *vr = (ap_vref *)gz_alloc(AP_MAXVOL * sizeof(ap_vref));
    if (!sb || !blk || !vr) { r = GZ_E_NOMEM; goto out; }

    /* checkpoint candidates: superblocks in the descriptor area, then block 0 */
    ap_cand cd[AP_NCAND];
    u32 nc = 0;
    if ((r = gz_src_read_exact(s, 0, sb, bs))) goto out;
    int b0 = sb_valid(sb, bs, bshift);
    u64 dbase = rd64(sb + 0x70);
    u32 dblocks = rd32(sb + 0x68);
    if (!(dblocks & 0x80000000u) && dbase && dbase < nblocks) {     /* contiguous area */
        if (dblocks > nblocks - dbase) dblocks = (u32)(nblocks - dbase);
        if (dblocks > AP_DESC_MAX) dblocks = AP_DESC_MAX;
        for (u32 i = 0; i < dblocks; i++) {
            if (gz_src_read_exact(s, (dbase + i) << bshift, blk, bs)) break;
            if (sb_valid(blk, bs, bshift)) cand_add(cd, &nc, rd64(blk + 16), dbase + i);
        }
    }
    if (b0) cand_add(cd, &nc, rd64(sb + 16), 0);
    if (!nc) { r = GZ_E_FORMAT; goto out; }

    /* newest checkpoint first; an older one is used when the container metadata of the newer
     * one is damaged or none of its volumes can be read */
    int err = GZ_E_FORMAT;
    for (u32 ci = 0; ci < nc; ci++) {
        u32 nvr = 0;
        if ((r = gz_src_read_exact(s, cd[ci].blk << bshift, sb, bs))) { err = r; continue; }
        if (!sb_valid(sb, bs, bshift)) continue;
        r = load_checkpoint(&x, sb, blk, vr, &nvr);
        if (r == GZ_E_NOMEM || r == GZ_E_CANCEL) goto out;
        if (r) { if (err == GZ_E_FORMAT) err = r; continue; }
        pv->nblocks = x.nblocks;
        ap_reset(a, pv);
        ap_build b;
        __builtin_memset(&b, 0, sizeof b);
        b.a = a;
        b.pv = pv;
        b.x = &x;
        if ((r = gz_fs1_tree_init(&b.t, GZ_NE_UTF8, GZ_CP_UTF8))) goto out;
        int multi = nvr > 1, nok = 0, nenc = 0;
        for (u32 i = 0; i < nvr; i++) {
            if ((r = read_obj(&x, vr[i].pa, sb, vr[i].oid, OT_FS, 0))) { if (err == GZ_E_FORMAT) err = r; continue; }
            pv->nv = i + 1;
            r = open_volume(&b, &x, sb, i, multi, blk);
            if (r == GZ_E_NOMEM || r == GZ_E_CANCEL || r == GZ_E_LIMIT) break;
            if (!r) nok++;
            else if (r == GZ_E_METHOD) nenc++;
            else if (err == GZ_E_FORMAT) err = r;
            r = GZ_OK;
        }
        gz_fs1_tree_free(&b.t);
        gz_fs1_set_free(&b.seen);
        if (r || nok) goto out;
        if (nenc) { r = GZ_E_METHOD; goto out; }     /* encrypted: older checkpoints are too */
    }
    ap_reset(a, pv);
    r = err;
out:
    gz_free(sb);
    gz_free(blk);
    gz_free(vr);
    return r;
}

/* ---------------- extraction ---------------- */

/* value of an xattr into memory (*p owned by the caller) */
static int xval_read(const ap_priv *pv, const ap_vol *v, gz_src *s, const ap_xval *xv, u32 cap, u8 **p, u32 *n)
{
    *p = 0;
    *n = 0;
    if (xv->size > cap) return GZ_E_LIMIT;
    u32 sz = (u32)xv->size;
    u8 *m = (u8 *)gz_alloc(sz + 1);
    if (!m) return GZ_E_NOMEM;
    int r;
    if (xv->kind == XV_EMB) {
        u8 *b = (u8 *)gz_alloc(pv->bs);
        ap_ctx x = { s, 0, pv->bs, pv->bshift, pv->nblocks, ~(u64)0 };
        r = b ? read_obj(&x, xv->loc, b, 0, 0, 0) : GZ_E_NOMEM;
        if (!r && (u64)xv->off + sz > pv->bs) r = GZ_E_FORMAT;
        if (!r) __builtin_memcpy(m, b + xv->off, sz);
        gz_free(b);
    } else if (xv->kind == XV_STREAM) {
        gz_fs1_mem mm;
        gz_fs1_mem_init(&mm, s, sz);
        r = emit_stream(v->x, v->n, xv->loc, pv->bshift, pv->nblocks, &mm.k);
        if (!r) r = gz_fs1_flush(&mm.k, 1);
        if (!r && mm.k.flushed == sz) __builtin_memcpy(m, mm.p, sz);
        else if (!r) r = GZ_E_DATA;
        gz_free(mm.p);
    } else {
        r = GZ_E_DATA;
    }
    if (r) { gz_free(m); return r; }
    *p = m;
    *n = sz;
    return GZ_OK;
}

/* random-access source over an xattr value (resource fork) */
static gz_src *xval_src(const ap_priv *pv, const ap_vol *v, gz_src *s, const ap_xval *xv, int *err)
{
    if (xv->kind == XV_STREAM) {
        gz_fs1_list l;
        gz_fs1_list_init(&l, xv->size, 1u << 20);
        int r = emit_stream(v->x, v->n, xv->loc, pv->bshift, pv->nblocks, &l.k);
        if (!r) r = gz_fs1_flush(&l.k, 1);
        if (r) { gz_fs1_list_free(&l); *err = r; return 0; }
        gz_src *q = gz_fs1_list_src(s, &l);
        if (!q) *err = GZ_E_NOMEM;
        return q;
    }
    u8 *p;
    u32 n;
    int r = xval_read(pv, v, s, xv, AP_CHUNK, &p, &n);
    if (r) { *err = r; return 0; }
    gz_src *q = gz_src_mem(p, n, 1);
    if (!q) { gz_free(p); *err = GZ_E_NOMEM; }
    return q;
}

typedef struct { u8 *p; u32 cap, n; } ap_buf;
static int buf_put(void *u, const u8 *p, size_t n)
{
    ap_buf *k = (ap_buf *)u;
    if (n > k->cap - k->n) return GZ_E_DATA;
    __builtin_memcpy(k->p + k->n, p, n);
    k->n += (u32)n;
    return GZ_OK;
}

/* sink that stops a zlib stream at the declared size */
typedef struct { gz_out *out; u64 n, limit; } ap_lim;
static int lim_put(void *u, const u8 *p, size_t n)
{
    ap_lim *k = (ap_lim *)u;
    if (n > k->limit - k->n) return GZ_E_DATA;
    k->n += n;
    return k->out->write(k->out, p, n);
}

static int zlib_hdr_ok(const u8 *h)
{
    return (h[0] & 0x0F) == 8 && (h[0] >> 4) <= 7 && !((h[0] << 8 | h[1]) % 31) && !(h[1] & 0x20);
}

static void *lzfse_new(void) { return gz_lzfse_dec_new(); }
static void lzfse_del(void *p) { gz_lzfse_dec_free((gz_lzfse_dec *)p); }

/* decode one block (a whole inline stream or a 64 KiB chunk) of in[0..n) to exactly want bytes */
static int dec_block(u32 kind, const u8 *in, u32 n, u8 *out, u32 want, gz_ctx *c)
{
    size_t on = 0;
    int r;
    if (!want) return GZ_OK;
    if (!n) return GZ_E_DATA;
    if (kind == 1) {                                  /* stored, maybe with a marker byte */
        if (n == want + 1) { in++; n--; }
        if (n != want) return GZ_E_DATA;
        __builtin_memcpy(out, in, want);
        return GZ_OK;
    }
    if (kind == 7) {                                  /* LZVN, 0x06 = stored */
        if (in[0] == 0x06) return dec_block(1, in + 1, n - 1, out, want, c);
        r = gz_lzvn_decode(in, n, out, want, &on, 0);
    } else {                                          /* LZFSE */
        if (n < 4 || in[0] != 'b' || in[1] != 'v' || in[2] != 'x')
            return n == want + 1 ? dec_block(1, in, n, out, want, c) : GZ_E_DATA;
        gz_lzfse_dec *d = c ? (gz_lzfse_dec *)gz_ctx_slot(c, GZ_SLOT_MISC2, lzfse_new, lzfse_del) : 0;
        r = gz_lzfse_decode_ex(d, in, n, out, want, &on, 0);
    }
    if (!r && on != want) r = GZ_E_DATA;
    return r == GZ_E_TRUNC ? GZ_E_DATA : r;
}

/* zlib stream in src[off, off+n) (0xFF/0x?F first byte: stored) -> sink */
static int zlib_run(gz_src *src, u64 off, u64 n, int (*sink)(void *, const u8 *, size_t), void *u, gz_ctx *c)
{
    u8 h[2];
    if (n < 1) return GZ_E_DATA;
    int r = gz_src_read_exact(src, off, h, n < 2 ? 1 : 2);
    if (r) return r;
    if ((h[0] & 0x0F) == 0x0F) {                      /* stored */
        u8 *buf = gz_ctx_buffer(c, 256u << 10);
        if (!buf) return GZ_E_NOMEM;
        off++; n--;
        while (n) {
            u32 k = n < (256u << 10) ? (u32)n : (256u << 10);
            if ((r = gz_src_read_exact(src, off, buf, k)) || (r = sink(u, buf, k))) return r;
            off += k; n -= k;
        }
        return GZ_OK;
    }
    if (n < 2 || !zlib_hdr_ok(h)) return GZ_E_DATA;
    gz_inflater *z = gz_ctx_inflater(c);
    if (!z) return GZ_E_NOMEM;
    gz_pipe pp = { { src, off + 2, off + n, c->cancel }, sink, u };
    gz_stream_io io = { gz_range_read, gz_pipe_write, &pp };
    r = gz_inflate_run(z, &io, 0);
    return r == GZ_E_TRUNC ? GZ_E_DATA : r;
}

/* decmpfs data kept in the xattr (types 1, 3, 7, 9, 11) */
static int dec_inline(const ap_priv *pv, const ap_vol *v, gz_src *s, const ap_file *f, u64 usize,
                      gz_out *out, gz_ctx *c)
{
    u8 *p;
    u32 n;
    int r = xval_read(pv, v, s, &f->dec, AP_INLINE_MAX, &p, &n);
    if (r) return r;
    if (n < 16 || rd32(p) != DEC_MAGIC) { gz_free(p); return GZ_E_DATA; }
    const u8 *d = p + 16;
    u32 dn = n - 16;
    if (f->cmp == 3) {
        gz_src *ms = gz_src_mem(d, dn, 0);
        ap_lim k = { out, 0, usize };
        r = ms ? zlib_run(ms, 0, dn, lim_put, &k, c) : GZ_E_NOMEM;
        if (!r && k.n != usize) r = GZ_E_DATA;
        gz_src_free(ms);
    } else if (usize > AP_INLINE_MAX) {
        r = GZ_E_LIMIT;
    } else if (f->cmp == 1 || f->cmp == 9) {
        if (f->cmp == 9 && dn == usize + 1 && d[0] == 0xCC) { d++; dn--; }   /* stored marker */
        r = dn < usize ? GZ_E_DATA : (usize ? out->write(out, d, (size_t)usize) : GZ_OK);
    } else {
        u8 *o = (u8 *)gz_alloc((size_t)usize + 1);
        r = o ? dec_block(f->cmp == 7 ? 7 : 11, d, dn, o, (u32)usize, c) : GZ_E_NOMEM;
        if (!r && usize) r = out->write(out, o, (size_t)usize);
        gz_free(o);
    }
    gz_free(p);
    return r;
}

/* decmpfs data in 64 KiB chunks in the resource fork (types 4, 8, 10, 12) */
static int dec_rsrc(const ap_priv *pv, const ap_vol *v, gz_src *s, const ap_file *f, u64 usize,
                    gz_out *out, gz_ctx *c)
{
    if (!f->rsrc.kind) return GZ_E_DATA;
    int r = GZ_OK;
    gz_src *rs = xval_src(pv, v, s, &f->rsrc, &r);
    if (!rs) return r ? r : GZ_E_NOMEM;
    u64 nch = (usize + AP_CHUNK - 1) / AP_CHUNK, base = 0, tnext, prev = 0;
    int zl = f->cmp == 4;
    u32 kind = f->cmp == 8 ? 7 : f->cmp == 12 ? 11 : 1, es = zl ? 8 : 4;
    u8 h[16];
    if (zl) {
        /* classic resource fork: BE header (data offset first), resource length, then
         * the 'cmpf' data: LE block count and (offset, size) pairs relative to base */
        if (!(r = gz_src_read_exact(rs, 0, h, 16))) {
            base = (u64)rd32be(h) + 4;
            if (!(r = gz_src_read_exact(rs, base, h, 4)) && rd32(h) != nch) r = GZ_E_DATA;
        }
        tnext = base + 4;
    } else {
        /* count + 1 LE offsets from the start of the fork, the first one = table size */
        if (!(r = gz_src_read_exact(rs, 0, h, 4)) && (prev = rd32(h)) != (nch + 1) * 4) r = GZ_E_DATA;
        tnext = 4;
    }
    u8 *ib = r ? 0 : gz_ctx_buffer(c, AP_CIN_MAX + AP_CHUNK);
    if (!r && !ib) r = GZ_E_NOMEM;
    u8 *ob = ib + AP_CIN_MAX;
    u8 t[4096];
    u32 tn = 0, tp = 0;                               /* table entries buffered in t */
    for (u64 i = 0; !r && i < nch; i++) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        if (tp == tn) {
            u64 left = (nch - i) * es;
            u32 tw = left < sizeof t ? (u32)left : (u32)sizeof t;
            if ((r = gz_src_read_exact(rs, tnext, t, tw))) break;
            tnext += tw;
            tn = tw / es;
            tp = 0;
        }
        u64 off, sz;
        if (zl) {
            off = base + rd32(t + tp * 8);
            sz = rd32(t + tp * 8 + 4);
        } else {
            u64 end = rd32(t + tp * 4);
            if (end < prev) { r = GZ_E_DATA; break; }
            off = prev;
            sz = end - prev;
            prev = end;
        }
        tp++;
        u32 want = (u32)(i + 1 < nch ? AP_CHUNK : usize - i * AP_CHUNK);
        if (off > rs->size || sz > rs->size - off || sz > AP_CIN_MAX || !sz) { r = GZ_E_DATA; break; }
        if ((r = gz_src_read_exact(rs, off, ib, (u32)sz))) break;
        if (zl && (ib[0] & 0x0F) != 0x0F) {           /* zlib chunk */
            gz_src *ms = gz_src_mem(ib, sz, 0);
            ap_buf k = { ob, want, 0 };
            r = ms ? zlib_run(ms, 0, sz, buf_put, &k, c) : GZ_E_NOMEM;
            if (!r && k.n != want) r = GZ_E_DATA;
            gz_src_free(ms);
        } else {
            r = dec_block(zl ? 1 : kind, ib, (u32)sz, ob, want, c);
        }
        if (!r) r = out->write(out, ob, want);
    }
    gz_src_free(rs);
    return r;
}

static int ap_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    const ap_priv *pv = (const ap_priv *)a->priv;
    const gz_entry *e = &a->e[idx];
    if (e->flags < pv->nv && pv->v[e->flags].encrypted && e->method == 0xFFFF) return GZ_E_METHOD;
    const ap_file *f = e->aux32 && e->aux32 <= pv->nf ? &pv->f[e->aux32 - 1] : 0;
    if (f && f->cmp && f->cmp != 1 && f->cmp != 3 && f->cmp != 4 && f->cmp != 7 && f->cmp != 8 &&
        f->cmp != 9 && f->cmp != 10 && f->cmp != 11 && f->cmp != 12)
        return GZ_E_METHOD;                           /* LZBITMAP, dedup, ... */
    int r = out->open(out, idx);
    if (r) return r;
    if (!f || !e->usize) return out->close(out, idx, GZ_OK);
    const ap_vol *v = &pv->v[f->vol];
    int st;
    if (!f->cmp) {
        gz_fs1_copy w;
        st = gz_fs1_copy_init(&w, s, out, c, e->usize);
        if (!st) st = emit_stream(v->x, v->n, f->data_id, pv->bshift, pv->nblocks, &w.k);
        if (!st) st = gz_fs1_flush(&w.k, 1);
    } else if (f->cmp == 4 || f->cmp == 8 || f->cmp == 10 || f->cmp == 12) {
        st = dec_rsrc(pv, v, s, f, e->usize, out, c);
    } else {
        st = dec_inline(pv, v, s, f, e->usize, out, c);
    }
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static gz_src *ap_view(gz_archive *a, gz_src *s, u32 idx)
{
    const ap_priv *pv = (const ap_priv *)a->priv;
    const gz_entry *e = &a->e[idx];
    const ap_file *f = e->aux32 && e->aux32 <= pv->nf ? &pv->f[e->aux32 - 1] : 0;
    if (!f || f->cmp || e->is_dir || e->is_link) return 0;
    if (!e->usize) return gz_src_sub(s, 0, 0);
    const ap_vol *v = &pv->v[f->vol];
    gz_fs1_list l;
    gz_fs1_list_init(&l, e->usize, 1u << 20);
    int r = emit_stream(v->x, v->n, f->data_id, pv->bshift, pv->nblocks, &l.k);
    if (!r) r = gz_fs1_flush(&l.k, 1);
    if (r) { gz_fs1_list_free(&l); return 0; }
    return gz_fs1_list_src(s, &l);
}

static void ap_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    const char *m;
    switch (e->method) {
    case 0: case 0xFFFF: return;
    case 1: case 9: case 10: m = "Store"; break;
    case 3: case 4: m = "zlib"; break;
    case 7: case 8: m = "LZVN"; break;
    case 11: case 12: m = "LZFSE"; break;
    case 13: case 14: m = "LZBITMAP"; break;
    default: m = "decmpfs"; break;
    }
    u32 i = 0;
    for (; m[i] && i + 1 < cap; i++) buf[i] = m[i];
    if (cap) buf[i] = 0;
}

GZ_FORMAT(gz_fmt_apfs)
const gz_format gz_fmt_apfs = {
    "APFS", "apfs img", 0, ap_probe, ap_open, ap_close, ap_extract, 0, 0, ap_method, ap_view, 0
};
