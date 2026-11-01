/*
 * 고깃ZIP - ext2 / ext3 / ext4 file system images
 *
 *   32/64-bit group descriptors (meta_bg, flex_bg), 128..4096-byte inodes,
 *   extent trees of any depth (unwritten extents read as zeros), single /
 *   double / triple indirect blocks, sparse holes, inline data (files,
 *   directories, symlinks), fast and slow symlinks, htree directories (leaf
 *   blocks are read linearly), files > 4 GiB, nanosecond / epoch time bits.
 *   Encrypted files give GZ_E_METHOD. The journal is not replayed.
 *
 *   Hostile images: every block number is checked against the volume size,
 *   extents must be in increasing logical order (so a tree cannot revisit a
 *   node), directories are read once (inode set) within a total budget of the
 *   volume size, and depth is limited.
 */
#include "fs1.h"

/* superblock features */
#define COMPAT_HAS_JOURNAL   0x0004u
#define COMPAT_SPARSE_SUPER2 0x0200u
#define INCOMPAT_JOURNAL_DEV 0x0008u
#define INCOMPAT_META_BG     0x0010u
#define INCOMPAT_EXTENTS     0x0040u
#define INCOMPAT_64BIT       0x0080u
#define INCOMPAT_FLEX_BG     0x0200u
#define INCOMPAT_INLINE      0x8000u
#define RO_SPARSE_SUPER      0x0001u
#define RO_HUGE_FILE         0x0008u
#define RO_GDT_CSUM          0x0010u
#define RO_DIR_NLINK         0x0020u
#define RO_EXTRA_ISIZE       0x0040u
#define RO_BIGALLOC          0x0200u
#define RO_METADATA_CSUM     0x0400u
/* inode flags */
#define FL_ENCRYPT  0x00000800u
#define FL_HUGE     0x00040000u
#define FL_EXTENTS  0x00080000u
#define FL_INLINE   0x10000000u

#define EXT_IRL_MAX 4096u              /* inode bytes we read (inline data lives in the first ones) */
#define EXT_LINK_MAX 4095u

typedef struct {
    u32 bs, bshift;
    u64 nblocks;
    u32 ipg, isz, irl;                 /* inodes per group, inode size, bytes read per inode */
    u32 ninodes, ngroups;
    u64 *itab;                         /* inode table block per group (0 = unusable group) */
    u32 compat, incompat, ro;
} ext_fs;

static int is_pow2(u32 x) { return x && !(x & (x - 1)); }

/* superblock sanity shared by probe and open; returns bshift or 0 */
static u32 sb_check(const u8 *sb)
{
    if (rd16(sb + 56) != 0xEF53) return 0;
    u32 lg = rd32(sb + 24), rev = rd32(sb + 76);
    if (lg > 6 || rev > 1) return 0;
    if (!rd32(sb + 32) || !rd32(sb + 40) || !rd32(sb + 0)) return 0;
    if (rev == 1) {
        u32 isz = rd16(sb + 88);
        if (isz < 128 || !is_pow2(isz) || isz > (1024u << lg)) return 0;
    }
    if (rd32(sb + 20) > 1) return 0;   /* s_first_data_block */
    return 10 + lg;
}

static int ext_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 2048 || !sb_check(h + 1024)) return 0;
    return 85;
}

/* ---------------- inodes ---------------- */

typedef struct { u64 base; u32 len; u8 *buf; } ext_icache;   /* 64 KiB window at open */

static int ext_inode(const ext_fs *fs, gz_src *s, ext_icache *ic, u32 ino, u8 *out)
{
    if (!ino || ino > fs->ninodes) return GZ_E_FORMAT;
    u32 g = (ino - 1) / fs->ipg, i = (ino - 1) % fs->ipg;
    if (g >= fs->ngroups || !fs->itab[g]) return GZ_E_FORMAT;
    u64 off = (fs->itab[g] << fs->bshift) + (u64)i * fs->isz;
    u32 n = fs->irl;
    if (!ic) return gz_src_read_exact(s, off, out, n);
    if (off < ic->base || off + n > ic->base + ic->len) {
        u64 base = off & ~(u64)0xFFFF;
        if (base >= s->size) return GZ_E_TRUNC;
        u32 want = s->size - base < 65536 ? (u32)(s->size - base) : 65536;
        ic->len = 0;
        int r = gz_src_read_exact(s, base, ic->buf, want);
        if (r) return r;
        ic->base = base;
        ic->len = want;
        if (off + n > base + want) return GZ_E_TRUNC;
    }
    __builtin_memcpy(out, ic->buf + (off - ic->base), n);
    return GZ_OK;
}

static u64 ino_size(const u8 *ib) { return rd32(ib + 4) | (u64)rd32(ib + 0x6C) << 32; }

/* system.data extended attribute in the inode body (rest of an inline file / directory) */
static void inline_ea(const ext_fs *fs, const u8 *ib, const u8 **p, u32 *n)
{
    *p = 0;
    *n = 0;
    if (fs->irl <= 128 + 4) return;
    u32 extra = rd16(ib + 0x80), st = 128 + extra;
    if ((extra & 3) || st + 4 > fs->irl || rd32(ib + st) != 0xEA020000u) return;
    u32 e0 = st + 4, pos = e0;
    while (pos + 16 <= fs->irl && rd32(ib + pos)) {
        u32 nl = ib[pos], idx = ib[pos + 1], vo = rd16(ib + pos + 2), vs = rd32(ib + pos + 8);
        if (pos + 16 + nl > fs->irl) return;
        if (idx == 7 && nl == 4 && !__builtin_memcmp(ib + pos + 16, "data", 4) && !rd32(ib + pos + 4)) {
            if ((u64)e0 + vo + vs <= fs->irl) { *p = ib + e0 + vo; *n = vs; }
            return;
        }
        pos += (16 + nl + 3) & ~3u;
    }
}

/* ---------------- block mapping ---------------- */

typedef struct {
    const ext_fs *fs;
    gz_src *s;
    gz_fs1_sink *k;
    u64 next;                          /* next logical block (extents) */
    u64 nodes;                         /* extent nodes read */
    u8 *lvl[5];
} ext_map;

static u8 *lvl_buf(ext_map *m, int i)
{
    if (!m->lvl[i]) m->lvl[i] = (u8 *)gz_alloc(m->fs->bs);
    return m->lvl[i];
}

static int ext_extents(ext_map *m, const u8 *nd, u32 nlen, int want_depth, int level)
{
    const ext_fs *fs = m->fs;
    if (nlen < 12 || rd16(nd) != 0xF30A) return GZ_E_FORMAT;
    u32 cnt = rd16(nd + 2), max = rd16(nd + 4), depth = rd16(nd + 6);
    if (cnt > max || 12 + (u64)max * 12 > nlen) return GZ_E_FORMAT;
    if (want_depth < 0 ? depth > 5 : depth != (u32)want_depth) return GZ_E_FORMAT;
    const u8 *x = nd + 12;
    int r;
    if (depth == 0) {
        for (u32 i = 0; i < cnt; i++, x += 12) {
            u64 lb = rd32(x), pb = (u64)rd16(x + 6) << 32 | rd32(x + 8);
            u32 len = rd16(x + 4);
            int unwritten = len > 32768;
            if (unwritten) len -= 32768;
            if (!len || lb < m->next || pb >= fs->nblocks || len > fs->nblocks - pb) return GZ_E_FORMAT;
            if (lb > m->next && (r = gz_fs1_emit(m->k, GZ_FS1_HOLE, (lb - m->next) << fs->bshift))) return r;
            m->next = lb + len;
            r = gz_fs1_emit(m->k, unwritten ? GZ_FS1_HOLE : pb << fs->bshift, (u64)len << fs->bshift);
            if (r) return r;
        }
        return GZ_OK;
    }
    if (level >= 5 || (!cnt && level)) return GZ_E_FORMAT;
    u8 *buf = lvl_buf(m, level);
    if (!buf) return GZ_E_NOMEM;
    for (u32 i = 0; i < cnt; i++, x += 12) {
        if (m->k->pos >= m->k->limit || ((u64)rd32(x) << fs->bshift) >= m->k->limit) return GZ_FS1_FULL;
        u64 ch = rd32(x + 4) | (u64)rd16(x + 8) << 32;
        if (!ch || ch >= fs->nblocks || ++m->nodes > fs->nblocks) return GZ_E_FORMAT;
        if ((r = gz_src_read_exact(m->s, ch << fs->bshift, buf, fs->bs))) return r;
        if ((r = ext_extents(m, buf, fs->bs, (int)depth - 1, level + 1))) return r;
    }
    return GZ_OK;
}

static int ext_blk(ext_map *m, u32 p)
{
    if (!p) return gz_fs1_emit(m->k, GZ_FS1_HOLE, m->fs->bs);
    if (p >= m->fs->nblocks) return GZ_E_FORMAT;
    return gz_fs1_emit(m->k, (u64)p << m->fs->bshift, m->fs->bs);
}

/* indirect block of level lvl (1 single, 2 double, 3 triple) */
static int ext_ind(ext_map *m, u32 p, int lvl)
{
    const ext_fs *fs = m->fs;
    if (m->k->pos >= m->k->limit) return GZ_FS1_FULL;
    if (!p) return gz_fs1_emit(m->k, GZ_FS1_HOLE, (u64)fs->bs << (lvl * (fs->bshift - 2)));
    if (p >= fs->nblocks) return GZ_E_FORMAT;
    u8 *buf = lvl_buf(m, lvl - 1);
    if (!buf) return GZ_E_NOMEM;
    int r = gz_src_read_exact(m->s, (u64)p << fs->bshift, buf, fs->bs);
    if (r) return r;
    for (u32 i = 0; i < fs->bs; i += 4) {
        u32 q = rd32(buf + i);
        r = lvl == 1 ? ext_blk(m, q) : ext_ind(m, q, lvl - 1);
        if (r) return r;
    }
    return GZ_OK;
}

/* Emit the data runs of an inode (not inline) into k; pads a sparse tail with zeros. */
static int ext_map_data(const ext_fs *fs, gz_src *s, const u8 *ib, gz_fs1_sink *k)
{
    ext_map m;
    __builtin_memset(&m, 0, sizeof m);
    m.fs = fs; m.s = s; m.k = k;
    const u8 *ibl = ib + 0x28;
    int r = GZ_OK;
    if (rd32(ib + 0x20) & FL_EXTENTS) {
        r = ext_extents(&m, ibl, 60, -1, 0);
    } else {
        for (u32 i = 0; i < 12 && !r; i++) r = ext_blk(&m, rd32(ibl + 4 * i));
        for (int l = 1; l <= 3 && !r; l++) r = ext_ind(&m, rd32(ibl + 44 + 4 * l), l);
    }
    for (int i = 0; i < 5; i++) gz_free(m.lvl[i]);
    if (r == GZ_FS1_FULL) r = GZ_OK;
    return r ? r : gz_fs1_flush(k, 1);
}

/* Inline data: up to 60 bytes in i_block, the rest in system.data. Returns bytes available. */
static u32 inline_parts(const ext_fs *fs, const u8 *ib, const u8 **p2, u32 *n2)
{
    inline_ea(fs, ib, p2, n2);
    return 60 + *n2;
}

static int write_inline(const ext_fs *fs, const u8 *ib, u64 size, gz_out *out)
{
    const u8 *p2;
    u32 n2;
    u64 avail = inline_parts(fs, ib, &p2, &n2);
    u32 n1 = size < 60 ? (u32)size : 60;
    int r = out->write(out, ib + 0x28, n1);
    if (!r && size > 60) {
        u64 rest = size - 60;
        r = out->write(out, p2 ? p2 : ib, (size_t)(rest < n2 ? rest : n2));
    }
    if (!r && size > avail) r = GZ_E_DATA;
    return r;
}

/* ---------------- directories ---------------- */

typedef struct {
    gz_archive *a;
    gz_src *s;
    gz_ctx *c;
    ext_fs *fs;
    gz_fs1_tree t;
    gz_fs1_set seen;
    ext_icache ic;
    u8 *ib;                            /* inode of the entry being added (irl bytes) */
    u8 *dib;                           /* inode of the directory being read */
    u8 *dbuf;                          /* directory block chunk */
    u32 dcap;
    u64 budget;                        /* directory bytes still allowed */
} ext_walk;

static void ext_time(gz_entry *e, const ext_fs *fs, const u8 *ib)
{
    i64 sec = (i32)rd32(ib + 0x10);
    u32 ns = 0;
    if (fs->irl >= 0x8C && rd16(ib + 0x80) >= 12) {
        u32 ex = rd32(ib + 0x88);
        sec += (i64)(ex & 3) << 32;
        ns = ex >> 2;
        if (ns > 999999999) ns = 0;
    }
    e->mtime = gz_unix_to_filetime(sec) + ns / 100;
    e->mtime_kind = GZ_MT_FILETIME;
}

static int ext_symlink(ext_walk *w, gz_entry *e, const u8 *ib, u64 size, u32 fl)
{
    const ext_fs *fs = w->fs;
    if ((fl & FL_ENCRYPT) || !size || size > EXT_LINK_MAX) return GZ_OK;   /* target = data */
    const u8 *tp = 0;
    u32 n = (u32)size, lo, lo2;
    gz_fs1_mem m;
    m.p = 0;
    if (fl & FL_INLINE) {
        const u8 *p2;
        u32 n2;
        if (size > inline_parts(fs, ib, &p2, &n2)) return GZ_OK;
        if (n <= 60) {
            tp = ib + 0x28;
        } else {                       /* two appends in a row stay contiguous in a->raw */
            int r = gz_arc_raw_append(w->a, ib + 0x28, 60, &lo);
            if (!r) r = gz_arc_raw_append(w->a, p2, n - 60, &lo2);
            if (r) return r;
            e->link_off = lo;
            e->link_len = n;
            e->usize = e->csize = 0;
            return GZ_OK;
        }
    } else if (size < 60 && (!(fl & FL_EXTENTS) || rd16(ib + 0x28) != 0xF30A)) {
        tp = ib + 0x28;                                   /* fast symlink */
    } else {
        gz_fs1_mem_init(&m, w->s, size);
        int r = ext_map_data(fs, w->s, ib, &m.k);
        if (r == GZ_E_NOMEM) { gz_free(m.p); return r; }
        if (r || m.k.flushed != size) { gz_free(m.p); return GZ_OK; }
        tp = m.p;
    }
    int r = gz_arc_raw_append(w->a, tp, n, &lo);
    gz_free(m.p);
    if (r) return r;
    e->link_off = lo;
    e->link_len = n;
    e->usize = e->csize = 0;
    return GZ_OK;
}

static int ext_add(ext_walk *w, i32 node, u32 ino, const u8 *name, u32 nl, int enc_dir)
{
    const ext_fs *fs = w->fs;
    u8 *ib = w->ib;
    if (ext_inode(fs, w->s, &w->ic, ino, ib)) return GZ_OK;          /* bad inode: skip */
    u32 mode = rd16(ib), links = rd16(ib + 0x1A), type = mode & 0xF000;
    if (!mode || !links) return GZ_OK;                                /* deleted */
    if (type != 0x4000 && type != 0x8000 && type != 0xA000) return GZ_OK;   /* devices, fifos */
    u8 hex[256];
    if (enc_dir) {                    /* encrypted names: show the cipher text in hex */
        static const char hd[] = "0123456789abcdef";
        u32 k = 0;
        for (u32 i = 0; i < nl && k + 2 <= 254; i++) { hex[k++] = (u8)hd[name[i] >> 4]; hex[k++] = (u8)hd[name[i] & 15]; }
        name = hex;
        nl = k;
    }
    gz_entry *e;
    int r = gz_fs1_add_entry(w->a, &w->t, node, name, nl, GZ_NE_LEGACY, &e);
    if (r) return r;
    u32 fl = rd32(ib + 0x20);
    u64 size = ino_size(ib);
    u64 blocks = rd32(ib + 0x1C) | ((fs->ro & RO_HUGE_FILE) ? (u64)rd16(ib + 0x74) << 32 : 0);
    e->is_dir = type == 0x4000;
    e->unix_mode = mode;
    e->attr = (e->is_dir ? 0x10 : 0) | ((mode & 0200) ? 0 : 1);
    e->usize = e->is_dir ? 0 : size;
    e->csize = (fl & FL_HUGE) ? blocks << fs->bshift : blocks * 512;
    if (fl & FL_INLINE) e->csize = 0;
    e->off = ino;
    e->aux = rd16(ib + 2) | (u32)rd16(ib + 0x78) << 16 | (u64)(rd16(ib + 0x18) | (u32)rd16(ib + 0x7A) << 16) << 32;
    e->aux32 = fl;
    ext_time(e, fs, ib);
    if (type == 0xA000) {
        e->is_link = 1;
        return ext_symlink(w, e, ib, size, fl);
    }
    if (e->is_dir) {
        int nw = gz_fs1_set_add(&w->seen, ino);
        if (nw < 0) return GZ_E_NOMEM;
        if (nw && gz_fs1_tree_add(&w->t, node, name, nl, GZ_NE_LEGACY, ino, size, (fl & FL_ENCRYPT) ? 1 : 0) == -1)
            return GZ_E_NOMEM;
    }
    return GZ_OK;
}

static u32 rec_len(u32 v, u32 bs)
{
    if (bs < 65536) return v;
    if (v == 65535 || v == 0) return bs;
    return (v & 65532) | ((v & 3) << 16);
}

/* linear dirent list (one directory block, or an inline area) */
static int parse_dirents(ext_walk *w, i32 node, const u8 *p, u32 len, int enc_dir)
{
    u32 off = 0;
    while (off + 8 <= len) {
        u32 ino = rd32(p + off), rl = rec_len(rd16(p + off + 4), w->fs->bs), nl = p[off + 6];
        if (rl < 8 || (rl & 3) || rl > len - off) break;
        if (ino && nl && 8 + nl <= rl) {
            const u8 *nm = p + off + 8;
            if (!(nm[0] == '.' && (nl == 1 || (nl == 2 && nm[1] == '.')))) {
                int r = ext_add(w, node, ino, nm, nl, enc_dir);
                if (r) return r;
            }
        }
        off += rl;
    }
    return GZ_OK;
}

typedef struct {
    gz_fs1_sink k;
    ext_walk *w;
    i32 node;
    int enc;
    u8 *buf;
    u32 cap;
} ext_dirsink;

static int dir_put(gz_fs1_sink *k, u64 poff, u64 len)
{
    ext_dirsink *d = (ext_dirsink *)k;
    ext_walk *w = d->w;
    u32 bs = w->fs->bs;
    if (poff == GZ_FS1_HOLE) return GZ_OK;
    while (len) {
        if (gz_cancelled(w->c)) return GZ_E_CANCEL;
        u32 n = len < d->cap ? (u32)len : d->cap;
        int r = gz_src_read_exact(w->s, poff, d->buf, n);
        if (r) return r;
        for (u32 o = 0; o < n; o += bs)
            if ((r = parse_dirents(w, d->node, d->buf + o, n - o < bs ? n - o : bs, d->enc))) return r;
        poff += n;
        len -= n;
    }
    return GZ_OK;
}

static int ext_dir(ext_walk *w, i32 node)
{
    const ext_fs *fs = w->fs;
    u32 ino = (u32)w->t.n[node].loc;
    int enc = (int)w->t.n[node].aux;
    u8 *ib = w->dib;                   /* own buffer: ext_add reuses w->ib for the entries */
    int r = ext_inode(fs, w->s, &w->ic, ino, ib);
    if (r) return r;
    if ((rd16(ib) & 0xF000) != 0x4000) return GZ_E_FORMAT;
    if (rd32(ib + 0x20) & FL_INLINE) {
        const u8 *p2;
        u32 n2;
        inline_ea(fs, ib, &p2, &n2);
        r = parse_dirents(w, node, ib + 0x28 + 4, 56, enc);
        if (!r && p2) r = parse_dirents(w, node, p2, n2, enc);
        return r;
    }
    u64 size = ino_size(ib);
    if (size > w->budget) size = w->budget;
    if (!size) return GZ_OK;
    ext_dirsink d;
    gz_fs1_sink_init(&d.k, dir_put, size);
    d.w = w;
    d.node = node;
    d.enc = enc;
    d.cap = w->dcap;
    d.buf = w->dbuf;
    r = ext_map_data(fs, w->s, ib, &d.k);
    w->budget -= d.k.pos < w->budget ? d.k.pos : w->budget;
    return r;
}

/* ---------------- open ---------------- */

static int test_root(u32 a, u32 b)
{
    for (;;) {
        if (a < b) return 0;
        if (a == b) return 1;
        if (a % b) return 0;
        a /= b;
    }
}

static int has_super(const ext_fs *fs, const u8 *sb, u32 g)
{
    if (g == 0) return 1;
    if (fs->compat & COMPAT_SPARSE_SUPER2) return g == rd32(sb + 0x24C) || g == rd32(sb + 0x250);
    if (g <= 1 || !(fs->ro & RO_SPARSE_SUPER)) return 1;
    if (!(g & 1)) return 0;
    return test_root(g, 3) || test_root(g, 5) || test_root(g, 7);
}

static void ext_close(gz_archive *a)
{
    ext_fs *fs = (ext_fs *)a->priv;
    if (!fs) return;
    gz_free(fs->itab);
    gz_free(fs);
    a->priv = 0;
}

static int load_groups(ext_fs *fs, gz_src *s, const u8 *sb)
{
    u32 fdb = rd32(sb + 20), bpg = rd32(sb + 32);
    u32 dsz = (fs->incompat & INCOMPAT_64BIT) ? rd16(sb + 0xFE) : 32;
    if (dsz < 32 || dsz > fs->bs || !is_pow2(dsz)) return GZ_E_FORMAT;
    u32 dpb = fs->bs / dsz, ndb = (fs->ngroups + dpb - 1) / dpb;
    u32 first_meta = (fs->incompat & INCOMPAT_META_BG) ? rd32(sb + 0x104) : 0xFFFFFFFFu;
    int adj = fs->bs == 1024 && (fs->ro & RO_BIGALLOC) && rd32(sb + 28) > rd32(sb + 24);
    u64 itb = ((u64)fs->ipg * fs->isz + fs->bs - 1) >> fs->bshift;    /* inode table blocks */
    fs->itab = (u64 *)gz_alloc((size_t)fs->ngroups * sizeof(u64));
    u8 *blk = (u8 *)gz_alloc(fs->bs);
    if (!fs->itab || !blk) { gz_free(blk); return GZ_E_NOMEM; }
    int r = GZ_OK;
    u32 good = 0;
    for (u32 i = 0; i < ndb; i++) {
        u64 loc;
        if (i < first_meta) loc = (u64)fdb + 1 + i;
        else {
            u64 bg = (u64)i * dpb;
            loc = fdb + bg * bpg + (u64)has_super(fs, sb, (u32)bg);
        }
        if (i == 0) loc += (u64)adj;
        if (loc >= fs->nblocks || gz_src_read_exact(s, loc << fs->bshift, blk, fs->bs)) {
            if (i == 0) { r = GZ_E_FORMAT; break; }
            continue;                       /* groups of a lost descriptor block stay unusable */
        }
        for (u32 j = 0; j < dpb; j++) {
            u64 g = (u64)i * dpb + j;
            if (g >= fs->ngroups) break;
            const u8 *d = blk + j * dsz;
            u64 it = rd32(d + 8) | (dsz >= 64 ? (u64)rd32(d + 0x28) << 32 : 0);
            if (it && it < fs->nblocks && itb <= fs->nblocks - it) { fs->itab[g] = it; good++; }
        }
    }
    gz_free(blk);
    if (!r && !good) r = GZ_E_FORMAT;
    return r;
}

static int ext_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    u8 sb[1024];
    int r = gz_src_read_exact(s, 1024, sb, 1024);
    if (r) return r;
    u32 bshift = sb_check(sb);
    if (!bshift) return GZ_E_FORMAT;
    ext_fs *fs = (ext_fs *)gz_alloc(sizeof(ext_fs));
    if (!fs) return GZ_E_NOMEM;
    a->priv = fs;
    fs->bshift = bshift;
    fs->bs = 1u << bshift;
    fs->compat = rd32(sb + 92);
    fs->incompat = rd32(sb + 96);
    fs->ro = rd32(sb + 100);
    if (fs->incompat & INCOMPAT_JOURNAL_DEV) return GZ_E_FORMAT;      /* external journal */
    fs->nblocks = rd32(sb + 4) | ((fs->incompat & INCOMPAT_64BIT) ? (u64)rd32(sb + 0x150) << 32 : 0);
    u32 fdb = rd32(sb + 20), bpg = rd32(sb + 32);
    fs->ipg = rd32(sb + 40);
    fs->ninodes = rd32(sb + 0);
    fs->isz = rd32(sb + 76) ? rd16(sb + 88) : 128;
    fs->irl = fs->isz < EXT_IRL_MAX ? fs->isz : EXT_IRL_MAX;
    if (fs->nblocks <= fdb || fs->nblocks >= ((u64)1 << (63 - bshift))) return GZ_E_FORMAT;
    if (fs->ipg > 8 * fs->bs) return GZ_E_FORMAT;
    u64 ng = (fs->nblocks - fdb + bpg - 1) / bpg;
    if (!ng || ng > (1u << 22)) return GZ_E_LIMIT;
    fs->ngroups = (u32)ng;
    if ((u64)fs->ninodes > ng * fs->ipg) return GZ_E_FORMAT;
    if ((r = load_groups(fs, s, sb))) return r;

    if (fs->incompat & (INCOMPAT_EXTENTS | INCOMPAT_64BIT | INCOMPAT_FLEX_BG | INCOMPAT_INLINE) ||
        (fs->ro & (RO_HUGE_FILE | RO_GDT_CSUM | RO_DIR_NLINK | RO_EXTRA_ISIZE | RO_BIGALLOC | RO_METADATA_CSUM)))
        gz_arc_set_type(a, "ext4");
    else gz_arc_set_type(a, (fs->compat & COMPAT_HAS_JOURNAL) ? "ext3" : "ext2");
    u32 ln = 0;
    while (ln < 16 && sb[120 + ln]) ln++;
    if (ln && (a->comment_raw = (u8 *)gz_alloc(ln))) {
        __builtin_memcpy(a->comment_raw, sb + 120, ln);
        a->comment_len = ln;
        a->comment_enc = GZ_NE_UTF8;
    }

    ext_walk w;
    __builtin_memset(&w, 0, sizeof w);
    w.a = a; w.s = s; w.c = c; w.fs = fs;
    w.budget = fs->nblocks << fs->bshift;
    w.ic.buf = (u8 *)gz_alloc(65536);
    w.ib = (u8 *)gz_alloc(EXT_IRL_MAX);
    w.dib = (u8 *)gz_alloc(EXT_IRL_MAX);
    w.dcap = fs->bs > 65536 ? fs->bs : 65536;
    w.dbuf = (u8 *)gz_alloc(w.dcap);
    r = (w.ic.buf && w.ib && w.dib && w.dbuf) ? gz_fs1_tree_init(&w.t, GZ_NE_LEGACY, GZ_CP_UTF8) : GZ_E_NOMEM;
    if (!r) {
        w.t.n[0].loc = 2;                                 /* root directory inode */
        if (gz_fs1_set_add(&w.seen, 2) < 0) r = GZ_E_NOMEM;
    }
    for (u32 i = 0; !r && i < w.t.nn; i++) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        int rr = ext_dir(&w, (i32)i);
        if (rr == GZ_E_NOMEM || rr == GZ_E_CANCEL || (rr && i == 0 && !a->n)) r = rr;
        if (c && c->progress && !(i & 63)) c->progress(c->progress_user, i, w.t.nn);
    }
    gz_fs1_tree_free(&w.t);
    gz_fs1_set_free(&w.seen);
    gz_free(w.ic.buf);
    gz_free(w.ib);
    gz_free(w.dib);
    gz_free(w.dbuf);
    return r;
}

/* ---------------- extract / view ---------------- */

static int ext_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    const ext_fs *fs = (const ext_fs *)a->priv;
    gz_entry *e = &a->e[idx];
    if (!e->is_dir && !(e->is_link && e->link_len) && (e->aux32 & FL_ENCRYPT)) return GZ_E_METHOD;
    int r = out->open(out, idx);
    if (r) return r;
    if (e->is_dir || (e->is_link && e->link_len) || !e->usize) return out->close(out, idx, GZ_OK);
    u8 ib[EXT_IRL_MAX];
    int st = ext_inode(fs, s, 0, (u32)e->off, ib);
    if (!st) {
        if (rd32(ib + 0x20) & FL_INLINE) {
            st = write_inline(fs, ib, e->usize, out);
        } else {
            gz_fs1_copy w;
            st = gz_fs1_copy_init(&w, s, out, c, e->usize);
            if (!st) st = ext_map_data(fs, s, ib, &w.k);
        }
    }
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static gz_src *ext_view(gz_archive *a, gz_src *s, u32 idx)
{
    const ext_fs *fs = (const ext_fs *)a->priv;
    gz_entry *e = &a->e[idx];
    if (e->is_dir || e->is_link || (e->aux32 & FL_ENCRYPT)) return 0;
    if (!e->usize) return gz_src_sub(s, 0, 0);
    u8 ib[EXT_IRL_MAX];
    if (ext_inode(fs, s, 0, (u32)e->off, ib)) return 0;
    if (rd32(ib + 0x20) & FL_INLINE) {
        const u8 *p2;
        u32 n2;
        if (e->usize > inline_parts(fs, ib, &p2, &n2)) return 0;
        u32 n = (u32)e->usize;
        u8 *m = (u8 *)gz_alloc(n);
        if (!m) return 0;
        __builtin_memcpy(m, ib + 0x28, n < 60 ? n : 60);
        if (n > 60) __builtin_memcpy(m + 60, p2, n - 60);
        gz_src *v = gz_src_mem(m, n, 1);
        if (!v) gz_free(m);
        return v;
    }
    gz_fs1_list l;
    gz_fs1_list_init(&l, e->usize, 1u << 20);
    if (ext_map_data(fs, s, ib, &l.k)) { gz_fs1_list_free(&l); return 0; }
    return gz_fs1_list_src(s, &l);
}

GZ_FORMAT(gz_fmt_ext)
const gz_format gz_fmt_ext = {
    "ext", "ext ext2 ext3 ext4 img", 0, ext_probe, ext_open, ext_close, ext_extract, 0, 0, 0, ext_view, 0
};
