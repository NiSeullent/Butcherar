/*
 * 고깃ZIP - exFAT file system images
 *
 *   Main / backup boot region (boot checksum), active FAT, allocation bitmap
 *   check, File + Stream Extension + File Name entry sets (set checksum),
 *   NoFatChain contiguous files, ValidDataLength (zeros after it), UTF-16
 *   names, timestamps with 10 ms increments and UTC offsets, volume label.
 */
#include "fs1.h"

#define EX_DIR_CAP (64u << 20)        /* bytes per directory (spec: 256 MiB) */
#define EX_TAB_MAX (1u << 20)         /* FAT entries kept in memory, else read on demand */

typedef struct {
    gz_fs1_fat fat;
    u32 *tab;
    u64 ncl_bytes;                    /* cluster heap size */
} exfat_fs;

static int ex_bpb_ok(const u8 *b)
{
    if (__builtin_memcmp(b + 3, "EXFAT   ", 8)) return 0;
    for (int i = 11; i < 64; i++) if (b[i]) return 0;           /* MustBeZero */
    u32 bs = b[108], cs = b[109];
    if (bs < 9 || bs > 12 || cs > 25 - bs) return 0;
    if (b[110] < 1 || b[110] > 2) return 0;
    return 1;
}

static int exfat_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 512 || !ex_bpb_ok(h)) return 0;
    return h[510] == 0x55 && h[511] == 0xAA ? 95 : 90;
}

static u32 boot_sum(const u8 *b, u32 n)
{
    u32 c = 0;
    for (u32 i = 0; i < n; i++) {
        if (i == 106 || i == 107 || i == 112) continue;
        c = ((c & 1) ? 0x80000000u : 0) + (c >> 1) + b[i];
    }
    return c;
}

/* 12-sector boot region: boot sector + checksum sector 11 */
static int region_ok(const u8 *r, u32 bps)
{
    if (!ex_bpb_ok(r)) return 0;
    u32 c = boot_sum(r, 11 * bps);
    for (u32 i = 0; i < bps; i += 4) if (rd32(r + 11 * bps + i) != c) return 0;
    return 1;
}

/* ---------------- directories ---------------- */

typedef struct {
    gz_archive *a;
    gz_src *s;
    exfat_fs *fs;
    gz_fs1_tree t;
    gz_fs1_set seen;
    gz_fs1_fatcache *fc;
    u64 budget;
    int have_bitmap;
} ex_walk;

static void ex_time(gz_entry *e, u32 ts, u32 inc, u32 utc)
{
    if (!ts) return;
    if (utc & 0x80) {                     /* OffsetValid: local time + offset in 15 min units */
        i32 off = (i32)(utc & 0x7F);
        if (off & 0x40) off -= 0x80;
        i64 ft = (i64)gz_dos_to_filetime(ts) + (inc <= 199 ? (i64)inc * 100000 : 0);
        ft -= (i64)off * 15 * 60 * 10000000;
        e->mtime = (u64)ft;
        e->mtime_kind = GZ_MT_FILETIME;
    } else {
        e->mtime = ts;                    /* same layout as DOS date<<16 | time, local */
        e->mtime_kind = GZ_MT_DOS;
    }
}

static int ex_parse(ex_walk *w, i32 node, const u8 *d, u32 len)
{
    exfat_fs *fs = w->fs;
    gz_archive *a = w->a;
    u32 off = 0;
    while (off + 32 <= len) {
        const u8 *x = d + off;
        u8 t = x[0];
        if (!t) break;                                      /* end of directory */
        if (t == 0x81) w->have_bitmap = 1;
        if (t == 0x83 && node == 0 && !a->comment_raw) {    /* volume label */
            u32 n = x[1] > 11 ? 11 : x[1];
            if (n && (a->comment_raw = (u8 *)gz_alloc(n * 2))) {
                __builtin_memcpy(a->comment_raw, x + 2, n * 2);
                a->comment_len = n * 2;
                a->comment_enc = GZ_NE_UTF16LE;
            }
        }
        if (t != 0x85) { off += 32; continue; }
        u32 sc = x[1], sz = (sc + 1) * 32;
        if (sc < 2 || sc > 18 || sz > len - off) { off += 32; continue; }
        u16 sum = 0;
        for (u32 i = 0; i < sz; i++) {
            if (i == 2 || i == 3) continue;
            sum = (u16)(((sum & 1) ? 0x8000 : 0) + (sum >> 1) + x[i]);
        }
        const u8 *st = x + 32;
        u32 nl = st[3], nent = (nl + 14) / 15;
        if (sum != rd16(x + 2) || st[0] != 0xC0 || !nl || nent > sc - 1) { off += 32; continue; }
        u8 nm[255 * 2];
        int ok = 1;
        for (u32 k = 0; k < nent && ok; k++) {
            const u8 *fe = x + 64 + 32 * k;
            u32 take = nl - 15 * k < 15 ? nl - 15 * k : 15;
            if (fe[0] != 0xC1) ok = 0;
            else __builtin_memcpy(nm + 30 * k, fe + 2, take * 2);
        }
        if (!ok) { off += 32; continue; }
        u32 nb = nl * 2;
        for (u32 k = 0; k < nl; k++) if (!nm[2 * k] && !nm[2 * k + 1]) { nb = k * 2; break; }
        gz_entry *e;
        int r = gz_fs1_add_entry(a, &w->t, node, nm, nb, GZ_NE_UTF16LE, &e);
        if (r) return r;
        u32 attr = rd16(x + 4);
        u32 fl = st[1];
        u32 first = rd32(st + 20);
        u64 dlen = rd64(st + 24), vdl = rd64(st + 8);
        if (!(fl & 1)) { first = 0; dlen = vdl = 0; }       /* AllocationPossible clear */
        if (vdl > dlen) vdl = dlen;
        u64 csz = (u64)1 << fs->fat.cshift;
        e->is_dir = (attr & 0x10) ? 1 : 0;
        e->attr = attr & 0x37;
        e->off = first;
        e->aux = vdl;
        e->flags = (u16)((fl >> 1) & 1);                    /* NoFatChain */
        e->usize = e->is_dir ? 0 : dlen;
        e->csize = dlen > fs->ncl_bytes ? dlen : (dlen + csz - 1) & ~(csz - 1);
        ex_time(e, rd32(x + 12), x[21], x[23]);
        if (e->is_dir && dlen && first >= 2 && first - 2 < fs->fat.nclus) {
            int nw = gz_fs1_set_add(&w->seen, first);
            if (nw < 0) return GZ_E_NOMEM;
            if (nw && gz_fs1_tree_add(&w->t, node, nm, nb, GZ_NE_UTF16LE, first, dlen, (fl >> 1) & 1) == -1)
                return GZ_E_NOMEM;
        }
        off += sz;
    }
    return GZ_OK;
}

static int ex_read_dir(ex_walk *w, const gz_fs1_node *n, gz_fs1_mem *m)
{
    u64 cap = w->budget < EX_DIR_CAP ? w->budget : EX_DIR_CAP;
    if (n->size && n->size < cap) cap = n->size;            /* root: chain length only */
    gz_fs1_mem_init(m, w->s, cap);
    if (!cap) return GZ_OK;
    int r = gz_fs1_fat_walk(&w->fs->fat, w->s, w->fc, (u32)n->loc, (int)n->aux, &m->k);
    int f = gz_fs1_flush(&m->k, 0);
    if (r == GZ_FS1_FULL || r == GZ_E_DATA) r = GZ_OK;
    if (!r) r = f;
    w->budget -= m->k.flushed;
    return r;
}

/* ---------------- open / extract ---------------- */

static void exfat_close(gz_archive *a)
{
    exfat_fs *fs = (exfat_fs *)a->priv;
    if (!fs) return;
    gz_free(fs->tab);
    gz_free(fs);
    a->priv = 0;
}

static int exfat_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    u8 b0[512];
    int r = gz_src_read_exact(s, 0, b0, 512);
    if (r) return r;
    if (!ex_bpb_ok(b0)) return GZ_E_FORMAT;
    u32 bshift = b0[108], bps = 1u << bshift;
    u8 *reg = (u8 *)gz_alloc(12 * bps);
    if (!reg) return GZ_E_NOMEM;
    /* main boot region, else the backup one when only that is intact */
    r = gz_src_read_exact(s, 0, reg, 12 * bps);
    if (!r && !region_ok(reg, bps)) {
        u8 *bk = (u8 *)gz_alloc(12 * bps);
        if (bk && !gz_src_read_exact(s, 12 * (u64)bps, bk, 12 * bps) && region_ok(bk, bps) &&
            bk[108] == bshift) {
            gz_free(reg);
            reg = bk;
            bk = 0;
        }
        gz_free(bk);
    }
    if (r) { gz_free(reg); return r; }
    const u8 *b = reg;
    u64 vol_len = rd64(b + 72);
    u32 fat_off = rd32(b + 80), fat_len = rd32(b + 84), heap = rd32(b + 88);
    u32 ncl = rd32(b + 92), root = rd32(b + 96), vflags = rd16(b + 106);
    u32 cshift = bshift + b[109], nfats = b[110];
    int bad = fat_off < 24 || (u64)heap < (u64)fat_off + (u64)fat_len * nfats || !ncl || ncl > 0xFFFFFFF5u ||
              ((u64)ncl + 2) * 4 > ((u64)fat_len << bshift) ||
              (u64)heap + ((u64)ncl << b[109]) > vol_len || root < 2 || root - 2 >= ncl;
    gz_free(reg);
    if (bad) return GZ_E_FORMAT;
    exfat_fs *fs = (exfat_fs *)gz_alloc(sizeof(exfat_fs));
    if (!fs) return GZ_E_NOMEM;
    a->priv = fs;
    u64 foff = (u64)fat_off << bshift;
    if (nfats == 2 && (vflags & 1)) foff += (u64)fat_len << bshift;   /* ActiveFat = second */
    r = gz_fs1_fat_load32(s, foff, ncl + 2, EX_TAB_MAX, &fs->tab);
    if (r) return r;
    fs->fat.tab = fs->tab;
    fs->fat.fat_off = foff;
    fs->fat.nclus = ncl;
    fs->fat.mask = 0xFFFFFFFFu;
    fs->fat.eoc = 0xFFFFFFF8u;
    fs->fat.cshift = cshift;
    fs->fat.heap = (u64)heap << bshift;
    fs->ncl_bytes = (u64)ncl << cshift;
    gz_arc_set_type(a, "exFAT");
    a->win_names = 1;

    ex_walk w;
    __builtin_memset(&w, 0, sizeof w);
    w.a = a; w.s = s; w.fs = fs;
    w.budget = fs->ncl_bytes;
    r = gz_fs1_tree_init(&w.t, GZ_NE_UTF8, GZ_CP_UTF8);
    if (!r && !fs->tab && !(w.fc = gz_fs1_fatcache_new())) r = GZ_E_NOMEM;
    if (!r) {
        w.t.n[0].loc = root;
        if (gz_fs1_set_add(&w.seen, root) < 0) r = GZ_E_NOMEM;
    }
    for (u32 i = 0; !r && i < w.t.nn; i++) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        gz_fs1_mem m;
        gz_fs1_node nd = w.t.n[i];
        int rr = ex_read_dir(&w, &nd, &m);
        if (rr == GZ_E_NOMEM || rr == GZ_E_CANCEL) r = rr;
        else if (m.k.flushed) r = ex_parse(&w, (i32)i, m.p, (u32)m.k.flushed);
        else if (rr && i == 0) r = rr;
        gz_free(m.p);
        /* a real exFAT root holds the allocation bitmap entry */
        if (!r && i == 0 && !w.have_bitmap) r = GZ_E_FORMAT;
        if (c && c->progress && !(i & 63)) c->progress(c->progress_user, i, w.t.nn);
    }
    gz_fs1_tree_free(&w.t);
    gz_fs1_set_free(&w.seen);
    gz_fs1_fatcache_free(w.fc);
    return r;
}

/* Emit an entry's data: ValidDataLength bytes from the clusters, zeros after that. */
static int ex_map(exfat_fs *fs, gz_src *s, const gz_entry *e, gz_fs1_sink *k)
{
    u64 vdl = e->aux < e->usize ? e->aux : e->usize;
    int r = GZ_OK;
    if (vdl) {
        k->limit = vdl;
        r = gz_fs1_fat_walk(&fs->fat, s, 0, (u32)e->off, e->flags & 1, k);
        if (r == GZ_FS1_FULL) r = GZ_OK;
        if (!r && k->pos < vdl) r = GZ_E_DATA;              /* chain shorter than the data */
        k->limit = e->usize;
    }
    if (!r) r = gz_fs1_flush(k, 1);
    return r;
}

static int exfat_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    gz_entry *e = &a->e[idx];
    int r = out->open(out, idx);
    if (r) return r;
    if (e->is_dir || !e->usize) return out->close(out, idx, GZ_OK);
    gz_fs1_copy w;
    int st = gz_fs1_copy_init(&w, s, out, c, e->usize);
    if (!st) st = ex_map((exfat_fs *)a->priv, s, e, &w.k);
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static gz_src *exfat_view(gz_archive *a, gz_src *s, u32 idx)
{
    gz_entry *e = &a->e[idx];
    if (e->is_dir) return 0;
    if (!e->usize) return gz_src_sub(s, 0, 0);
    gz_fs1_list l;
    gz_fs1_list_init(&l, e->usize, 1u << 20);
    if (ex_map((exfat_fs *)a->priv, s, e, &l.k)) { gz_fs1_list_free(&l); return 0; }
    return gz_fs1_list_src(s, &l);
}

GZ_FORMAT(gz_fmt_exfat)
const gz_format gz_fmt_exfat = {
    "exFAT", "exfat img", 0, exfat_probe, exfat_open, exfat_close, exfat_extract, 0, 0, 0, exfat_view, 0
};
