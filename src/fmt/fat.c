/*
 * 고깃ZIP - FAT12 / FAT16 / FAT32 file system images
 *
 *   VFAT long names (UTF-16LE, checksum + sequence checked), 8.3 names in the
 *   OEM code page (NT lower-case bits), volume label (archive comment), deleted
 *   and orphaned entries skipped. 0x55AA is a weak signature, so the BPB is
 *   checked field by field. Hostile images: cluster chains are bounded by the
 *   cluster count, directories are read once (start cluster set) within a
 *   total budget of the volume size, and depth is limited.
 */
#include "fs1.h"

#define FAT_DIR_CAP (8u << 20)        /* bytes per directory (spec: 65536 entries = 2 MiB) */
#define FAT_TAB_MAX (1u << 20)        /* FAT32 entries kept in memory, else read on demand */

typedef struct {
    u32 bps, spc, rsvd, nfats, root_ent, fatsz, tot, media;
    u32 root_secs, clusters, bits, root_clus, ext_flags;
} fat_bpb;

typedef struct {
    gz_fs1_fat fat;
    u32 *tab;
    u32 bits;
    u64 root_off;                     /* FAT12/16 fixed root directory */
    u32 root_len;
} fat_fs;

static int is_pow2(u32 x) { return x && !(x & (x - 1)); }

static u32 ilog2(u32 x) { u32 n = 0; while (x > 1) { x >>= 1; n++; } return n; }

/* Validate a BIOS parameter block; 1 if it describes a usable FAT volume. */
static int bpb_parse(const u8 *b, fat_bpb *p)
{
    __builtin_memset(p, 0, sizeof *p);
    p->bps = rd16(b + 11);
    p->spc = b[13];
    p->rsvd = rd16(b + 14);
    p->nfats = b[16];
    p->root_ent = rd16(b + 17);
    p->media = b[21];
    u32 tot16 = rd16(b + 19), fat16 = rd16(b + 22), tot32 = rd32(b + 32);
    if (p->bps < 512 || p->bps > 4096 || !is_pow2(p->bps)) return 0;
    if (!is_pow2(p->spc)) return 0;
    if (!p->rsvd || !p->nfats || p->nfats > 4) return 0;
    if (p->media != 0xF0 && p->media < 0xF8) return 0;
    p->tot = tot16 ? tot16 : tot32;
    if (!p->tot) return 0;
    if (fat16) {
        p->fatsz = fat16;
        if (!p->root_ent) return 0;
    } else {                                   /* FAT32 extended BPB */
        p->fatsz = rd32(b + 36);
        if (!p->fatsz || p->root_ent || tot16 || rd16(b + 42) != 0) return 0;
        p->ext_flags = rd16(b + 40);
        p->root_clus = rd32(b + 44);
        p->bits = 32;
    }
    p->root_secs = (p->root_ent * 32 + p->bps - 1) / p->bps;
    u64 meta = (u64)p->rsvd + (u64)p->nfats * p->fatsz + p->root_secs;
    if (meta >= p->tot) return 0;
    u32 cl = (u32)((p->tot - meta) / p->spc);
    if (!p->bits) p->bits = cl <= 4084 ? 12 : 16;
    u64 ent = (u64)p->fatsz * p->bps * 8 / p->bits;     /* entries the FAT can hold */
    if (ent < 3) return 0;
    if (cl > ent - 2) cl = (u32)(ent - 2);
    u32 lim = p->bits == 12 ? 0xFF4 : p->bits == 16 ? 0xFFF5 : 0x0FFFFFF5;
    if (cl > lim) cl = lim;
    if (!cl) return 0;
    p->clusters = cl;
    if (p->bits == 32 && (p->root_clus < 2 || p->root_clus - 2 >= cl)) return 0;
    return 1;
}

/* A partition table whose entries point past sector 0 marks an MBR whose boot code happens
 * to pass the BPB checks: leave it to the partition map reader. (mkfs.vfat --mbr writes a
 * table whose single partition starts at sector 0: that stays FAT.) */
static int looks_like_mbr(const u8 *h, u64 size)
{
    int any = 0;
    for (int i = 0; i < 4; i++) {
        const u8 *p = h + 446 + 16 * i;
        u32 lba = rd32(p + 8), cnt = rd32(p + 12);
        if (p[0] != 0 && p[0] != 0x80) return 0;
        if (!p[4]) { if (lba || cnt) return 0; continue; }
        if (!lba || !cnt || (u64)lba * 512 >= size) return 0;
        any = 1;
    }
    return any;
}

static int fat_probe(gz_src *s, const u8 *h, u32 n)
{
    fat_bpb p;
    if (n < 512 || !bpb_parse(h, &p) || looks_like_mbr(h, s->size)) return 0;
    int jmp = h[0] == 0xE9 || (h[0] == 0xEB && h[2] == 0x90);
    int sig = h[510] == 0x55 && h[511] == 0xAA;
    if (!jmp && !sig) return 0;
    u64 fat_end = ((u64)p.rsvd + (u64)p.nfats * p.fatsz) * p.bps;
    if (fat_end > s->size) return 0;                  /* the FATs must be in the image */
    int sc = 40 + (jmp ? 10 : 0) + (sig ? 10 : 0);
    if (!__builtin_memcmp(p.bits == 32 ? h + 82 : h + 54, "FAT", 3)) sc += 15;
    if (h[p.bits == 32 ? 66 : 38] == 0x29) sc += 5;   /* extended boot signature */
    return sc;
}

/* ---------------- directories ---------------- */

typedef struct {
    gz_archive *a;
    gz_src *s;
    gz_ctx *c;
    fat_fs *fs;
    gz_fs1_tree t;
    gz_fs1_set seen;
    gz_fs1_fatcache *fc;
    u64 budget;                       /* directory bytes still allowed */
} fat_walk;

static u8 lfn_sum(const u8 *x)
{
    u8 s = 0;
    for (int i = 0; i < 11; i++) s = (u8)(((s & 1) << 7) + (s >> 1) + x[i]);
    return s;
}

/* 8.3 name with NT case bits; returns length */
static u32 short_name(const u8 *x, u8 *o)
{
    u32 bl = 8, el = 3, n = 0;
    while (bl && x[bl - 1] == ' ') bl--;
    while (el && x[8 + el - 1] == ' ') el--;
    int lb = (x[12] & 0x08) != 0, le = (x[12] & 0x10) != 0;
    /* lower-case only pure ASCII parts: DBCS trail bytes may look like letters */
    if (x[0] == 0x05) lb = 0;
    for (u32 i = 0; i < bl; i++) if (x[i] >= 0x80) lb = 0;
    for (u32 i = 0; i < el; i++) if (x[8 + i] >= 0x80) le = 0;
    for (u32 i = 0; i < bl; i++) {
        u8 ch = x[i];
        if (i == 0 && ch == 0x05) ch = 0xE5;           /* KANJI lead byte escape */
        if (lb && ch >= 'A' && ch <= 'Z') ch += 32;
        o[n++] = ch;
    }
    if (el) {
        o[n++] = '.';
        for (u32 i = 0; i < el; i++) {
            u8 ch = x[8 + i];
            if (le && ch >= 'A' && ch <= 'Z') ch += 32;
            o[n++] = ch;
        }
    }
    return n;
}

static int parse_dir(fat_walk *w, i32 node, const u8 *d, u32 len)
{
    fat_fs *fs = w->fs;
    gz_archive *a = w->a;
    u8 lfn[20 * 26];
    u32 seq = 0, lfn_cnt = 0;             /* seq: ordinal of the last LFN slot seen, 0 = none */
    u8 chk = 0;
    for (u32 off = 0; off + 32 <= len; off += 32) {
        const u8 *x = d + off;
        if (x[0] == 0) break;                                   /* end of directory */
        if (x[0] == 0xE5) { seq = 0; continue; }                /* deleted */
        u8 at = x[11];
        if ((at & 0x3F) == 0x0F) {                              /* long name slot */
            u32 ord = x[0] & 0x1F;
            if (x[0] & 0x40) {
                if (!ord || ord > 20) { seq = 0; continue; }
                lfn_cnt = ord;
                chk = x[13];
            } else if (!seq || ord != seq - 1 || x[13] != chk) {
                seq = 0;
                continue;
            }
            seq = ord;
            u8 *p = lfn + (ord - 1) * 26;
            __builtin_memcpy(p, x + 1, 10);
            __builtin_memcpy(p + 10, x + 14, 12);
            __builtin_memcpy(p + 22, x + 28, 4);
            continue;
        }
        int have_lfn = seq == 1 && lfn_sum(x) == chk;
        seq = 0;
        if (at & 0x08) {                                        /* volume label */
            if (node == 0 && !(at & 0x10) && !a->comment_raw) {
                u32 n = 11;
                while (n && x[n - 1] == ' ') n--;
                if (n && (a->comment_raw = (u8 *)gz_alloc(n))) {
                    __builtin_memcpy(a->comment_raw, x, n);
                    a->comment_len = n;
                    a->comment_enc = GZ_NE_OEM;
                }
            }
            continue;
        }
        if (x[0] == '.' && (x[1] == ' ' || (x[1] == '.' && x[2] == ' '))) continue;
        const u8 *nm;
        u32 nl;
        int ne;
        u8 sn[16];
        if (have_lfn) {
            u32 k = 0, max = lfn_cnt * 13;
            while (k < max && (lfn[2 * k] || lfn[2 * k + 1])) k++;
            if (k > 255) k = 255;
            nm = lfn; nl = k * 2; ne = GZ_NE_UTF16LE;
            if (!k) have_lfn = 0;
        }
        if (!have_lfn) {
            nl = short_name(x, sn);
            nm = sn; ne = GZ_NE_OEM;
        }
        gz_entry *e;
        int r = gz_fs1_add_entry(a, &w->t, node, nm, nl, ne, &e);
        if (r) return r;
        u32 cl = rd16(x + 26) | (fs->bits == 32 ? (u32)rd16(x + 20) << 16 : 0);
        u64 csz = (u64)1 << fs->fat.cshift;
        e->is_dir = (at & 0x10) ? 1 : 0;
        e->attr = at & 0x37;
        e->off = cl;
        e->usize = e->is_dir ? 0 : rd32(x + 28);
        e->csize = (e->usize + csz - 1) & ~(csz - 1);
        u32 dt = rd16(x + 24), tm = rd16(x + 22);
        if (dt) { e->mtime = (u64)dt << 16 | tm; e->mtime_kind = GZ_MT_DOS; }
        if (e->is_dir && cl >= 2 && cl - 2 < fs->fat.nclus) {
            int nw = gz_fs1_set_add(&w->seen, cl);
            if (nw < 0) return GZ_E_NOMEM;
            if (nw) {
                i32 ni = gz_fs1_tree_add(&w->t, node, nm, nl, ne, cl, 0, 0);
                if (ni == -1) return GZ_E_NOMEM;
            }
        }
    }
    return GZ_OK;
}

static int read_dir(fat_walk *w, u64 loc, gz_fs1_mem *m)
{
    u64 cap = w->budget < FAT_DIR_CAP ? w->budget : FAT_DIR_CAP;
    gz_fs1_mem_init(m, w->s, cap);
    if (!cap) return GZ_OK;
    int r;
    if (!loc) r = gz_fs1_emit(&m->k, w->fs->root_off, w->fs->root_len);    /* FAT12/16 root */
    else r = gz_fs1_fat_walk(&w->fs->fat, w->s, w->fc, (u32)loc, 0, &m->k);
    int f = gz_fs1_flush(&m->k, 0);
    if (r == GZ_FS1_FULL || r == GZ_E_DATA) r = GZ_OK;    /* broken chain: use what was read */
    if (!r) r = f;
    w->budget -= m->k.flushed;
    return r;
}

/* ---------------- open / extract ---------------- */

static void fat_close(gz_archive *a)
{
    fat_fs *fs = (fat_fs *)a->priv;
    if (!fs) return;
    gz_free(fs->tab);
    gz_free(fs);
    a->priv = 0;
}

static int load_fat(fat_fs *fs, gz_src *s, u64 off, u32 nent)
{
    if (fs->bits == 32) return gz_fs1_fat_load32(s, off, nent, FAT_TAB_MAX, &fs->tab);
    u32 bytes = fs->bits == 12 ? (nent * 3 + 1) / 2 : nent * 2;
    u8 *raw = (u8 *)gz_alloc(bytes + 4);
    u32 *t = (u32 *)gz_alloc((size_t)nent * 4);
    if (!raw || !t) { gz_free(raw); gz_free(t); return GZ_E_NOMEM; }
    int r = gz_src_read_exact(s, off, raw, bytes);
    if (r) { gz_free(raw); gz_free(t); return r; }
    /* normalise to FAT32 values: >= 0x0FFFFFF8 end of chain, 0x0FFFFFF7 bad */
    for (u32 i = 0; i < nent; i++) {
        u32 v;
        if (fs->bits == 12) {
            v = rd16(raw + i + i / 2);
            v = (i & 1) ? v >> 4 : v & 0xFFF;
            if (v >= 0xFF7) v += 0x0FFFF000;
        } else {
            v = rd16(raw + 2 * i);
            if (v >= 0xFFF7) v += 0x0FFF0000;
        }
        t[i] = v;
    }
    gz_free(raw);
    fs->tab = t;
    return GZ_OK;
}

static int fat_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    u8 b[512];
    int r = gz_src_read_exact(s, 0, b, 512);
    if (r) return r;
    fat_bpb p;
    if (!bpb_parse(b, &p)) return GZ_E_FORMAT;
    fat_fs *fs = (fat_fs *)gz_alloc(sizeof(fat_fs));
    if (!fs) return GZ_E_NOMEM;
    a->priv = fs;
    fs->bits = p.bits;
    u32 cshift = ilog2(p.bps) + ilog2(p.spc);
    u64 fat_off = (u64)p.rsvd * p.bps;
    if (p.bits == 32 && (p.ext_flags & 0x80) && (p.ext_flags & 15) < p.nfats)
        fat_off += (u64)(p.ext_flags & 15) * p.fatsz * p.bps;   /* mirroring off: active FAT */
    fs->root_off = ((u64)p.rsvd + (u64)p.nfats * p.fatsz) * p.bps;
    fs->root_len = p.root_secs * p.bps;
    r = load_fat(fs, s, fat_off, p.clusters + 2);
    if (r) return r;
    fs->fat.tab = fs->tab;
    fs->fat.fat_off = fat_off;
    fs->fat.nclus = p.clusters;
    fs->fat.mask = 0x0FFFFFFF;
    fs->fat.eoc = 0x0FFFFFF8;
    fs->fat.cshift = cshift;
    fs->fat.heap = fs->root_off + fs->root_len;
    gz_arc_set_type(a, p.bits == 12 ? "FAT12" : p.bits == 16 ? "FAT16" : "FAT32");
    a->win_names = 1;

    fat_walk w;
    __builtin_memset(&w, 0, sizeof w);
    w.a = a; w.s = s; w.c = c; w.fs = fs;
    w.budget = ((u64)p.clusters << cshift) + fs->root_len;
    int cp = a->codepage && a->codepage != GZ_CP_UTF8 ? a->codepage : gz_plat_oemcp();
    r = gz_fs1_tree_init(&w.t, GZ_NE_OEM, cp);
    if (!r && !fs->tab && !(w.fc = gz_fs1_fatcache_new())) r = GZ_E_NOMEM;
    if (!r && p.bits == 32) {
        w.t.n[0].loc = p.root_clus;
        if (gz_fs1_set_add(&w.seen, p.root_clus) < 0) r = GZ_E_NOMEM;
    }
    for (u32 i = 0; !r && i < w.t.nn; i++) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        gz_fs1_mem m;
        int rr = read_dir(&w, w.t.n[i].loc, &m);
        if (rr == GZ_E_NOMEM || rr == GZ_E_CANCEL) r = rr;
        else if (m.k.flushed) r = parse_dir(&w, (i32)i, m.p, (u32)m.k.flushed);
        else if (rr && i == 0) r = rr;                 /* unreadable root directory */
        gz_free(m.p);
        if (c && c->progress && !(i & 63)) c->progress(c->progress_user, i, w.t.nn);
    }
    gz_fs1_tree_free(&w.t);
    gz_fs1_set_free(&w.seen);
    gz_fs1_fatcache_free(w.fc);
    (void)o;
    return r;
}

static int fat_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    fat_fs *fs = (fat_fs *)a->priv;
    gz_entry *e = &a->e[idx];
    int r = out->open(out, idx);
    if (r) return r;
    if (e->is_dir || !e->usize) return out->close(out, idx, GZ_OK);
    gz_fs1_copy w;
    int st = gz_fs1_copy_init(&w, s, out, c, e->usize);
    if (!st) st = gz_fs1_fat_walk(&fs->fat, s, 0, (u32)e->off, 0, &w.k);
    if (st == GZ_FS1_FULL) st = GZ_OK;
    if (!st) st = gz_fs1_flush(&w.k, 0);
    if (!st && w.k.flushed < e->usize) st = GZ_E_DATA;     /* chain shorter than the file */
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static gz_src *fat_view(gz_archive *a, gz_src *s, u32 idx)
{
    fat_fs *fs = (fat_fs *)a->priv;
    gz_entry *e = &a->e[idx];
    if (e->is_dir) return 0;
    if (!e->usize) return gz_src_sub(s, 0, 0);
    gz_fs1_list l;
    gz_fs1_list_init(&l, e->usize, 1u << 20);
    int r = gz_fs1_fat_walk(&fs->fat, s, 0, (u32)e->off, 0, &l.k);
    if (r == GZ_FS1_FULL) r = GZ_OK;
    if (!r) r = gz_fs1_flush(&l.k, 0);
    if (r || l.k.flushed < e->usize) { gz_fs1_list_free(&l); return 0; }
    return gz_fs1_list_src(s, &l);
}

GZ_FORMAT(gz_fmt_fat)
const gz_format gz_fmt_fat = {
    "FAT", "fat img ima vfd flp", 0, fat_probe, fat_open, fat_close, fat_extract, 0, 0, 0, fat_view, 0
};
