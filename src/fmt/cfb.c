/*
 * 고깃ZIP - Compound File Binary (OLE2 / MS-CFB): MSI, MSP, MST, MSM, DOC, XLS, PPT, MSG ...
 *
 * Layout: a 512-byte header, then sectors of 1 << shift bytes (v3: 512, v4: 4096);
 * sector n lives at (n + 1) << shift. The FAT (whose sectors are listed by the DIFAT:
 * 109 ids in the header plus a chain of DIFAT sectors) links sectors into chains.
 * Streams smaller than the cutoff (4096) live in the mini stream (the root entry's
 * chain), cut into 64-byte mini sectors linked by the MiniFAT. The directory is an
 * array of 128-byte entries; the children of a storage form a red-black tree
 * (left/right sibling links) hanging off the storage's child link.
 *
 * At open every chain is walked once with an ownership bitmap: a sector reached a
 * second time (cycle, cross link) or out of range ends the chain, so the walk is
 * O(sectors) whatever the FAT says. Each stream becomes a list of extents (runs of
 * file offsets); extraction and view() read through them. A chain shorter than the
 * stream maps a prefix and the entry is reported as damaged.
 *
 * Names follow 7-Zip: control characters become "[5]", MSI-compressed names
 * (units 0x3800..0x4840) are unpacked, "!" marks MSI tables. In MSI packages a
 * stream starting with "MSCF" gets a ".cab" extension so it opens as an archive.
 */
#include "arc.h"

#define CFB_FREE   0xFFFFFFFFu
#define CFB_END    0xFFFFFFFEu
#define CFB_MAXREG 0xFFFFFFFAu      /* largest regular sector id */

#define CFB_MAX_DEPTH 64            /* storage nesting                                  */
#define CFB_MAX_TAB   (256u << 20)  /* FAT / MiniFAT bytes held in memory               */
#define CFB_MAX_DIR   (64u << 20)   /* directory bytes (512K entries)                    */
#define CFB_MAX_NAMES (128u << 20)  /* raw path bytes of all entries                     */
#define CFB_NAME_MAX  (32 * 4 + 8)  /* converted name units: "[31]" per unit + ".cab"   */

enum { T_EMPTY = 0, T_STORAGE = 1, T_STREAM = 2, T_ROOT = 5 };
enum { CF_BROKEN = 1, CF_MINI = 2 };     /* gz_entry.flags */

static const u8 k_sig[8] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
static const char k_msi_chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";

/* A run of a stream: file offset phys holds stream bytes [previous lend, lend). */
typedef struct { u64 phys, lend; } cfb_ext;

typedef struct {
    cfb_ext *x;               /* extents of every stream; entry: off = first, aux32 = count */
    u32 nx, capx;
} cfb_priv;

/* open-time state */
typedef struct {
    gz_src *s;
    cfb_priv *p;
    u32 shift, mshift;
    u32 cutoff;               /* streams below this size live in the mini stream          */
    u32 nsec;                 /* sectors present in the file (last one may be partial)   */
    u32 *fat;  u32 nfat;      /* FAT entries kept: ids >= nfat are unusable               */
    u8  *own;                 /* sectors already claimed by a chain                       */
    u32 *mfat; u32 nmfat;     /* MiniFAT                                                  */
    u32 *msid; u32 nmsid;     /* mini stream sectors                                      */
    u32 nmini;                /* usable mini sectors                                      */
    u8  *mown;                /* mini sectors already claimed                             */
    u8  *dir;  u32 ndir;      /* directory entries (128 bytes each)                       */
} cfb_rd;

typedef struct {
    u32 did;
    i32 parent;               /* index of the parent storage's ref, -1 = root            */
    u32 depth;
    u32 noff;                 /* converted name in the name buffer                       */
    u32 nlen;
} cfb_ref;

/* ---------------- helpers ---------------- */

/* Read up to n bytes at off (short only at end of file). Returns bytes read. */
static u32 read_some(gz_src *s, u64 off, u8 *buf, u32 n)
{
    u32 done = 0;
    while (done < n && off + done < s->size) {
        u32 got = 0;
        if (s->read_at(s, off + done, buf + done, n - done, &got) || !got) break;
        done += got;
    }
    return done;
}

static int bit_test_set(u8 *bm, u32 i)
{
    u8 m = (u8)(1u << (i & 7));
    if (bm[i >> 3] & m) return 1;
    bm[i >> 3] |= m;
    return 0;
}

static int ext_push(cfb_priv *p, u64 phys, u64 lend)
{
    if (p->nx == p->capx) {
        if (p->capx >= (1u << 27)) return GZ_E_LIMIT;
        u32 nc = p->capx ? p->capx * 2 : 256;
        cfb_ext *nx = (cfb_ext *)gz_realloc(p->x, (size_t)nc * sizeof(cfb_ext));
        if (!nx) return GZ_E_NOMEM;
        p->x = nx;
        p->capx = nc;
    }
    p->x[p->nx].phys = phys;
    p->x[p->nx].lend = lend;
    p->nx++;
    return GZ_OK;
}

static u64 sec_off(const cfb_rd *r, u32 sid) { return ((u64)sid + 1) << r->shift; }

static u64 mini_off(const cfb_rd *r, u32 m)
{
    u64 mo = (u64)m << r->mshift;
    return sec_off(r, r->msid[mo >> r->shift]) + (mo & (((u64)1 << r->shift) - 1));
}

/* Walk a FAT (mini = 0) or MiniFAT chain from start, mapping at most max bytes to
 * extents appended to r->p (merged when contiguous in the file). Stops at ENDOFCHAIN,
 * at a bad link and at a sector some chain already owns. *mapped = bytes mapped. */
static int walk(cfb_rd *r, u32 start, u64 max, int mini, u64 *mapped)
{
    const u32 *next = mini ? r->mfat : r->fat;
    u32 lim = mini ? r->nmini : r->nfat;
    u8 *own = mini ? r->mown : r->own;
    u32 cs = 1u << (mini ? r->mshift : r->shift);
    cfb_priv *p = r->p;
    u32 first = p->nx;
    u64 done = 0, run_start = 0;
    u32 sid = start;
    while (done < max) {
        if (sid >= lim || bit_test_set(own, sid)) break;      /* end, bad link, cycle or cross link */
        u64 phys = mini ? mini_off(r, sid) : sec_off(r, sid);
        u64 len = max - done < cs ? max - done : cs;
        if (p->nx > first && p->x[p->nx - 1].phys + (done - run_start) == phys) {
            p->x[p->nx - 1].lend = done + len;
        } else {
            int e = ext_push(p, phys, done + len);
            if (e) return e;
            run_start = done;
        }
        done += len;
        sid = next[sid];
    }
    *mapped = done;
    return GZ_OK;
}

/* Read the bytes of extents [first, p->nx) into a new buffer (zero-filled where the
 * file ends early) and drop the extents. */
static int read_extents(cfb_rd *r, u32 first, u64 len, u64 limit, u8 **out)
{
    cfb_priv *p = r->p;
    *out = 0;
    if (len > limit) return GZ_E_LIMIT;
    u8 *b = (u8 *)gz_alloc((size_t)len + 1);
    if (!b) return GZ_E_NOMEM;
    u64 pos = 0;
    for (u32 i = first; i < p->nx; i++) {
        u32 n = (u32)(p->x[i].lend - pos);
        read_some(r->s, p->x[i].phys, b + pos, n);
        pos = p->x[i].lend;
    }
    p->nx = first;
    *out = b;
    return GZ_OK;
}

/* ---------------- header, FAT, MiniFAT, directory ---------------- */

static int hdr_ok(const u8 *h)
{
    if (__builtin_memcmp(h, k_sig, 8)) return 0;
    if (rd16(h + 0x1C) != 0xFFFE || rd16(h + 0x1A) > 4) return 0;
    u32 sh = rd16(h + 0x1E), ms = rd16(h + 0x20);
    return sh >= 7 && sh <= 16 && ms >= 2 && ms <= sh;
}

static int read_fat(cfb_rd *r, const u8 *h)
{
    u32 sh2 = r->shift - 2, epsec = 1u << sh2;
    u64 cover = (u64)rd32(h + 0x2C) << sh2;
    r->nfat = cover < r->nsec ? (u32)cover : r->nsec;
    if ((u64)r->nfat * 4 > CFB_MAX_TAB) return GZ_E_LIMIT;
    u32 need = (u32)(((u64)r->nfat + epsec - 1) >> sh2);     /* FAT sectors to read */
    u32 *ids = (u32 *)gz_alloc(((size_t)need + 110) * sizeof(u32));
    r->fat = (u32 *)gz_alloc((size_t)r->nfat * 4 + 4);
    r->own = (u8 *)gz_alloc(((size_t)r->nfat >> 3) + 1);
    u8 *sec = (u8 *)gz_alloc((size_t)1 << r->shift);
    int res = GZ_E_NOMEM;
    if (!ids || !r->fat || !r->own || !sec) goto done;

    /* FAT sector ids: 109 in the header, then the DIFAT chain (epsec - 1 ids + next link).
     * Each DIFAT sector adds >= 1 id, so the loop runs at most need times. */
    u32 k = 0, ndif = 0;
    for (u32 i = 0; i < 109 && k < need; i++) ids[k++] = rd32(h + 0x4C + 4 * i);
    u32 dsid = rd32(h + 0x44), dcount = rd32(h + 0x48);
    u32 *difs = ids + need;           /* DIFAT sector ids, marked as owned below (<= 109 kept) */
    while (k < need && ndif < dcount && dsid < r->nsec) {
        u32 got = read_some(r->s, sec_off(r, dsid), sec, 1u << r->shift);
        if (got < (1u << r->shift)) break;
        if (ndif < 109) difs[ndif] = dsid;
        ndif++;
        for (u32 j = 0; j + 1 < epsec && k < need; j++) ids[k++] = rd32(sec + 4 * j);
        dsid = rd32(sec + 4 * (epsec - 1));
    }
    for (u32 i = k; i < need; i++) ids[i] = CFB_FREE;           /* missing: entries stay free */

    /* read FAT sectors, merging runs of consecutive ids into one read */
    __builtin_memset(r->fat, 0xFF, (size_t)r->nfat * 4);
    for (u32 i = 0; i < need;) {
        u32 sid = ids[i], run = 1;
        if (sid >= r->nsec) { i++; continue; }
        while (i + run < need && run < 256 && (u64)sid + run < r->nsec && ids[i + run] == sid + run) run++;
        u64 ent = (u64)i << sh2;                                 /* first FAT entry of the run */
        u64 cnt = (u64)run << sh2;
        if (cnt > r->nfat - ent) cnt = r->nfat - ent;
        u32 got = read_some(r->s, sec_off(r, sid), (u8 *)(r->fat + ent), (u32)(cnt * 4));
        if (got < cnt * 4) __builtin_memset((u8 *)(r->fat + ent) + got, 0xFF, (size_t)(cnt * 4 - got));
        i += run;
    }
    /* FAT and DIFAT sectors are not stream data */
    for (u32 i = 0; i < need; i++) if (ids[i] < r->nfat) bit_test_set(r->own, ids[i]);
    for (u32 i = 0; i < ndif && i < 109; i++) if (difs[i] < r->nfat) bit_test_set(r->own, difs[i]);
    res = GZ_OK;
done:
    gz_free(ids);
    gz_free(sec);
    return res;
}

/* ---------------- names ---------------- */

static int msi_unit(u32 c) { return c >= 0x3800 && c <= 0x4840; }

/* Raw directory name: units up to the first NUL (at most 32, like 7-Zip). */
static u32 raw_name_len(const u8 *d)
{
    u32 n = 0;
    while (n < 32 && rd16(d + 2 * n)) n++;
    return n;
}

/* Display name of a raw name (n <= 32 units) into out (CFB_NAME_MAX units).
 * decode: unpack MSI units (all units of an MSI name, or the encoded parts of a
 * partly encoded name inside an MSI package). */
static u32 conv_name(const u8 *d, u32 n, int decode, gzch *out)
{
    u32 o = 0;
    for (u32 i = 0; i < n; i++) {
        u32 c = rd16(d + 2 * i);
        if (decode && msi_unit(c)) {
            c -= 0x3800;
            if (c < 0x1000) {                       /* two characters */
                out[o++] = (gzch)k_msi_chars[c & 63];
                out[o++] = (gzch)k_msi_chars[c >> 6];
            } else if (c < 0x1040) {                /* one character */
                out[o++] = (gzch)k_msi_chars[c & 63];
            } else {
                out[o++] = '!';                     /* table prefix */
            }
        } else if (c < 0x20) {                      /* "\x05SummaryInformation" -> "[5]..." */
            out[o++] = '[';
            if (c >= 10) out[o++] = (gzch)('0' + c / 10);
            out[o++] = (gzch)('0' + c % 10);
            out[o++] = ']';
        } else if (c == '/' || c == '\\') {
            out[o++] = '_';                         /* keep the storage tree intact */
        } else {
            out[o++] = (gzch)c;
        }
    }
    if (!o) out[o++] = '_';
    return o;
}

static int ends_with_cab(const gzch *s, u32 n)
{
    if (n < 4 || s[n - 4] != '.') return 0;
    return (s[n - 3] | 0x20) == 'c' && (s[n - 2] | 0x20) == 'a' && (s[n - 1] | 0x20) == 'b';
}

/* ---------------- directory traversal ---------------- */

/* Pre-order walk like 7-Zip (node, left subtree, right subtree, children), iterative.
 * Every entry is visited at most once; storages deeper than CFB_MAX_DEPTH are listed
 * without their contents. */
static int collect_refs(cfb_rd *r, cfb_ref **prefs, u32 *pn)
{
    u32 nd = r->ndir;
    cfb_ref *refs = (cfb_ref *)gz_alloc((size_t)nd * sizeof(cfb_ref) + sizeof(cfb_ref));
    u32 *stack = (u32 *)gz_alloc((size_t)nd * 2 * sizeof(u32) + 8);     /* (did, parent) pairs */
    u8 *seen = (u8 *)gz_alloc(((size_t)nd >> 3) + 1);
    if (!refs || !stack || !seen) { gz_free(refs); gz_free(stack); gz_free(seen); return GZ_E_NOMEM; }
    bit_test_set(seen, 0);                                  /* the root is not listed */
    u32 sp = 0, n = 0;
#define PUSH(did, par) do { u32 d_ = (did); \
        if (d_ < nd && !bit_test_set(seen, d_)) { stack[2 * sp] = d_; stack[2 * sp + 1] = (u32)(par); sp++; } \
    } while (0)
    PUSH(rd32(r->dir + 0x4C), -1);
    while (sp) {
        sp--;
        u32 did = stack[2 * sp];
        i32 par = (i32)stack[2 * sp + 1];
        const u8 *d = r->dir + (size_t)did * 128;
        u32 type = d[0x42];
        if (type != T_STORAGE && type != T_STREAM) continue;     /* empty / bogus: drop subtree */
        cfb_ref *f = &refs[n];
        f->did = did;
        f->parent = par;
        f->depth = par < 0 ? 0 : refs[par].depth + 1;
        u32 me = n++;
        /* pushed in reverse so the left subtree is handled first */
        if (type == T_STORAGE && f->depth + 1 < CFB_MAX_DEPTH) PUSH(rd32(d + 0x4C), me);
        PUSH(rd32(d + 0x48), par);
        PUSH(rd32(d + 0x44), par);
    }
#undef PUSH
    gz_free(stack);
    gz_free(seen);
    *prefs = refs;
    *pn = n;
    return GZ_OK;
}

/* ---------------- open ---------------- */

static int open_dir(cfb_rd *r, const u8 *h)
{
    /* directory chain (until ENDOFCHAIN) */
    u32 first = r->p->nx;
    u64 len;
    int e = walk(r, rd32(h + 0x30), (u64)r->nfat << r->shift, 0, &len);
    if (e) return e;
    if (len < 128) return GZ_E_FORMAT;
    e = read_extents(r, first, len, CFB_MAX_DIR, &r->dir);
    if (e) return e;
    r->ndir = (u32)(len / 128);

    /* MiniFAT: its sector count is trusted (a bogus start with count 0 must not steal sectors) */
    u32 mcount = rd32(h + 0x40);
    if (mcount) {
        u64 max = (u64)mcount << r->shift;
        e = walk(r, rd32(h + 0x3C), max, 0, &len);
        if (e) return e;
        u8 *b;
        e = read_extents(r, first, len, CFB_MAX_TAB, &b);
        if (e) return e;
        r->mfat = (u32 *)b;
        r->nmfat = (u32)(len / 4);
    }

    /* mini stream = the root entry's chain */
    const u8 *root = r->dir;
    u64 rsize = r->shift >= 12 ? rd64(root + 0x78) : rd32(root + 0x78);
    if (r->nmfat && rsize) {
        u64 want = (rsize >> r->shift) + ((rsize & ((1u << r->shift) - 1)) != 0);
        if (want > r->nfat) want = r->nfat;
        r->msid = (u32 *)gz_alloc((size_t)want * 4 + 4);
        if (!r->msid) return GZ_E_NOMEM;
        u32 sid = rd32(root + 0x74);
        while (r->nmsid < want && sid < r->nfat && !bit_test_set(r->own, sid)) {
            r->msid[r->nmsid++] = sid;
            sid = r->fat[sid];
        }
        u64 mbytes = (u64)r->nmsid << r->shift;
        if (mbytes > rsize) mbytes = rsize;
        u64 nm = (mbytes + (1u << r->mshift) - 1) >> r->mshift;
        r->nmini = nm < r->nmfat ? (u32)nm : r->nmfat;
        r->mown = (u8 *)gz_alloc(((size_t)r->nmini >> 3) + 1);
        if (!r->mown) return GZ_E_NOMEM;
    }
    return GZ_OK;
}

/* archive named .msi / .msp / .mst / .msm */
static int file_is_msi(const gz_open_opts *o)
{
    const gzch *f = o ? o->file_name : 0;
    if (!f) return 0;
    size_t n = gz_wcslen(f);
    if (n < 4 || f[n - 4] != '.' || (f[n - 3] | 0x20) != 'm' || (f[n - 2] | 0x20) != 's') return 0;
    gzch x = (gzch)(f[n - 1] | 0x20);
    return x == 'i' || x == 'p' || x == 't' || x == 'm';
}

static int add_entries(gz_archive *a, cfb_rd *r, cfb_ref *refs, u32 n, gz_ctx *c, int is_msi)
{
    /* converted names of storages (needed for their children's paths); a stream's name
     * only lives in the scratch slot at the end until its entry is added */
    u32 ncap = 4096, nn = 0;
    gzch *names = (gzch *)gz_alloc((size_t)ncap * sizeof(gzch));
    gzch *path = (gzch *)gz_alloc((size_t)CFB_MAX_DEPTH * (CFB_NAME_MAX + 1) * sizeof(gzch));
    int res = GZ_E_NOMEM;
    if (!names || !path) goto done;
    for (u32 i = 0; i < n; i++) {
        if (!(i & 1023) && gz_cancelled(c)) { res = GZ_E_CANCEL; goto done; }
        if (nn + CFB_NAME_MAX > ncap) {
            gzch *nb = (gzch *)gz_realloc(names, (size_t)ncap * 2 * sizeof(gzch));
            if (!nb) goto done;
            names = nb;
            ncap *= 2;
        }
        cfb_ref *f = &refs[i];
        const u8 *d = r->dir + (size_t)f->did * 128;
        u32 rl = raw_name_len(d), inr = 0;
        for (u32 k = 0; k < rl; k++) inr += msi_unit(rd16(d + 2 * k));
        f->noff = nn;
        f->nlen = conv_name(d, rl, (rl && inr == rl) || (is_msi && inr), names + nn);

        int isdir = d[0x42] == T_STORAGE;
        u64 size = 0, mapped = 0;
        u32 x0 = r->p->nx;
        int mini = 0;
        if (isdir) {
            nn += f->nlen;
        } else {
            size = r->shift >= 12 ? rd64(d + 0x78) : rd32(d + 0x78);
            mini = size < r->cutoff;
            if (size) {
                int er = walk(r, rd32(d + 0x74), size, mini, &mapped);
                if (er) { res = er; goto done; }
            }
            /* embedded cabinets (MSI media, MSP patch cabinets) without an extension */
            if (is_msi && mapped >= 4 && !ends_with_cab(names + nn, f->nlen)) {
                u8 m[4];
                if (!gz_src_read_exact(r->s, r->p->x[x0].phys, m, 4) && !__builtin_memcmp(m, "MSCF", 4)) {
                    gzch *t = names + nn + f->nlen;
                    t[0] = '.'; t[1] = 'c'; t[2] = 'a'; t[3] = 'b';
                    f->nlen += 4;
                }
            }
        }

        /* full path, built back to front from the parent chain (depth < CFB_MAX_DEPTH) */
        u32 cap = CFB_MAX_DEPTH * (CFB_NAME_MAX + 1), pos = cap;
        for (i32 j = (i32)i; j >= 0; j = refs[j].parent) {
            const cfb_ref *g = &refs[j];
            if (pos != cap) path[--pos] = '/';
            pos -= g->nlen;
            __builtin_memcpy(path + pos, names + g->noff, (size_t)g->nlen * sizeof(gzch));
        }
        if (a->raw_len + (cap - pos) * 2 > CFB_MAX_NAMES) { res = GZ_E_LIMIT; goto done; }
        gz_entry *e;
        int er = gz_arc_add_named(a, path + pos, (cap - pos) * 2, GZ_NE_UTF16LE, &e);
        if (er) { res = er; goto done; }
        u64 ct = rd64(d + 0x64), mt = rd64(d + 0x6C);
        if (mt || ct) { e->mtime = mt ? mt : ct; e->mtime_kind = GZ_MT_FILETIME; }
        if (isdir) {
            e->is_dir = 1;
            e->attr = 0x10;
            continue;
        }
        u32 cs = 1u << (mini ? r->mshift : r->shift);
        e->usize = size;
        e->csize = (mapped + cs - 1) & ~(u64)(cs - 1);      /* allocated size, like 7-Zip */
        e->off = x0;
        e->aux32 = r->p->nx - x0;
        e->aux = mapped;
        e->flags = (u16)((mini ? CF_MINI : 0) | (mapped < size ? CF_BROKEN : 0));
    }
    res = GZ_OK;
done:
    gz_free(names);
    gz_free(path);
    return res;
}

static void cfb_close(gz_archive *a)
{
    cfb_priv *p = (cfb_priv *)a->priv;
    if (!p) return;
    gz_free(p->x);
    gz_free(p);
    a->priv = 0;
}

static int cfb_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    u8 h[512];
    int res = gz_src_read_exact(s, 0, h, 512);
    if (res) return res == GZ_E_TRUNC ? GZ_E_FORMAT : res;
    if (!hdr_ok(h)) return GZ_E_FORMAT;

    cfb_rd r;
    __builtin_memset(&r, 0, sizeof r);
    r.s = s;
    r.shift = rd16(h + 0x1E);
    r.mshift = rd16(h + 0x20);
    r.cutoff = rd32(h + 0x38);
    u64 ss = (u64)1 << r.shift;
    u64 nsec = s->size > ss ? (s->size - 1) >> r.shift : 0;
    r.nsec = nsec > CFB_MAXREG ? CFB_MAXREG : (u32)nsec;
    if (!r.nsec) return GZ_E_FORMAT;

    cfb_priv *p = (cfb_priv *)gz_alloc(sizeof(cfb_priv));
    if (!p) return GZ_E_NOMEM;
    a->priv = p;
    r.p = p;
    cfb_ref *refs = 0;
    u32 n = 0;
    res = read_fat(&r, h);
    if (!res) res = open_dir(&r, h);
    if (!res) res = collect_refs(&r, &refs, &n);
    if (!res) {
        int is_msi = file_is_msi(o);
        for (u32 i = 0; i < n && !is_msi; i++) is_msi = msi_unit(rd16(r.dir + (size_t)refs[i].did * 128));
        res = add_entries(a, &r, refs, n, c, is_msi);
        if (!res && is_msi) gz_arc_set_type(a, "MSI");
    }
    gz_free(refs);
    gz_free(r.fat);
    gz_free(r.own);
    gz_free(r.mfat);
    gz_free(r.msid);
    gz_free(r.mown);
    gz_free(r.dir);
    if (res) cfb_close(a);
    return res;
}

static int cfb_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    return n >= 512 && hdr_ok(h) ? 95 : 0;
}

/* ---------------- extraction ---------------- */

static int cfb_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    const gz_entry *e = &a->e[idx];
    int r = out->open(out, idx);
    if (r) return r;
    if (e->is_dir) return out->close(out, idx, GZ_OK);
    const cfb_priv *p = (const cfb_priv *)a->priv;
    const u32 cap = 256u << 10;
    u8 *buf = gz_ctx_buffer(c, cap);
    int st = buf ? GZ_OK : GZ_E_NOMEM;
    u64 pos = 0;
    u32 bp = 0;
    /* gather extents (mini streams are often 64-byte pieces) into large writes */
    for (u32 i = 0; i < e->aux32 && !st; i++) {
        const cfb_ext *x = &p->x[e->off + i];
        u64 phys = x->phys, len = x->lend - pos;
        pos = x->lend;
        while (len && !st) {
            u32 take = len < cap - bp ? (u32)len : cap - bp;
            st = gz_src_read_exact(s, phys, buf + bp, take);
            phys += take;
            len -= take;
            bp += take;
            if (!st && bp == cap) {
                st = gz_cancelled(c) ? GZ_E_CANCEL : out->write(out, buf, bp);
                bp = 0;
            }
        }
    }
    if (!st && bp) st = out->write(out, buf, bp);
    if (!st && (e->flags & CF_BROKEN)) st = GZ_E_DATA;
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

/* ---------------- view: the stream's extents as a random-access source ---------------- */

typedef struct {
    gz_src s;
    gz_src *par;
    u32 n, cur;
    cfb_ext x[];
} cfb_view;

static int view_read(gz_src *v, u64 off, void *buf, u32 n, u32 *got)
{
    cfb_view *w = (cfb_view *)v;
    u8 *p = (u8 *)buf;
    *got = 0;
    if (off >= v->size) return GZ_OK;
    if (n > v->size - off) n = (u32)(v->size - off);
    u32 i = w->cur;
    if (i >= w->n || off >= w->x[i].lend || (i && off < w->x[i - 1].lend)) {
        u32 lo = 0, hi = w->n - 1;                  /* first extent with lend > off */
        while (lo < hi) {
            u32 mid = lo + (hi - lo) / 2;
            if (w->x[mid].lend > off) hi = mid; else lo = mid + 1;
        }
        i = lo;
    }
    while (n && i < w->n) {
        u64 ls = i ? w->x[i - 1].lend : 0;
        u64 avail = w->x[i].lend - off;
        u32 take = n < avail ? n : (u32)avail;
        u32 g = 0;
        int r = w->par->read_at(w->par, w->x[i].phys + (off - ls), p, take, &g);
        if (r) return r;
        *got += g;
        if (g < take) break;
        p += g;
        off += g;
        n -= g;
        if (off >= w->x[i].lend) i++;
    }
    w->cur = i < w->n ? i : w->n - 1;
    return GZ_OK;
}

static void view_free(gz_src *v) { gz_free(v); }

static gz_src *cfb_view_entry(gz_archive *a, gz_src *s, u32 idx)
{
    const gz_entry *e = &a->e[idx];
    if (e->is_dir) return 0;
    const cfb_priv *p = (const cfb_priv *)a->priv;
    cfb_view *w = (cfb_view *)gz_alloc(sizeof(cfb_view) + (size_t)e->aux32 * sizeof(cfb_ext));
    if (!w) return 0;
    if (e->aux32) __builtin_memcpy(w->x, p->x + e->off, (size_t)e->aux32 * sizeof(cfb_ext));
    w->n = e->aux32;
    w->par = s;
    w->s.read_at = view_read;
    w->s.size = e->aux32 ? e->aux : 0;
    w->s.free = view_free;
    return &w->s;
}

GZ_FORMAT(gz_fmt_cfb)
const gz_format gz_fmt_cfb = {
    "Compound", "msi msp mst msm doc xls ppt msg",
    0, cfb_probe, cfb_open, cfb_close, cfb_extract, 0, 0, 0, cfb_view_entry, 0
};
