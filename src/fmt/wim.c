/*
 * 고깃ZIP - Windows Imaging reader (WIM / ESD / split SWM)
 *
 *   Header (208 bytes) -> blob table (50-byte entries: resource header, part number,
 *   reference count, SHA-1), XML data, one metadata resource per image (security
 *   data + dentry tree). File data is addressed by SHA-1: a dentry names the hash
 *   of each of its streams (unnamed data, reparse data, named alternate streams).
 *
 *   Resources: uncompressed; compressed in independent chunks (chunk table of
 *   offsets in front; XPRESS Huffman, LZX with the WIM parameters, LZMS); solid
 *   resources (version 3584) whose own header gives size, chunk size and method,
 *   followed by the compressed size of every chunk; blobs live at offsets inside
 *   the concatenated solid resources of their run of table entries.
 *
 *   Entries: a single image is shown at the root, several images as folders "1",
 *   "2", ... plus the XML data as "[1].xml" (both like 7-Zip). Named streams become
 *   aux entries "file:stream". Symbolic links and junctions become links (target
 *   from the reparse data, '/' separated, "\??\C:" dropped); hard links are plain
 *   files sharing a blob. Every blob is checked against its SHA-1 (GZ_E_CRC).
 *
 *   Non-solid blobs are extracted independently (any thread); WIMs with solid
 *   resources set a->solid and extract_solid decodes each chunk once, in order.
 *   Split WIMs: the parts "name.swm", "name2.swm", ... are opened through
 *   o->open_volume and matched by GUID and part number. Encrypted ESD files
 *   (XML <ENCRYPTED>) give GZ_E_METHOD.
 */
#include "arc.h"
#include "lzx.h"
#include "xpress.h"
#include "lzms.h"

#define HDR_SIZE        208u
#define RF_COMPRESSED   0x04u
#define RF_METADATA     0x02u
#define RF_SPANNED      0x08u
#define RF_SOLID        0x10u
#define HF_COMPRESSION  0x00000002u
#define HF_XPRESS       0x00020000u
#define HF_LZX          0x00040000u
#define HF_LZMS         0x00080000u
#define SOLID_MAGIC     0x100000000ull
#define FA_DIRECTORY    0x10u
#define FA_REPARSE      0x400u
#define FA_ENCRYPTED    0x4000u
#define TAG_SYMLINK     0xA000000Cu
#define TAG_MOUNT       0xA0000003u
#define TAG_UNIX        0x337DD873u
#define DENTRY_FIXED    102u
#define STREAM_FIXED    38u

#define MAX_META        (256u << 20)    /* metadata resource of one image            */
#define MAX_TABLE       (256u << 20)    /* blob table                                */
#define MAX_XML         (32u << 20)
#define MAX_CHUNK       (1u << 30)
#define MAX_CHUNKS      (1u << 22)      /* chunks of one resource                    */
#define MAX_IMAGES      4096u
#define MAX_PARTS       4096u
#define MAX_ENTRIES     (8u << 20)
#define MAX_PATH_BYTES  65534u          /* UTF-16LE bytes of a full path             */
#define MAX_REPARSE     (64u << 10)
#define TOTAL_META      (2ull << 30)    /* metadata bytes parsed over all images     */

enum { CT_NONE = 0, CT_XPRESS = 1, CT_LZX = 2, CT_LZMS = 3, CT_UNKNOWN = 15 };
enum { RK_RAW = 0, RK_CHUNKED, RK_SOLID, RK_BAD };
enum { EF_LINK = 1, EF_MISSING = 2, EF_XML = 4 };         /* gz_entry.flags */
#define M_SOLID 0x8000u                                   /* gz_entry.method */

typedef struct {
    u64 off, csize, usize;   /* in part `part`; usize: uncompressed data size        */
    u32 chunk;               /* chunk size of the compressed kinds                   */
    u16 part;                /* 1-based part number                                  */
    u8 kind, ctype;          /* RK_*, CT_*                                           */
    u8 err;                  /* RK_BAD: error reported when a blob is read           */
} wim_res;

typedef struct {
    u8 hash[20];
    u8 has_hash;             /* 0: internal (XML, tables), not verified              */
    u8 meta;                 /* metadata resource                                    */
    u32 res;
    u64 off, size;           /* range in the uncompressed resource                   */
} wim_blob;

typedef struct {
    wim_res *res;   u32 nres, capres;
    wim_blob *blob; u32 nblob, capblob;
    u32 *byhash; u32 nhash;  /* blobs with a hash, sorted by (hash, table order)     */
    i32 *pvol;               /* part -> -1 own source, k >= 0 a->vols[k], -2 missing */
    u32 nparts, own_part;
    int missing;             /* some part could not be opened                        */
} wim_priv;

typedef struct {
    u32 version, flags, chunk, images;
    u16 part, total;
    u8 guid[16];
    u8 table[24], xml[24];
} wim_hdr;

typedef struct { u64 csize, off, usize; u8 flags; } reshdr;

static void get_reshdr(const u8 *b, reshdr *r)
{
    r->csize = rd64(b) & 0x00FFFFFFFFFFFFFFull;
    r->flags = b[7];
    r->off = rd64(b + 8);
    r->usize = rd64(b + 16);
}

static int parse_hdr(const u8 *h, wim_hdr *w)
{
    if (__builtin_memcmp(h, "MSWIM\0\0\0", 8) || rd32(h + 8) < HDR_SIZE) return GZ_E_FORMAT;
    w->version = rd32(h + 12);
    w->flags = rd32(h + 16);
    w->chunk = rd32(h + 20);
    __builtin_memcpy(w->guid, h + 24, 16);
    w->part = rd16(h + 40);
    w->total = rd16(h + 42);
    w->images = rd32(h + 44);
    __builtin_memcpy(w->table, h + 48, 24);
    __builtin_memcpy(w->xml, h + 72, 24);
    if (!w->total) w->total = 1;
    if (!w->part || w->part > w->total) return GZ_E_FORMAT;
    return GZ_OK;
}

static u32 hdr_ctype(const wim_hdr *h)
{
    if (!(h->flags & HF_COMPRESSION)) return CT_NONE;
    if (h->flags & HF_LZMS) return CT_LZMS;
    if (h->flags & HF_LZX) return CT_LZX;
    if (h->flags & HF_XPRESS) return CT_XPRESS;
    return CT_UNKNOWN;
}

static u32 log2u(u32 v) { return 31u - (u32)__builtin_clz(v | 1); }

/* chunk sizes each method can decode */
static int chunk_ok(u32 ctype, u32 chunk)
{
    if (!chunk || chunk > MAX_CHUNK) return 0;
    if (ctype == CT_LZX) return !(chunk & (chunk - 1)) && chunk >= (1u << 15) && chunk <= (1u << 21);
    if (ctype == CT_XPRESS) return chunk >= 4096 && chunk <= (1u << 26);
    return 1;
}

/* ---------------- tables ---------------- */

static int add_res(wim_priv *p, u32 *out)
{
    if (p->nres == p->capres) {
        u32 nc = p->capres ? p->capres * 2 : 64;
        wim_res *n = (wim_res *)gz_realloc(p->res, (size_t)nc * sizeof(wim_res));
        if (!n) return GZ_E_NOMEM;
        p->res = n;
        p->capres = nc;
    }
    __builtin_memset(&p->res[p->nres], 0, sizeof(wim_res));
    *out = p->nres++;
    return GZ_OK;
}

static int add_blob(wim_priv *p, u32 res, u64 off, u64 size, const u8 *hash, u32 *out)
{
    if (p->nblob == p->capblob) {
        u32 nc = p->capblob ? p->capblob * 2 : 256;
        wim_blob *n = (wim_blob *)gz_realloc(p->blob, (size_t)nc * sizeof(wim_blob));
        if (!n) return GZ_E_NOMEM;
        p->blob = n;
        p->capblob = nc;
    }
    wim_blob *b = &p->blob[p->nblob];
    __builtin_memset(b, 0, sizeof *b);
    b->res = res;
    b->off = off;
    b->size = size;
    if (hash) { __builtin_memcpy(b->hash, hash, 20); b->has_hash = 1; }
    *out = p->nblob++;
    return GZ_OK;
}

static int is_zero_hash(const u8 *h)
{
    u8 x = 0;
    for (int i = 0; i < 20; i++) x |= h[i];
    return !x;
}

static int hash_less(const wim_priv *p, u32 x, u32 y)
{
    int c = __builtin_memcmp(p->blob[x].hash, p->blob[y].hash, 20);
    return c < 0 || (!c && x < y);
}

/* Index of the blobs by SHA-1 (merge sort: no worst case on crafted hashes). */
static int hash_index(wim_priv *p)
{
    u32 n = 0;
    p->byhash = (u32 *)gz_alloc((size_t)p->nblob * 2 * sizeof(u32) + 8);
    if (!p->byhash) return GZ_E_NOMEM;
    for (u32 i = 0; i < p->nblob; i++) {
        const wim_blob *b = &p->blob[i];
        if (b->has_hash && !b->meta && !is_zero_hash(b->hash)) p->byhash[n++] = i;
    }
    u32 *src = p->byhash, *dst = p->byhash + n;
    for (u32 w = 1; w < n; w *= 2) {
        for (u32 lo = 0; lo < n; lo += 2 * w) {
            u32 mid = lo + w < n ? lo + w : n, hi = lo + 2 * w < n ? lo + 2 * w : n;
            u32 i = lo, j = mid, o = lo;
            while (i < mid && j < hi) dst[o++] = hash_less(p, src[j], src[i]) ? src[j++] : src[i++];
            while (i < mid) dst[o++] = src[i++];
            while (j < hi) dst[o++] = src[j++];
        }
        u32 *t = src; src = dst; dst = t;
    }
    if (src != p->byhash) __builtin_memcpy(p->byhash, src, (size_t)n * sizeof(u32));
    p->nhash = n;
    return GZ_OK;
}

/* first blob (in table order) with this hash, or -1 */
static i32 hash_find(const wim_priv *p, const u8 *hash)
{
    u32 lo = 0, hi = p->nhash;
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        if (__builtin_memcmp(p->blob[p->byhash[mid]].hash, hash, 20) < 0) lo = mid + 1; else hi = mid;
    }
    if (lo < p->nhash && !__builtin_memcmp(p->blob[p->byhash[lo]].hash, hash, 20)) return (i32)p->byhash[lo];
    return -1;
}

static gz_src *part_src(gz_archive *a, gz_src *s, u32 part)
{
    wim_priv *p = (wim_priv *)a->priv;
    if (!part || part > p->nparts) return 0;
    i32 v = p->pvol[part];
    return v == -1 ? s : v >= 0 ? a->vols[v] : 0;
}

/* Resource of a non-solid table entry (or a header resource) in part `part`. */
static int make_res(wim_priv *p, const reshdr *rh, u32 part, u32 ctype, u32 chunk, u32 *out)
{
    int r = add_res(p, out);
    if (r) return r;
    wim_res *R = &p->res[*out];
    R->off = rh->off;
    R->csize = rh->csize;
    R->usize = rh->usize;
    R->part = (u16)part;
    R->chunk = chunk;
    if (rh->flags & RF_SPANNED) {
        R->kind = RK_BAD;
        R->err = GZ_E_METHOD;
    } else if (!(rh->flags & RF_COMPRESSED) || !rh->usize) {
        R->kind = RK_RAW;
        R->ctype = CT_NONE;
    } else {
        R->kind = RK_CHUNKED;
        R->ctype = (u8)ctype;
        if (ctype == CT_UNKNOWN) { R->kind = RK_BAD; R->err = GZ_E_METHOD; }
        else if (!chunk_ok(ctype, chunk)) { R->kind = RK_BAD; R->err = GZ_E_FORMAT; }
    }
    return GZ_OK;
}

/* One part's blob table: t[0..n) entries. Metadata blobs are appended to meta[]. */
static int parse_table(wim_priv *p, gz_src *src, const wim_hdr *h, const u8 *t, u32 n,
                       u32 *meta, u32 *nmeta, u32 maxmeta)
{
    u32 ctype = hdr_ctype(h), chunk = h->chunk ? h->chunk : 32768;
    u32 *run = 0;
    u64 *cum = 0;
    int r = GZ_OK;
    for (u32 i = 0; i < n && !r;) {
        const u8 *ent = t + (size_t)i * 50;
        reshdr rh;
        get_reshdr(ent, &rh);
        if (rd16(ent + 24) != h->part) { i++; continue; }     /* listed for another part */
        if (!(rh.flags & RF_SOLID)) {
            u32 ri, bi;
            if ((r = make_res(p, &rh, h->part, ctype, chunk, &ri))) break;
            if ((r = add_blob(p, ri, 0, rh.usize, ent + 30, &bi))) break;
            if (rh.flags & RF_METADATA) {
                p->blob[bi].meta = 1;
                if (*nmeta < maxmeta) meta[(*nmeta)++] = bi;
            }
            i++;
            continue;
        }
        /* a run of solid entries: resource entries (usize == SOLID_MAGIC) and blobs
         * addressed inside the concatenation of the run's resources */
        u32 j = i, nr = 0;
        while (j < n && (t[(size_t)j * 50 + 7] & RF_SOLID)) j++;
        gz_free(run);
        gz_free(cum);
        run = (u32 *)gz_alloc((size_t)(j - i) * sizeof(u32) + 4);
        cum = (u64 *)gz_alloc(((size_t)(j - i) + 1) * sizeof(u64));
        if (!run || !cum) { r = GZ_E_NOMEM; break; }
        for (u32 k = i; k < j; k++) {
            const u8 *e2 = t + (size_t)k * 50;
            reshdr sh;
            get_reshdr(e2, &sh);
            if (sh.usize != SOLID_MAGIC || rd16(e2 + 24) != h->part) continue;
            u32 ri;
            if ((r = add_res(p, &ri))) break;
            wim_res *R = &p->res[ri];
            R->off = sh.off;
            R->csize = sh.csize;
            R->part = h->part;
            R->kind = RK_SOLID;
            u8 sh16[16];
            if (sh.csize < 16 || sh.off > src->size || src->size - sh.off < sh.csize ||
                gz_src_read_exact(src, sh.off, sh16, 16)) {
                R->kind = RK_BAD;
                R->err = GZ_E_FORMAT;
            } else {
                R->usize = rd64(sh16);
                R->chunk = rd32(sh16 + 8);
                u32 ct = rd32(sh16 + 12);
                R->ctype = (u8)(ct <= CT_LZMS ? ct : CT_UNKNOWN);
                if (ct > CT_LZMS) { R->kind = RK_BAD; R->err = GZ_E_METHOD; }
                else if (R->usize && !chunk_ok(ct, R->chunk)) { R->kind = RK_BAD; R->err = GZ_E_FORMAT; }
            }
            /* start of each resource in the run (saturating) */
            u64 us = R->usize;
            cum[nr + 1] = cum[nr] + us < cum[nr] ? ~0ull : cum[nr] + us;
            run[nr++] = ri;
        }
        for (u32 k = i; k < j && !r; k++) {
            const u8 *e2 = t + (size_t)k * 50;
            reshdr bh;
            get_reshdr(e2, &bh);
            if (bh.usize == SOLID_MAGIC || rd16(e2 + 24) != h->part) continue;
            /* blob: offset_in_wim = offset in the run, size_in_wim = size; it must lie
             * inside one resource: the first one ending after its start */
            u64 off = bh.off, size = bh.csize;
            u32 ri = ~0u, lo = 0, hi = nr;
            while (lo < hi) {
                u32 mid = lo + (hi - lo) / 2;
                if (cum[mid + 1] > off) hi = mid; else lo = mid + 1;
            }
            if (lo < nr && size <= cum[lo + 1] - off) {
                ri = run[lo];
                off -= cum[lo];
            } else if (!size && nr) {
                ri = run[0];                         /* empty: never read */
                off = 0;
            }
            u32 bi;
            if (ri == ~0u) {
                /* no resource holds it: keep the blob, reading it fails */
                if ((r = add_res(p, &ri))) break;
                p->res[ri].kind = RK_BAD;
                p->res[ri].err = GZ_E_FORMAT;
                p->res[ri].part = h->part;
                off = 0;
            }
            if ((r = add_blob(p, ri, off, size, e2 + 30, &bi))) break;
            if (bh.flags & RF_METADATA) {
                p->blob[bi].meta = 1;
                if (*nmeta < maxmeta) meta[(*nmeta)++] = bi;
            }
        }
        i = j;
    }
    gz_free(run);
    gz_free(cum);
    return r;
}

/* ---------------- resource reader ---------------- */

typedef struct {
    gz_archive *a;
    gz_src *s;
    gz_ctx *c;
    u8 *buf; size_t cap; int own;   /* ubuf | cbuf                               */
    u8 *ubuf, *cbuf;
    size_t ucap;
    u32 cres; u64 cidx; size_t cn;  /* decoded chunk in ubuf (cres ~0: none)      */
    u64 *tab; u64 tn; u32 tres;     /* chunk starts (absolute) of resource tres   */
    size_t tabcap;
} wim_rd;

static void rd_init(wim_rd *r, gz_archive *a, gz_src *s, gz_ctx *c)
{
    __builtin_memset(r, 0, sizeof *r);
    r->a = a;
    r->s = s;
    r->c = c;
    r->cres = ~0u;
    r->tres = ~0u;
}

static void rd_free(wim_rd *r)
{
    if (r->own) gz_free_big(r->buf, r->cap);
    gz_free(r->tab);
    r->buf = 0;
    r->tab = 0;
}

/* ubuf of at least u bytes and cbuf of at least u bytes (u >= 64 KiB) */
static int rd_bufs(wim_rd *r, size_t u)
{
    if (u < (64u << 10)) u = 64u << 10;
    if (r->ucap >= u) return GZ_OK;
    size_t need = u * 2;
    if (r->own) gz_free_big(r->buf, r->cap);
    r->buf = 0;
    r->own = 0;
    r->cap = r->ucap = 0;
    r->cres = ~0u;
    if (need <= (16u << 20)) {
        r->buf = gz_ctx_buffer(r->c, (u32)need);
    } else {
        r->buf = (u8 *)gz_alloc_big(need);
        r->own = 1;
    }
    if (!r->buf) { r->own = 0; return GZ_E_NOMEM; }
    r->cap = need;
    r->ucap = u;
    r->ubuf = r->buf;
    r->cbuf = r->buf + u;
    return GZ_OK;
}

/* Chunk start offsets of a compressed resource (validated). */
static int rd_table(wim_rd *r, u32 ri)
{
    if (r->tres == ri) return GZ_OK;
    wim_priv *p = (wim_priv *)r->a->priv;
    const wim_res *R = &p->res[ri];
    gz_src *src = part_src(r->a, r->s, R->part);
    if (!src) return GZ_E_VOLUME;
    if (R->off > src->size || src->size - R->off < R->csize) return GZ_E_TRUNC;
    u64 n = (R->usize - 1) / R->chunk + 1;
    if (n > MAX_CHUNKS) return GZ_E_LIMIT;
    u32 esz = R->kind == RK_SOLID ? 4 : R->usize > 0xFFFFFFFFull ? 8 : 4;
    u64 tb = R->kind == RK_SOLID ? 16 + n * 4 : (n - 1) * esz;
    if (tb > R->csize) return GZ_E_FORMAT;
    if (r->tabcap < n + 1) {
        gz_free(r->tab);
        r->tab = (u64 *)gz_alloc((size_t)(n + 1) * sizeof(u64));
        r->tabcap = r->tab ? (size_t)(n + 1) : 0;
        if (!r->tab) return GZ_E_NOMEM;
    }
    r->tres = ~0u;
    u64 base = R->off + tb, end = R->off + R->csize, *t = r->tab;
    u8 tmp[4096];
    u64 pos = R->off + (R->kind == RK_SOLID ? 16 : 0), left = tb - (R->kind == RK_SOLID ? 16 : 0);
    u64 k = 0;
    t[0] = base;
    while (left) {
        u32 take = left < sizeof tmp ? (u32)left : (u32)sizeof tmp;
        int e = gz_src_read_exact(src, pos, tmp, take);
        if (e) return e;
        for (u32 q = 0; q + esz <= take; q += esz) {
            u64 v = esz == 8 ? rd64(tmp + q) : rd32(tmp + q);
            k++;
            if (R->kind == RK_SOLID) {
                if (v > end - t[k - 1]) return GZ_E_FORMAT;
                t[k] = t[k - 1] + v;
            } else {
                if (v > end - base) return GZ_E_FORMAT;
                t[k] = base + v;
            }
        }
        pos += take;
        left -= take;
    }
    if (R->kind != RK_SOLID) t[n] = end;
    /* every chunk: 1 <= compressed size <= uncompressed size */
    for (u64 q = 0; q < n; q++) {
        u64 us = q + 1 < n ? R->chunk : R->usize - (n - 1) * (u64)R->chunk;
        if (t[q + 1] <= t[q] || t[q + 1] - t[q] > us) return GZ_E_FORMAT;
    }
    r->tres = ri;
    r->tn = n;
    return GZ_OK;
}

static int rd_chunk(wim_rd *r, u32 ri, u64 k, const u8 **out, size_t *on)
{
    if (r->cres == ri && r->cidx == k) { *out = r->ubuf; *on = r->cn; return GZ_OK; }
    if (gz_cancelled(r->c)) return GZ_E_CANCEL;
    int st = rd_table(r, ri);
    if (st) return st;
    wim_priv *p = (wim_priv *)r->a->priv;
    const wim_res *R = &p->res[ri];
    if (k >= r->tn) return GZ_E_FORMAT;
    size_t us = (size_t)(k + 1 < r->tn ? R->chunk : R->usize - k * (u64)R->chunk);
    size_t cs = (size_t)(r->tab[k + 1] - r->tab[k]);
    if ((st = rd_bufs(r, R->usize < R->chunk ? (size_t)R->usize : R->chunk))) return st;
    r->cres = ~0u;
    gz_src *src = part_src(r->a, r->s, R->part);
    if (!src) return GZ_E_VOLUME;
    if (cs == us) {
        st = gz_src_read_exact(src, r->tab[k], r->ubuf, (u32)us);
    } else if (!(st = gz_src_read_exact(src, r->tab[k], r->cbuf, (u32)cs))) {
        switch (R->ctype) {
        case CT_XPRESS:
            st = gz_xpress_huff_decode(r->cbuf, cs, r->ubuf, us);
            break;
        case CT_LZX: {
            gz_lzx_dec *d = (gz_lzx_dec *)gz_ctx_slot(r->c, GZ_SLOT_LZX, gz_lzx_slot_new, gz_lzx_slot_free);
            if (!d) return GZ_E_NOMEM;
            st = gz_lzx_init(d, log2u(R->chunk), GZ_LZX_WIM);
            if (!st) st = gz_lzx_decode_chunk(d, r->cbuf, (u32)cs, r->ubuf, (u32)us);
            break;
        }
        case CT_LZMS: {
            gz_lzms_dec *d = (gz_lzms_dec *)gz_ctx_slot(r->c, GZ_SLOT_MISC1, gz_lzms_slot_new, gz_lzms_slot_free);
            if (!d) return GZ_E_NOMEM;
            st = gz_lzms_decode(d, r->cbuf, cs, r->ubuf, us);
            break;
        }
        default:
            st = GZ_E_METHOD;
        }
        if (st == GZ_E_TRUNC) st = GZ_E_DATA;
    }
    if (st) return st;
    r->cres = ri;
    r->cidx = k;
    r->cn = us;
    *out = r->ubuf;
    *on = us;
    return GZ_OK;
}

typedef int (*wim_sink)(void *user, const u8 *p, size_t n);

/* Pass the data of blob bi to fn. */
static int rd_blob(wim_rd *r, u32 bi, wim_sink fn, void *user)
{
    wim_priv *p = (wim_priv *)r->a->priv;
    const wim_blob *b = &p->blob[bi];
    const wim_res *R = &p->res[b->res];
    if (!b->size) return GZ_OK;
    if (R->kind == RK_BAD) return R->err;
    if (b->off > R->usize || b->size > R->usize - b->off) return GZ_E_FORMAT;
    int st;
    if (R->kind == RK_RAW) {
        gz_src *src = part_src(r->a, r->s, R->part);
        if (!src) return GZ_E_VOLUME;
        if ((st = rd_bufs(r, 1u << 20))) return st;
        r->cres = ~0u;
        u64 pos = R->off + b->off, left = b->size;
        if (pos < R->off) return GZ_E_FORMAT;
        while (left) {
            if (gz_cancelled(r->c)) return GZ_E_CANCEL;
            u32 take = left < r->ucap ? (u32)left : (u32)r->ucap;
            if ((st = gz_src_read_exact(src, pos, r->ubuf, take))) return st;
            if ((st = fn(user, r->ubuf, take))) return st;
            pos += take;
            left -= take;
        }
        return GZ_OK;
    }
    u64 pos = b->off, end = b->off + b->size;
    while (pos < end) {
        u64 k = pos / R->chunk;
        const u8 *cp;
        size_t cn;
        if ((st = rd_chunk(r, b->res, k, &cp, &cn))) return st;
        size_t from = (size_t)(pos - k * R->chunk);
        if (from >= cn) return GZ_E_FORMAT;
        size_t take = cn - from;
        if (take > end - pos) take = (size_t)(end - pos);
        if ((st = fn(user, cp + from, take))) return st;
        pos += take;
    }
    return GZ_OK;
}

/* blob data into memory (at most cap bytes) */
static int read_all(wim_rd *r, u32 bi, size_t cap, gz_mem_sink *m)
{
    __builtin_memset(m, 0, sizeof *m);
    m->limit = cap;
    const wim_blob *b = &((wim_priv *)r->a->priv)->blob[bi];
    if (b->size > cap) return GZ_E_LIMIT;
    return rd_blob(r, bi, gz_mem_write, m);
}

static int hash_ok(const wim_blob *b, const u8 *p, size_t n)
{
    if (!b->has_hash) return 1;
    u8 d[20];
    gz_sha1_calc(p, n, d);
    return !__builtin_memcmp(d, b->hash, 20);
}

/* ---------------- reparse points ---------------- */

/* Link target (UTF-8, '/' separated) from symlink / junction reparse data. */
static int reparse_target(const u8 *rp, size_t n, u32 tag, u8 **out, u32 *outn)
{
    u32 hl = tag == TAG_SYMLINK ? 12 : 8;
    if (n < hl) return GZ_E_DATA;
    u32 so = rd16(rp), sl = rd16(rp + 2), po = rd16(rp + 4), pl = rd16(rp + 6);
    int rel = tag == TAG_SYMLINK && (rd32(rp + 8) & 1);
    const u8 *pb = rp + hl;
    size_t pn = n - hl;
    if (!sl || (sl & 1) || so + sl > pn) { so = po; sl = pl; }
    if (!sl || (sl & 1) || so + sl > pn) return GZ_E_DATA;
    u32 m = sl / 2, k = 0;
    gzch *w = (gzch *)gz_alloc(((size_t)m + 2) * sizeof(gzch));
    u8 *u = (u8 *)gz_alloc((size_t)m * 3 + 4);
    if (!w || !u) { gz_free(w); gz_free(u); return GZ_E_NOMEM; }
    for (u32 i = 0; i < m; i++) w[i] = rd16(pb + so + 2 * i);
    gzch *s = w;
    if (m >= 4 && s[0] == '\\' && (s[1] == '?' || s[1] == '\\') && s[2] == '?' && s[3] == '\\') {
        s += 4;                                         /* \??\ or \\?\ */
        m -= 4;
        if (m >= 4 && (s[0] | 32) == 'u' && (s[1] | 32) == 'n' && (s[2] | 32) == 'c' && s[3] == '\\') {
            s += 2;                                     /* UNC\srv -> \\srv */
            m -= 2;
            s[0] = '\\';
        }
    }
    if (!rel && m >= 2 && s[1] == ':' && (((s[0] | 32) >= 'a' && (s[0] | 32) <= 'z'))) {
        s += 2;                                         /* drive letter */
        m -= 2;
    }
    for (u32 i = 0; i < m; i++) if (s[i] == '\\') s[i] = '/';
    while (k < m && s[k]) k++;                          /* stop at an embedded NUL */
    int b = gz_utf16_to_utf8(s, k, u);
    gz_free(w);
    if (b <= 0) { gz_free(u); return GZ_E_DATA; }
    *out = u;
    *outn = (u32)b;
    return GZ_OK;
}

/* ---------------- metadata ---------------- */

typedef struct { u64 off; i32 dir; u32 depth; } pend;

typedef struct {
    gz_archive *a;
    wim_priv *p;
    gz_ctx *c;
    const u8 *m;
    u64 n;
    u8 *seen;                       /* dentry / stream entry starts (8-byte units) */
    pend *st; u32 nst, capst;
    u8 *path; u32 pcap;
} meta_ctx;

static int seen_test_set(meta_ctx *x, u64 off)
{
    u64 q = off >> 3;
    u8 bit = (u8)(1u << (q & 7));
    if (x->seen[q >> 3] & bit) return 1;
    x->seen[q >> 3] |= bit;
    return 0;
}

static int push(meta_ctx *x, u64 off, i32 dir, u32 depth)
{
    if (x->nst == x->capst) {
        u32 nc = x->capst ? x->capst * 2 : 64;
        pend *n = (pend *)gz_realloc(x->st, (size_t)nc * sizeof(pend));
        if (!n) return GZ_E_NOMEM;
        x->st = n;
        x->capst = nc;
    }
    x->st[x->nst].off = off;
    x->st[x->nst].dir = dir;
    x->st[x->nst].depth = depth;
    x->nst++;
    return GZ_OK;
}

static int add_ent(meta_ctx *x, u32 plen, gz_entry **pe)
{
    if (x->a->n >= MAX_ENTRIES) return GZ_E_LIMIT;
    return gz_arc_add_named(x->a, x->path, plen, GZ_NE_UTF16LE, pe);
}

/* data / size / method of an entry from a stream hash */
static void set_blob(meta_ctx *x, gz_entry *e, const u8 *hash)
{
    if (!hash || is_zero_hash(hash)) return;
    i32 bi = hash_find(x->p, hash);
    if (bi < 0) {
        e->flags |= EF_MISSING;
        return;
    }
    const wim_blob *b = &x->p->blob[bi];
    const wim_res *R = &x->p->res[b->res];
    e->aux32 = (u32)bi + 1;
    e->off = (u64)R->part << 48 | ((R->off + b->off) & 0xFFFFFFFFFFFFull);   /* extraction order */
    e->usize = b->size;
    e->csize = R->kind == RK_CHUNKED ? R->csize : R->kind == RK_RAW ? b->size : GZ_SIZE_UNKNOWN;
    e->method = (u16)((R->kind == RK_RAW ? CT_NONE : R->ctype) | (log2u(R->chunk) << 8) |
                      (R->kind == RK_SOLID ? M_SOLID : 0));
}

static u32 path_join(meta_ctx *x, u32 plen, const u8 *name, u32 nb, u32 sep)
{
    if (plen + nb + 2 > x->pcap) return 0;
    if (plen) { x->path[plen] = (u8)sep; x->path[plen + 1] = 0; plen += 2; }
    __builtin_memcpy(x->path + plen, name, nb);
    return plen + nb;
}

/* unix mode from wimlib's tagged metadata items (after the names, 8-byte aligned) */
static u32 unix_mode(const u8 *m, u64 p, u64 end)
{
    p = (p + 7) & ~(u64)7;
    while (p + 8 <= end) {
        u32 tag = rd32(m + p), len = rd32(m + p + 4);
        if (len > end - p - 8) break;
        if (tag == TAG_UNIX && len >= 16) return rd32(m + p + 16);
        p += 8 + (((u64)len + 7) & ~(u64)7);
    }
    return 0;
}

/* One directory's child list; subdirectories are queued. */
static int read_dir(meta_ctx *x, const pend *pd)
{
    gz_archive *a = x->a;
    const u8 *m = x->m;
    u32 plen0 = 0;
    if (pd->dir >= 0) {
        const gz_entry *de = &a->e[pd->dir];
        if (de->raw_len > x->pcap) return GZ_OK;
        __builtin_memcpy(x->path, a->raw + de->raw_off, de->raw_len);
        plen0 = de->raw_len;
    }
    u64 off = pd->off;
    for (;;) {
        if ((off & 7) || off > x->n || x->n - off < 8) break;
        u64 len = rd64(m + off);
        if (len > x->n) break;
        len = (len + 7) & ~(u64)7;
        if (len <= 8) break;                                  /* end of directory */
        if (seen_test_set(x, off)) break;                     /* loop or overlap */
        if (len < DENTRY_FIXED || len > x->n - off) break;
        const u8 *d = m + off;
        u32 attr = rd32(d + 8), nstr = rd16(d + 0x60), snb = rd16(d + 0x62), nb = rd16(d + 0x64);
        u64 sub = rd64(d + 16);
        if ((nb | snb) & 1) break;
        u64 need = DENTRY_FIXED + (nb ? nb + 2u : 0) + (snb ? snb + 2u : 0);
        if (need > len) break;
        /* streams follow the dentry */
        u64 soff = off + len;
        const u8 *data_hash = 0, *rp_hash = 0, *zero_unnamed = 0;
        int bad = 0;
        for (u32 k = 0; k < nstr; k++) {
            if (soff > x->n || x->n - soff < STREAM_FIXED || (soff & 7) || seen_test_set(x, soff)) { bad = 1; break; }
            u64 sl = rd64(m + soff);
            if (sl > x->n) { bad = 1; break; }
            sl = (sl + 7) & ~(u64)7;
            u32 snl = rd16(m + soff + 36);
            if (sl < STREAM_FIXED || sl > x->n - soff || (snl & 1) || STREAM_FIXED + (u64)snl > sl) { bad = 1; break; }
            soff += sl;
        }
        if (bad) break;
        u64 next = soff;

        int encrypted = (attr & FA_ENCRYPTED) != 0, reparse = (attr & FA_REPARSE) != 0;
        u32 tag = reparse ? rd32(d + 0x58) : 0;
        /* stream roles (WIM has no stream types): see wimlib's assign_stream_types */
        if (!nstr) {
            if (reparse && !encrypted) rp_hash = d + 0x40;
            else data_hash = d + 0x40;
        } else {
            if (encrypted && !is_zero_hash(d + 0x40)) data_hash = d + 0x40;
            u64 so = off + len;
            for (u32 k = 0; k < nstr; k++) {
                const u8 *se = m + so;
                if (!rd16(se + 36)) {
                    const u8 *h = se + 16;
                    if (encrypted) { if (!data_hash && !is_zero_hash(h)) data_hash = h; }
                    else if (reparse && !rp_hash) rp_hash = h;
                    else if (is_zero_hash(h)) { if (!zero_unnamed) zero_unnamed = h; }
                    else if (!data_hash) data_hash = h;
                }
                so += (rd64(se) + 7) & ~(u64)7;
            }
            if (!data_hash) data_hash = zero_unnamed;
        }

        const u8 *name = d + DENTRY_FIXED;
        int dot = (nb == 2 && rd16(name) == '.') || (nb == 4 && rd16(name) == '.' && rd16(name + 2) == '.');
        u32 plen = (nb && !dot) ? path_join(x, plen0, name, nb, '/') : 0;
        if (plen) {
            int is_link = reparse && (tag == TAG_SYMLINK || tag == TAG_MOUNT) && rp_hash && !is_zero_hash(rp_hash);
            gz_entry *e;
            int r = add_ent(x, plen, &e);
            if (r) return r;
            i32 ei = (i32)(a->n - 1);
            e->attr = attr;
            e->mtime = rd64(d + 0x38);
            e->mtime_kind = GZ_MT_FILETIME;
            e->unix_mode = unix_mode(m, off + need, off + len);
            if (is_link) {
                e->is_link = 1;
                e->flags |= EF_LINK;
                e->aux = tag;
                e->unix_mode = 0120777;
                set_blob(x, e, rp_hash);
                e->usize = 0;
            } else if (attr & FA_DIRECTORY) {
                e->is_dir = 1;
                if (sub && pd->depth < 4096 && (r = push(x, sub, ei, pd->depth + 1))) return r;
            } else {
                set_blob(x, e, data_hash);
                if (!e->aux32 && !(e->flags & EF_MISSING)) e->usize = 0;
            }
            /* named streams: "path:name" */
            u64 so = off + len;
            for (u32 k = 0; k < nstr; k++) {
                const u8 *se = m + so;
                u32 snl = rd16(se + 36);
                so += (rd64(se) + 7) & ~(u64)7;
                if (!snl) continue;
                u32 pl2 = path_join(x, plen, se + STREAM_FIXED, snl, ':');
                if (!pl2) continue;
                gz_entry *ae;
                if ((r = add_ent(x, pl2, &ae))) return r;
                ae->is_aux = 1;
                ae->attr = attr & ~(FA_DIRECTORY | FA_REPARSE);
                ae->mtime = rd64(d + 0x38);
                ae->mtime_kind = GZ_MT_FILETIME;
                set_blob(x, ae, se + 16);
            }
        }
        off = next;
    }
    return GZ_OK;
}

/* Parse one image's metadata into entries below the folder entry `img` (-1 = root). */
static int read_image(gz_archive *a, wim_priv *p, gz_ctx *c, const u8 *m, u64 n, i32 img)
{
    if (n < 8) return GZ_E_FORMAT;
    u64 sec = rd32(m);
    if (sec < 8) sec = 8;
    u64 root = (sec + 7) & ~(u64)7;
    if (root > n || n - root < DENTRY_FIXED) return GZ_E_FORMAT;
    u64 rl = (rd64(m + root) + 7) & ~(u64)7;
    if (rl < DENTRY_FIXED || rl > n - root) return GZ_E_FORMAT;
    meta_ctx x;
    __builtin_memset(&x, 0, sizeof x);
    x.a = a;
    x.p = p;
    x.c = c;
    x.m = m;
    x.n = n;
    x.pcap = MAX_PATH_BYTES + 8;
    x.seen = (u8 *)gz_alloc((size_t)(n >> 6) + 2);
    x.path = (u8 *)gz_alloc(x.pcap + 8);
    int r = (!x.seen || !x.path) ? GZ_E_NOMEM : GZ_OK;
    if (!r) {
        seen_test_set(&x, root);
        if (img >= 0) {
            a->e[img].mtime = rd64(m + root + 0x38);
            a->e[img].mtime_kind = GZ_MT_FILETIME;
        }
        u64 sub = rd64(m + root + 16);
        if (sub) r = push(&x, sub, img, 1);
    }
    u32 steps = 0;
    while (!r && x.nst) {
        pend pd = x.st[--x.nst];
        if (!(++steps & 1023) && gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        r = read_dir(&x, &pd);
    }
    gz_free(x.seen);
    gz_free(x.path);
    gz_free(x.st);
    return r;
}

/* ---------------- open ---------------- */

static int wim_probe(gz_src *s, const u8 *head, u32 n)
{
    (void)s;
    if (n >= HDR_SIZE && !__builtin_memcmp(head, "MSWIM\0\0\0", 8) && rd32(head + 8) >= HDR_SIZE) return 95;
    return 0;
}

/* "name.swm" / "name<k>.swm" of part k, built from the opened part's file name */
static gzch *part_name(const gzch *fn, u32 own, u32 k)
{
    size_t n = gz_wcslen(fn), dot = n, sl = 0;
    for (size_t i = 0; i < n; i++) {
        if (fn[i] == '/' || fn[i] == '\\') { sl = i + 1; dot = n; }
        else if (fn[i] == '.') dot = i;
    }
    size_t stem = dot;
    if (own > 1) {
        /* drop the opened part's own number */
        char num[12];
        u32 nd = 0;
        for (u32 v = own; v; v /= 10) num[nd++] = (char)('0' + v % 10);
        size_t i = 0;
        while (i < nd && stem > sl && fn[stem - 1] == (gzch)num[i]) { stem--; i++; }
        if (i < nd) stem = dot;
    }
    gzch *w = (gzch *)gz_alloc((n + 16) * sizeof(gzch));
    if (!w) return 0;
    __builtin_memcpy(w, fn, stem * sizeof(gzch));
    size_t o = stem;
    if (k > 1) {
        char num[12];
        u32 nd = 0;
        for (u32 v = k; v; v /= 10) num[nd++] = (char)('0' + v % 10);
        while (nd) w[o++] = (gzch)num[--nd];
    }
    for (size_t i = dot; i < n; i++) w[o++] = fn[i];
    w[o] = 0;
    return w;
}

/* UTF-16LE text contains the ASCII tag (case-sensitive) */
static int xml_has(const u8 *x, size_t n, const char *tag)
{
    size_t tl = 0;
    while (tag[tl]) tl++;
    for (size_t i = 0; i + tl * 2 <= n; i += 2) {
        size_t k = 0;
        while (k < tl && x[i + 2 * k] == (u8)tag[k] && !x[i + 2 * k + 1]) k++;
        if (k == tl) return 1;
    }
    return 0;
}

static void wim_close(gz_archive *a)
{
    wim_priv *p = (wim_priv *)a->priv;
    if (!p) return;
    gz_free(p->res);
    gz_free(p->blob);
    gz_free(p->byhash);
    gz_free(p->pvol);
    gz_free(p);
    a->priv = 0;
}

/* blob for a resource named directly by a header (blob table, XML) */
static int header_blob(wim_priv *p, const u8 *rh24, const wim_hdr *h, u32 *bi)
{
    reshdr rh;
    get_reshdr(rh24, &rh);
    u32 ri;
    int r = make_res(p, &rh, h->part, hdr_ctype(h), h->chunk ? h->chunk : 32768, &ri);
    if (r) return r;
    return add_blob(p, ri, 0, rh.usize, 0, bi);
}

static int wim_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    u8 h8[HDR_SIZE];
    int r = gz_src_read_exact(s, 0, h8, HDR_SIZE);
    if (r) return r == GZ_E_TRUNC ? GZ_E_FORMAT : r;
    wim_hdr own;
    if ((r = parse_hdr(h8, &own))) return r;
    if (own.total > MAX_PARTS) return GZ_E_LIMIT;
    wim_priv *p = (wim_priv *)gz_alloc(sizeof(wim_priv));
    if (!p) return GZ_E_NOMEM;
    a->priv = p;
    p->nparts = own.total;
    p->own_part = own.part;
    p->pvol = (i32 *)gz_alloc(((size_t)own.total + 1) * sizeof(i32));
    wim_hdr *hd = (wim_hdr *)gz_alloc(((size_t)own.total + 1) * sizeof(wim_hdr));
    u32 *meta = 0, nmeta = 0;
    gz_mem_sink ms;
    __builtin_memset(&ms, 0, sizeof ms);
    wim_rd rd;
    rd_init(&rd, a, s, c);
    if (!p->pvol || !hd) { r = GZ_E_NOMEM; goto out; }
    for (u32 k = 0; k <= own.total; k++) p->pvol[k] = -2;
    p->pvol[own.part] = -1;
    hd[own.part] = own;

    /* other parts of a split WIM */
    if (own.total > 1) {
        a->vols = (gz_src **)gz_alloc((size_t)own.total * sizeof(gz_src *));
        if (!a->vols) { r = GZ_E_NOMEM; goto out; }
        for (u32 k = 1; k <= own.total; k++) {
            if (k == own.part) continue;
            gz_src *v = 0;
            gzch *w = (o->file_name && o->open_volume) ? part_name(o->file_name, own.part, k) : 0;
            int vr = w ? o->open_volume(o->user, w, &v) : GZ_E_VOLUME;
            gz_free(w);
            if (vr == GZ_E_CANCEL) { r = vr; goto out; }
            wim_hdr ph;
            if (!vr && v && !gz_src_read_exact(v, 0, h8, HDR_SIZE) && !parse_hdr(h8, &ph) && ph.part == k &&
                ph.total == own.total && !__builtin_memcmp(ph.guid, own.guid, 16)) {
                hd[k] = ph;
                p->pvol[k] = (i32)a->nvols;
                a->vols[a->nvols++] = v;
            } else {
                if (v) gz_src_free(v);
                p->missing = 1;
            }
        }
    }
    if (p->pvol[1] == -2) { r = GZ_E_VOLUME; goto out; }          /* images live in part 1 */
    const wim_hdr *h1 = &hd[1];
    u32 nimg = h1->images;
    if (nimg > MAX_IMAGES) { r = GZ_E_LIMIT; goto out; }
    meta = (u32 *)gz_alloc(((size_t)nimg + 1) * sizeof(u32));
    if (!meta) { r = GZ_E_NOMEM; goto out; }

    /* XML first: encrypted ESD files cannot be read */
    u32 xml_blob = ~0u;
    {
        reshdr xr;
        get_reshdr(h1->xml, &xr);
        if (xr.usize) {
            u32 bi;
            if ((r = header_blob(p, h1->xml, h1, &bi))) goto out;
            if (!read_all(&rd, bi, MAX_XML, &ms)) {
                if (xml_has(ms.p, ms.n, "<ENCRYPTED")) { r = GZ_E_METHOD; goto out; }
                xml_blob = bi;
            }
            gz_mem_sink_free(&ms);
        }
    }

    /* blob tables of all parts */
    for (u32 k = 1; k <= own.total; k++) {
        if (p->pvol[k] == -2) continue;
        gz_src *ps = part_src(a, s, k);
        reshdr tr;
        get_reshdr(hd[k].table, &tr);
        if (!tr.usize) continue;
        if (tr.usize > MAX_TABLE) { r = GZ_E_LIMIT; goto out; }
        u32 bi;
        if ((r = header_blob(p, hd[k].table, &hd[k], &bi))) goto out;
        if (p->res[p->blob[bi].res].kind == RK_RAW && tr.usize > ps->size) { r = GZ_E_FORMAT; goto out; }
        r = read_all(&rd, bi, MAX_TABLE, &ms);
        if (r) { if (r != GZ_E_NOMEM && r != GZ_E_CANCEL) r = GZ_E_FORMAT; goto out; }
        r = parse_table(p, ps, &hd[k], ms.p, (u32)(ms.n / 50), meta, &nmeta, k == 1 ? nimg : 0);
        gz_mem_sink_free(&ms);
        if (r) goto out;
    }
    if ((r = hash_index(p))) goto out;
    for (u32 i = 0; i < p->nblob; i++) if (p->res[p->blob[i].res].kind == RK_SOLID) a->solid = 1;

    /* images */
    u64 total_meta = 0;
    u32 nshow = nimg < nmeta ? nimg : nmeta;
    for (u32 i = 0; i < nshow; i++) {
        i32 img = -1;
        if (nshow > 1) {
            char num[12];
            u8 nm[24];
            u32 nd = 0, l = 0;
            for (u32 v = i + 1; v; v /= 10) num[nd++] = (char)('0' + v % 10);
            while (nd) { nm[l++] = (u8)num[--nd]; nm[l++] = 0; }
            gz_entry *e;
            if ((r = gz_arc_add_named(a, nm, l, GZ_NE_UTF16LE, &e))) goto out;
            e->is_dir = 1;
            e->attr = FA_DIRECTORY;
            img = (i32)(a->n - 1);
        }
        const wim_blob *mb = &p->blob[meta[i]];
        if (mb->size > MAX_META) { r = GZ_E_LIMIT; goto out; }
        total_meta += mb->size;
        if (total_meta > TOTAL_META) { r = GZ_E_LIMIT; goto out; }
        r = read_all(&rd, meta[i], MAX_META, &ms);
        if (!r && !hash_ok(mb, ms.p, ms.n)) r = GZ_E_CRC;
        if (!r) r = read_image(a, p, c, ms.p, ms.n, img);
        gz_mem_sink_free(&ms);
        if (r) goto out;
        if (c && c->progress) c->progress(c->progress_user, i + 1, nshow);
    }
    if (nshow > 1 && xml_blob != ~0u) {
        static const u8 xn[] = { '[', 0, '1', 0, ']', 0, '.', 0, 'x', 0, 'm', 0, 'l', 0 };
        gz_entry *e;
        if ((r = gz_arc_add_named(a, xn, sizeof xn, GZ_NE_UTF16LE, &e))) goto out;
        e->is_aux = 1;
        e->flags = EF_XML;
        e->aux32 = xml_blob + 1;
        e->usize = e->csize = p->blob[xml_blob].size;
    }

    /* link targets that are cheap to read now (not inside solid resources) */
    for (u32 i = 0; i < a->n; i++) {
        gz_entry *e = &a->e[i];
        if (!(e->flags & EF_LINK) || !e->aux32) continue;
        const wim_blob *b = &p->blob[e->aux32 - 1];
        if (p->res[b->res].kind == RK_SOLID || b->size > MAX_REPARSE) continue;
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; goto out; }
        u8 *t;
        u32 tn, off;
        if (!read_all(&rd, e->aux32 - 1, MAX_REPARSE, &ms) && hash_ok(b, ms.p, ms.n) &&
            !reparse_target(ms.p, ms.n, (u32)e->aux, &t, &tn)) {
            r = gz_arc_raw_append(a, t, tn, &off);
            gz_free(t);
            if (r) goto out;
            e->link_off = off;
            e->link_len = tn;
        }
        gz_mem_sink_free(&ms);
    }
    gz_arc_set_type(a, "WIM");
out:
    gz_mem_sink_free(&ms);
    rd_free(&rd);
    gz_free(meta);
    gz_free(hd);
    return r;
}

/* ---------------- extraction ---------------- */

typedef struct { gz_out *out; u32 idx; gz_sha1 sha; } x_sink;

static int x_write(void *u, const u8 *p, size_t n)
{
    x_sink *k = (x_sink *)u;
    gz_sha1_update(&k->sha, p, n);
    return k->out->write(k->out, p, n);
}

static int extract_one(wim_rd *rd, u32 idx, gz_out *out)
{
    gz_archive *a = rd->a;
    wim_priv *p = (wim_priv *)a->priv;
    gz_entry *e = &a->e[idx];
    int st = out->open(out, idx);
    if (st) return st;
    if (e->is_dir || (e->is_link && e->link_len)) {
        st = GZ_OK;
    } else if (e->flags & EF_MISSING) {
        st = p->missing ? GZ_E_VOLUME : GZ_E_FORMAT;
    } else if (e->aux32) {
        u32 bi = e->aux32 - 1;
        const wim_blob *b = &p->blob[bi];
        if (e->flags & EF_LINK) {
            gz_mem_sink ms;
            st = read_all(rd, bi, MAX_REPARSE, &ms);
            if (!st && !hash_ok(b, ms.p, ms.n)) st = GZ_E_CRC;
            u8 *t = 0;
            u32 tn = 0;
            if (!st) st = reparse_target(ms.p, ms.n, (u32)e->aux, &t, &tn);
            if (!st) st = out->write(out, t, tn);
            gz_free(t);
            gz_mem_sink_free(&ms);
        } else {
            x_sink k;
            k.out = out;
            k.idx = idx;
            gz_sha1_init(&k.sha);
            st = rd_blob(rd, bi, x_write, &k);
            if (!st && b->has_hash) {
                u8 d[20];
                gz_sha1_final(&k.sha, d);
                if (__builtin_memcmp(d, b->hash, 20)) st = GZ_E_CRC;
            }
        }
    }
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static int wim_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    wim_rd rd;
    rd_init(&rd, a, s, c);
    int r = extract_one(&rd, idx, out);
    rd_free(&rd);
    return r;
}

/* (resource, offset) of an entry's data; entries without data sort first */
static void sort_key(const gz_archive *a, u32 idx, u32 *res, u64 *off)
{
    const wim_priv *p = (const wim_priv *)a->priv;
    const gz_entry *e = &a->e[idx];
    *res = 0;
    *off = 0;
    if (e->aux32 && !e->is_dir && !(e->is_link && e->link_len)) {
        const wim_blob *b = &p->blob[e->aux32 - 1];
        *res = b->res + 1;
        *off = b->off;
    }
}

static int wim_extract_solid(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_ctx *c)
{
    u32 n = 0;
    for (u32 i = 0; i < a->n; i++) n += sel[i] != 0;
    u32 *ord = (u32 *)gz_alloc((size_t)n * 2 * sizeof(u32) + 8);
    u32 *kr = (u32 *)gz_alloc((size_t)a->n * sizeof(u32) + 4);
    u64 *ko = (u64 *)gz_alloc((size_t)a->n * sizeof(u64) + 8);
    if (!ord || !kr || !ko) { gz_free(ord); gz_free(kr); gz_free(ko); return GZ_E_NOMEM; }
    u32 k = 0;
    for (u32 i = 0; i < a->n; i++) {
        if (!sel[i]) continue;
        ord[k++] = i;
        sort_key(a, i, &kr[i], &ko[i]);
    }
    /* bottom-up merge sort by (resource, offset), stable */
    u32 *src = ord, *dst = ord + n;
    for (u32 w = 1; w < n; w *= 2) {
        for (u32 lo = 0; lo < n; lo += 2 * w) {
            u32 mid = lo + w < n ? lo + w : n, hi = lo + 2 * w < n ? lo + 2 * w : n;
            u32 i = lo, j = mid, o = lo;
            while (i < mid && j < hi) {
                u32 x = src[i], y = src[j];
                int le = kr[x] < kr[y] || (kr[x] == kr[y] && ko[x] <= ko[y]);
                dst[o++] = le ? src[i++] : src[j++];
            }
            while (i < mid) dst[o++] = src[i++];
            while (j < hi) dst[o++] = src[j++];
        }
        u32 *t = src; src = dst; dst = t;
    }
    wim_rd rd;
    rd_init(&rd, a, s, c);
    int r = GZ_OK;
    for (u32 i = 0; i < n; i++) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        int st = extract_one(&rd, src[i], out);
        if (st == GZ_E_CANCEL) { r = st; break; }
    }
    rd_free(&rd);
    gz_free(ord);
    gz_free(kr);
    gz_free(ko);
    return r;
}

static gz_src *wim_view(gz_archive *a, gz_src *s, u32 idx)
{
    wim_priv *p = (wim_priv *)a->priv;
    const gz_entry *e = &a->e[idx];
    if (e->is_dir || e->is_link || !e->aux32) return 0;
    const wim_blob *b = &p->blob[e->aux32 - 1];
    const wim_res *R = &p->res[b->res];
    if (R->kind != RK_RAW || !b->size) return 0;
    gz_src *src = part_src(a, s, R->part);
    if (!src || R->off > src->size || b->size > src->size - R->off) return 0;
    return gz_src_sub(src, R->off, b->size);
}

static void wim_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    static const char *const names[4] = { "Copy", "XPRESS", "LZX", "LZMS" };
    char t[40];
    u32 i = 0, ct = e->method & 15, bits = (e->method >> 8) & 31;
    const char *nm = (e->aux32 && ct < 4) ? names[ct] : "";
    while (*nm && i < 20) t[i++] = *nm++;
    if (e->aux32 && ct && ct < 4) {
        t[i++] = ':';
        if (bits >= 10) t[i++] = (char)('0' + bits / 10);
        t[i++] = (char)('0' + bits % 10);
    }
    if (e->method & M_SOLID) {
        const char *sl = " Solid";
        while (*sl) t[i++] = *sl++;
    }
    t[i] = 0;
    u32 k = 0;
    for (; t[k] && k + 1 < cap; k++) buf[k] = t[k];
    if (cap) buf[k] = 0;
}

GZ_FORMAT(gz_fmt_wim)
const gz_format gz_fmt_wim = {
    "WIM", "wim swm esd",
    0, wim_probe, wim_open, wim_close, wim_extract, wim_extract_solid, 0, wim_method, wim_view, 0
};
