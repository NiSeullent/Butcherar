/*
 * 고깃ZIP - 7z reader
 *
 * Archive layout: 32-byte signature header ("7z\xBC\xAF\x27\x1C", version 0.x,
 * start header CRC, next header offset/size/CRC), packed streams, then the next
 * header: either a plain kHeader or a kEncodedHeader (StreamsInfo of one folder
 * whose output is the real header, usually LZMA, with 7zAES when -mhe is used).
 * The header holds archive properties (skipped), additional streams (decoded to
 * memory, referenced by "External" properties), the main StreamsInfo (pack info,
 * folders = coder graphs, unpack sizes, CRCs, substreams = files) and FilesInfo
 * (UTF-16LE names, empty stream / empty file / anti bits, times, attributes with
 * the p7zip unix mode in the high 16 bits when 0x8000 is set).
 *
 * Folders are generic coder graphs (every coder has one output, BCJ2 four inputs).
 * The folder output is produced by push_coder() on the main coder:
 *   - decoders (LZMA, LZMA2, PPMd, BZip2, Deflate(64), Zstd, LZ4) pull their input
 *     through a reader and push output to a sink;
 *   - filters (BCJ x86/PPC/IA64/ARM/ARMT/SPARC/ARM64/RISCV, Delta, Swap2/4) are push
 *     transforms in front of the sink;
 *   - Copy and 7zAES are pull transforms (readers over their input);
 *   - BCJ2 takes MAIN pushed and CALL/JUMP/RC pulled.
 * A reader for a coder output that is neither a pull transform nor a packed
 * stream (e.g. BCJ2's LZMA-coded CALL/JUMP streams) is "materialised": the coder
 * is run first into a buffer of its declared size (capped, SZ_MAT_MAX). Graphs are
 * validated at open (bonds unique, every in-stream bound or packed, every coder
 * reachable from the main coder, so there are no cycles) and decoding recursion is
 * bounded by the coder count (<= 64).
 *
 * Extraction: extract() decodes the entry's folder up to the end of the entry;
 * extract_solid() decodes, in order, each folder holding selected files and stops
 * after the last selected one; a->solid is set when some folder holds more than one
 * file, otherwise the engine can extract entries in parallel. Every file is
 * CRC-checked; data errors in an encrypted folder are reported as GZ_E_PASSWORD.
 *
 * Passwords: 7z has no password check value. check_password() decodes the start
 * of the entry's folder with the password: the first file of the folder when it is
 * at most 1 MiB and has a CRC (definitive), else the first 256 KiB of the folder
 * (decoder errors reveal a wrong key: LZMA requires a zero first byte and valid
 * distances, LZMA2 valid control bytes, BZip2 a "BZh" header, Deflate valid block
 * headers). Copy+AES with a large first file cannot be checked early; extraction
 * then fails with GZ_E_PASSWORD at the CRC. Derived AES keys are cached per thread
 * (gz_ctx slot), and a key once proven by a CRC answers later checks directly, so
 * non-solid archives are not decoded twice.
 * Encrypted headers: the password comes from o->password or o->ask_password; a
 * wrong one is detected by the decoded header's CRC / decoder errors and asked
 * again (retry = 1).
 *
 * SFX: the signature is searched after a PE/ELF stub (PE overlay start, then the
 * first 4 MiB); a candidate counts only with a valid start header CRC.
 */
#include "arc.h"
#include "crc32.h"
#include "lzma.h"
#include "bcj.h"
#include "bcj2.h"
#include "bzip2.h"
#include "zstd.h"
#include "lz4.h"

/* ---------------- constants and limits ---------------- */

enum {
    P_END, P_HEADER, P_ARCHIVE_PROPS, P_ADD_STREAMS, P_MAIN_STREAMS, P_FILES, P_PACK_INFO,
    P_UNPACK_INFO, P_SUBSTREAMS, P_SIZE, P_CRC, P_FOLDER, P_CODERS_UNPACK_SIZE,
    P_NUM_UNPACK_STREAM, P_EMPTY_STREAM, P_EMPTY_FILE, P_ANTI, P_NAME, P_CTIME, P_ATIME,
    P_MTIME, P_WIN_ATTRIB, P_COMMENT, P_ENCODED_HEADER, P_START_POS, P_DUMMY
};

enum {
    K_UNKNOWN, K_COPY, K_LZMA, K_LZMA2, K_PPMD, K_BZIP2, K_DEFLATE, K_DEFLATE64, K_FILTER,
    K_BCJ2, K_AES, K_SWAP2, K_SWAP4, K_ZSTD, K_LZ4
};

#define SZ_MAXS      64u                   /* coders / in-streams per folder (7-Zip's limit) */
#define SZ_NONE      0xFFFFFFFFu
#define SZ_BIG       ((u64)1 << 62)        /* sizes and offsets above this are corrupt */
#define SZ_COUNT_MAX (1u << 26)            /* files, folders, pack streams, substreams */
#define SZ_SFX_SCAN  (4u << 20)            /* SFX stub search range */
#define SZ_PW_CAP    512u
#if UINTPTR_MAX > 0xffffffffu
#  define SZ_HDR_MAX ((u64)1 << 30)        /* raw/decoded header and additional streams */
#  define SZ_MAT_MAX ((u64)1 << 30)        /* intermediate streams held in memory per folder */
#else
#  define SZ_HDR_MAX ((u64)256 << 20)
#  define SZ_MAT_MAX ((u64)384 << 20)
#endif

enum { SZF_AES = 1, SZF_UNSUP = 2 };

static const u8 sz_sig[6] = { '7', 'z', 0xBC, 0xAF, 0x27, 0x1C };

/* ---------------- archive model ---------------- */

typedef struct {
    u64 id;
    u32 prop, nprop;      /* properties in st->props */
    u8 kind, bcj;         /* K_*, GZ_BCJ_* for K_FILTER */
    u8 nin, in0;          /* in-streams (packed side) and the first one's folder index */
} sz_coder;

typedef struct {
    u32 coder0;           /* first coder in st->co (and its unpack size in st->usz) */
    u32 pack0;            /* first packed stream in st->ppos/psz */
    u32 map0;             /* in-stream map in st->map: 0x80|k = packed stream k, else coder */
    u32 first_entry;      /* a->e index of the first file, SZ_NONE if none */
    u32 nsub;             /* files (substreams) */
    u32 crc;
    u8 ncoders, nin, npack, main;
    u8 has_crc, flags;
} sz_folder;

typedef struct {
    sz_folder *fo; u32 nfo;
    sz_coder *co; u32 nco, cap_co;
    u64 *usz;                         /* unpack size of every coder */
    u8 *map; u32 nmap, cap_map;
    u8 *props; u32 nprops, cap_props;
    u64 *ppos, *psz; u32 npack;       /* absolute offset and size of every packed stream */
    /* substreams, only until FilesInfo is parsed */
    u64 *ssz; u32 *scrc; u8 *shas; u32 nss;
} sz_streams;

typedef struct { u8 *p; size_t n; } sz_buf;
typedef struct { sz_buf *b; u32 n; } sz_dvec;

typedef struct {
    sz_streams st;
    u64 base;                         /* offset of the signature header (SFX stub size) */
} sz_priv;

static void streams_free(sz_streams *st)
{
    gz_free(st->fo); gz_free(st->co); gz_free(st->usz); gz_free(st->map); gz_free(st->props);
    gz_free(st->ppos); gz_free(st->psz); gz_free(st->ssz); gz_free(st->scrc); gz_free(st->shas);
    __builtin_memset(st, 0, sizeof *st);
}

static void dvec_free(sz_dvec *dv)
{
    for (u32 i = 0; i < dv->n; i++) if (dv->b[i].p) gz_free_big(dv->b[i].p, dv->b[i].n ? dv->b[i].n : 1);
    gz_free(dv->b);
    dv->b = 0;
    dv->n = 0;
}

static int grow(void **p, u32 *cap, u64 need, size_t elem)
{
    if (need <= *cap) return GZ_OK;
    if (need > SZ_COUNT_MAX * (u64)SZ_MAXS) return GZ_E_LIMIT;
    u64 nc = *cap ? *cap : 64;
    while (nc < need) nc *= 2;
    if (nc * elem > ((size_t)-1) / 2) return GZ_E_LIMIT;
    void *q = gz_realloc(*p, (size_t)(nc * elem));
    if (!q) return GZ_E_NOMEM;
    *p = q;
    *cap = (u32)nc;
    return GZ_OK;
}

static int method_kind(u64 id, u8 *bcj)
{
    switch (id) {
    case 0x00:       return K_COPY;
    case 0x21:       return K_LZMA2;
    case 0x030101:   return K_LZMA;
    case 0x030401:   return K_PPMD;
    case 0x040202:   return K_BZIP2;
    case 0x040108:   return K_DEFLATE;
    case 0x040109:   return K_DEFLATE64;
    case 0x0303011B: return K_BCJ2;
    case 0x06F10701: return K_AES;
    case 0x020302:   return K_SWAP2;
    case 0x020304:   return K_SWAP4;
    case 0x04F71101: return K_ZSTD;
    case 0x04F71104: return K_LZ4;
    }
    int t = gz_bcj_from_7z_id(id);
    if (!t && id >= 0x04 && id <= 0x09) t = gz_bcj_from_xz_id(id);   /* reserved short ids = xz ids */
    if (t) { *bcj = (u8)t; return K_FILTER; }
    return K_UNKNOWN;
}

/* PPMd var.H (7z method 03 04 01, props: order byte + LE32 memory size) comes from
 * src/codec/ppmd7.h, developed separately: it is used when that header is present
 * (shared GZ_SLOT_PPMD cache, see ppmd.h); without it PPMd folders give GZ_E_METHOD. */
#if defined(__has_include)
#  if __has_include("ppmd7.h")
#    define SZ_HAVE_PPMD 1
#    include "ppmd7.h"
#  endif
#endif
#ifndef SZ_HAVE_PPMD
#  define SZ_HAVE_PPMD 0
#endif

/* ---------------- header byte reader (sticky error) ---------------- */

typedef struct { const u8 *p, *end; int err; } br;

static void br_fail(br *r, int e) { if (!r->err) r->err = e; r->p = r->end; }
static u64 br_left(const br *r) { return (u64)(r->end - r->p); }

static u8 br_u8(br *r)
{
    if (r->p >= r->end) { br_fail(r, GZ_E_FORMAT); return 0; }
    return *r->p++;
}

static u32 br_u32(br *r)
{
    if (br_left(r) < 4) { br_fail(r, GZ_E_FORMAT); return 0; }
    u32 v = rd32(r->p);
    r->p += 4;
    return v;
}

/* 7z number: the count of leading 1 bits of the first byte gives the number of
 * extra little-endian bytes; the rest of the first byte holds the high bits */
static GZ_NOINLINE u64 br_num(br *r)
{
    if (r->p >= r->end) { br_fail(r, GZ_E_FORMAT); return 0; }
    u32 first = *r->p++, mask = 0x80;
    u64 v = 0;
    for (u32 i = 0; i < 8; i++, mask >>= 1) {
        if (!(first & mask)) return v | ((u64)(first & (mask - 1)) << (8 * i));
        if (r->p >= r->end) { br_fail(r, GZ_E_FORMAT); return 0; }
        v |= (u64)*r->p++ << (8 * i);
    }
    return v;
}

static GZ_NOINLINE const u8 *br_take(br *r, u64 n)
{
    if (n > br_left(r)) { br_fail(r, GZ_E_FORMAT); return 0; }
    const u8 *q = r->p;
    r->p += n;
    return q;
}

static void br_skip_data(br *r) { u64 n = br_num(r); br_take(r, n); }

/* a count read from the header, at most lim */
static u32 br_count(br *r, u64 lim)
{
    u64 v = br_num(r);
    if (v > lim) { br_fail(r, GZ_E_FORMAT); return 0; }
    return (u32)v;
}

/* skip properties until id (kEnd before it is an error) */
static int br_wait(br *r, u64 id)
{
    for (;;) {
        u64 t = br_num(r);
        if (r->err) return r->err;
        if (t == id) return GZ_OK;
        if (t == P_END) return GZ_E_FORMAT;
        br_skip_data(r);
    }
}

static int bit_at(const u8 *v, u64 i) { return (v[i >> 3] >> (7 - (i & 7))) & 1; }

static u64 count_bits(const u8 *v, u64 n)
{
    u64 c = 0;
    for (u64 i = 0; i < (n >> 3); i++) c += (u64)__builtin_popcount(v[i]);
    if (n & 7) c += (u64)__builtin_popcount((u32)(v[n >> 3] >> (8 - (n & 7))));
    return c;
}

/* "External" byte: data inline, or in additional stream #i */
static int ext_switch(br *r, const sz_dvec *dv)
{
    u8 ext = br_u8(r);
    if (r->err || !ext) return r->err;
    u64 i = br_num(r);
    if (r->err) return r->err;
    if (!dv || i >= dv->n) return GZ_E_FORMAT;
    r->p = dv->b[i].p;
    r->end = r->p + dv->b[i].n;
    return GZ_OK;
}

/* n digests: AllAreDefined byte or bit vector, then a CRC for each defined item */
static int read_digests(br *r, u32 n, u32 *crc, u8 *has)
{
    u8 all = br_u8(r);
    const u8 *v = all ? 0 : br_take(r, ((u64)n + 7) >> 3);
    if (r->err) return r->err;
    for (u32 i = 0; i < n; i++) {
        int d = all || bit_at(v, i);
        u32 x = d ? br_u32(r) : 0;
        if (r->err) return r->err;
        if (crc) { crc[i] = x; has[i] = (u8)d; }
    }
    return GZ_OK;
}

/* ---------------- StreamsInfo ---------------- */

static int parse_pack_info(br *r, sz_streams *st, u64 base)
{
    u64 pos = br_num(r);
    u32 n = br_count(r, GZ_MIN(br_left(r), (u64)SZ_COUNT_MAX));
    int e = br_wait(r, P_SIZE);
    if (e) return e;
    if (pos > SZ_BIG || st->ppos) return GZ_E_FORMAT;
    st->ppos = (u64 *)gz_alloc((size_t)n * 8 + 8);
    st->psz = (u64 *)gz_alloc((size_t)n * 8 + 8);
    if (!st->ppos || !st->psz) return GZ_E_NOMEM;
    st->npack = n;
    u64 off = base + 32 + pos;
    for (u32 i = 0; i < n; i++) {
        u64 sz = br_num(r);
        if (r->err) return r->err;
        if (sz > SZ_BIG || off + sz > SZ_BIG) return GZ_E_FORMAT;
        st->ppos[i] = off;
        st->psz[i] = sz;
        off += sz;
    }
    for (;;) {
        u64 t = br_num(r);
        if (r->err) return r->err;
        if (t == P_END) return GZ_OK;
        if (t == P_CRC) { if ((e = read_digests(r, n, 0, 0))) return e; continue; }
        br_skip_data(r);
    }
}

static int parse_folder(br *r, sz_streams *st, sz_folder *f)
{
    u32 nc = br_count(r, 0xFFFFFFFFu);
    if (r->err) return r->err;
    if (nc == 0 || nc > SZ_MAXS) return GZ_E_METHOD;
    int e = grow((void **)&st->co, &st->cap_co, (u64)st->nco + nc, sizeof(sz_coder));
    if (e) return e;
    f->coder0 = st->nco;
    f->ncoders = (u8)nc;
    u32 nin = 0;
    for (u32 k = 0; k < nc; k++) {
        sz_coder *cd = &st->co[st->nco + k];
        u8 b = br_u8(r);
        if (r->err) return r->err;
        if (b & 0xC0) return GZ_E_METHOD;           /* alternative methods / reserved */
        u32 idn = b & 15;
        if (idn > 8) return GZ_E_METHOD;
        u64 id = 0;
        for (u32 j = 0; j < idn; j++) id = id << 8 | br_u8(r);
        u64 ni = 1;
        if (b & 0x10) {
            ni = br_num(r);
            u64 no = br_num(r);
            if (r->err) return r->err;
            if (no != 1 || ni == 0 || ni > SZ_MAXS) return GZ_E_METHOD;
        }
        if (nin + ni > SZ_MAXS) return GZ_E_METHOD;
        cd->id = id;
        cd->nin = (u8)ni;
        cd->in0 = (u8)nin;
        nin += (u32)ni;
        cd->prop = cd->nprop = 0;
        if (b & 0x20) {
            u64 np = br_num(r);
            const u8 *pp = br_take(r, np);
            if (r->err) return r->err;
            if ((e = grow((void **)&st->props, &st->cap_props, (u64)st->nprops + np + 1, 1))) return e;
            if (np) __builtin_memcpy(st->props + st->nprops, pp, (size_t)np);
            cd->prop = st->nprops;
            cd->nprop = (u32)np;
            st->nprops += (u32)np;
        }
        cd->bcj = 0;
        cd->kind = (u8)method_kind(id, &cd->bcj);
        if (ni != (cd->kind == K_BCJ2 ? 4u : 1u) || cd->kind == K_UNKNOWN ||
            (cd->kind == K_PPMD && !SZ_HAVE_PPMD))
            f->flags |= SZF_UNSUP;
        if (cd->kind == K_AES) f->flags |= SZF_AES;
    }
    st->nco += nc;

    /* bonds: in-stream <- coder output; the remaining in-streams are packed */
    u8 map[SZ_MAXS], bound[SZ_MAXS];
    __builtin_memset(map, 0xFF, sizeof map);
    __builtin_memset(bound, 0, sizeof bound);
    for (u32 k = 0; k + 1 < nc; k++) {
        u64 in = br_num(r), out = br_num(r);
        if (r->err) return r->err;
        if (in >= nin || out >= nc || map[in] != 0xFF || bound[out]) return GZ_E_FORMAT;
        map[in] = (u8)out;
        bound[out] = 1;
    }
    u32 npk = nin - (nc - 1);
    if (npk == 1) {
        for (u32 k = 0; k < nin; k++) if (map[k] == 0xFF) { map[k] = 0x80; break; }
    } else {
        for (u32 k = 0; k < npk; k++) {
            u64 in = br_num(r);
            if (r->err) return r->err;
            if (in >= nin || map[in] != 0xFF) return GZ_E_FORMAT;
            map[in] = (u8)(0x80 | k);
        }
    }
    u32 main = 0;
    while (main < nc && bound[main]) main++;
    /* every coder must be reachable from the main one: no cycles, no orphans */
    u8 stack[SZ_MAXS];
    u32 sp = 0, seen = 0;
    stack[sp++] = (u8)main;
    while (sp) {
        const sz_coder *cd = &st->co[f->coder0 + stack[--sp]];
        seen++;
        for (u32 j = 0; j < cd->nin; j++) {
            u8 v = map[cd->in0 + j];
            if (!(v & 0x80)) {
                if (sp >= SZ_MAXS) return GZ_E_FORMAT;
                stack[sp++] = v;
            }
        }
    }
    if (seen != nc) return GZ_E_FORMAT;
    if ((e = grow((void **)&st->map, &st->cap_map, (u64)st->nmap + nin, 1))) return e;
    __builtin_memcpy(st->map + st->nmap, map, nin);
    f->map0 = st->nmap;
    st->nmap += nin;
    f->nin = (u8)nin;
    f->npack = (u8)npk;
    f->main = (u8)main;
    return GZ_OK;
}

static int parse_unpack_info(br *r, sz_streams *st, const sz_dvec *dv)
{
    int e = br_wait(r, P_FOLDER);
    if (e) return e;
    u32 n = br_count(r, GZ_MIN(br_left(r), (u64)SZ_COUNT_MAX));
    if (r->err) return r->err;
    if (st->fo) return GZ_E_FORMAT;
    st->fo = (sz_folder *)gz_alloc((size_t)n * sizeof(sz_folder) + 8);
    if (!st->fo) return GZ_E_NOMEM;
    st->nfo = n;
    {
        u8 ext = br_u8(r);                /* folders may live in an additional stream */
        br fr = *r;
        if (ext) {
            u64 i = br_num(r);
            if (r->err) return r->err;
            if (!dv || i >= dv->n) return GZ_E_FORMAT;
            fr.p = dv->b[i].p;
            fr.end = fr.p + dv->b[i].n;
        }
        for (u32 i = 0; i < n; i++) {
            st->fo[i].first_entry = SZ_NONE;
            if ((e = parse_folder(&fr, st, &st->fo[i]))) return e;
        }
        if (!ext) *r = fr;
    }
    if ((e = br_wait(r, P_CODERS_UNPACK_SIZE))) return e;
    st->usz = (u64 *)gz_alloc((size_t)st->nco * 8 + 8);
    if (!st->usz) return GZ_E_NOMEM;
    for (u32 i = 0; i < st->nco; i++) {
        st->usz[i] = br_num(r);
        if (r->err) return r->err;
        if (st->usz[i] > SZ_BIG) return GZ_E_FORMAT;
    }
    for (;;) {
        u64 t = br_num(r);
        if (r->err) return r->err;
        if (t == P_END) return GZ_OK;
        if (t != P_CRC) { br_skip_data(r); continue; }
        u32 *crc = (u32 *)gz_alloc((size_t)n * 4 + 4);
        u8 *has = (u8 *)gz_alloc((size_t)n + 1);
        if (!crc || !has) { gz_free(crc); gz_free(has); return GZ_E_NOMEM; }
        e = read_digests(r, n, crc, has);
        for (u32 i = 0; !e && i < n; i++) { st->fo[i].crc = crc[i]; st->fo[i].has_crc = has[i]; }
        gz_free(crc);
        gz_free(has);
        if (e) return e;
    }
}

static u64 folder_size(const sz_streams *st, const sz_folder *f) { return st->usz[f->coder0 + f->main]; }

static int parse_substreams(br *r, sz_streams *st, int present)
{
    u64 t = P_END, total = 0;
    for (u32 i = 0; i < st->nfo; i++) st->fo[i].nsub = 1;
    if (present) {
        for (;;) {
            t = br_num(r);
            if (r->err) return r->err;
            if (t == P_NUM_UNPACK_STREAM) {
                for (u32 i = 0; i < st->nfo; i++) {
                    st->fo[i].nsub = br_count(r, SZ_COUNT_MAX);
                    if (r->err) return r->err;
                }
                continue;
            }
            if (t == P_CRC || t == P_SIZE || t == P_END) break;
            br_skip_data(r);
        }
    }
    for (u32 i = 0; i < st->nfo; i++) total += st->fo[i].nsub;
    /* every substream but the last of a folder costs a size byte */
    if (total > SZ_COUNT_MAX || total > (u64)st->nfo + br_left(r)) return GZ_E_FORMAT;
    st->nss = (u32)total;
    st->ssz = (u64 *)gz_alloc((size_t)total * 8 + 8);
    st->scrc = (u32 *)gz_alloc((size_t)total * 4 + 4);
    st->shas = (u8 *)gz_alloc((size_t)total + 1);
    if (!st->ssz || !st->scrc || !st->shas) return GZ_E_NOMEM;
    u32 k = 0;
    for (u32 i = 0; i < st->nfo; i++) {
        const sz_folder *f = &st->fo[i];
        if (!f->nsub) continue;
        u64 sum = 0, fs = folder_size(st, f);
        for (u32 j = 1; j < f->nsub; j++) {
            if (t != P_SIZE) return GZ_E_FORMAT;
            u64 sz = br_num(r);
            if (r->err) return r->err;
            sum += sz;
            if (sz > SZ_BIG || sum > fs) return GZ_E_FORMAT;
            st->ssz[k++] = sz;
        }
        if (sum > fs) return GZ_E_FORMAT;
        st->ssz[k++] = fs - sum;
    }
    if (t == P_SIZE) t = br_num(r);
    /* CRCs: a folder with one file and a folder CRC already has it */
    u32 nd = 0;
    k = 0;
    for (u32 i = 0; i < st->nfo; i++) {
        const sz_folder *f = &st->fo[i];
        if (f->nsub == 1 && f->has_crc) { st->scrc[k] = f->crc; st->shas[k] = 1; }
        else nd += f->nsub;
        k += f->nsub;
    }
    while (present && t != P_END) {
        if (r->err) return r->err;
        if (t == P_CRC) {
            u32 *crc = (u32 *)gz_alloc((size_t)nd * 4 + 4);
            u8 *has = (u8 *)gz_alloc((size_t)nd + 1);
            if (!crc || !has) { gz_free(crc); gz_free(has); return GZ_E_NOMEM; }
            int e = read_digests(r, nd, crc, has);
            u32 d = 0;
            k = 0;
            for (u32 i = 0; !e && i < st->nfo; i++) {
                const sz_folder *f = &st->fo[i];
                if (f->nsub == 1 && f->has_crc) { k++; continue; }
                for (u32 j = 0; j < f->nsub; j++, k++, d++) { st->scrc[k] = crc[d]; st->shas[k] = has[d]; }
            }
            gz_free(crc);
            gz_free(has);
            if (e) return e;
        } else {
            br_skip_data(r);
        }
        t = br_num(r);
    }
    return r->err;
}

static int parse_streams(br *r, sz_streams *st, u64 base, const sz_dvec *dv)
{
    u64 t = br_num(r);
    int e;
    if (t == P_PACK_INFO) {
        if ((e = parse_pack_info(r, st, base))) return e;
        t = br_num(r);
    }
    if (t == P_UNPACK_INFO) {
        if ((e = parse_unpack_info(r, st, dv))) return e;
        t = br_num(r);
    }
    if (r->err) return r->err;
    /* packed streams of each folder follow each other */
    u64 pk = 0;
    for (u32 i = 0; i < st->nfo; i++) {
        st->fo[i].pack0 = (u32)pk;
        pk += st->fo[i].npack;
        if (pk > st->npack) return GZ_E_FORMAT;
    }
    if (t == P_SUBSTREAMS) {
        if ((e = parse_substreams(r, st, 1))) return e;
        t = br_num(r);
    } else if ((e = parse_substreams(r, st, 0))) {
        return e;
    }
    if (r->err) return r->err;
    return t == P_END ? GZ_OK : GZ_E_FORMAT;
}

/* ---------------- folder decoding ---------------- */

typedef int (*sz_sink)(void *ctx, const u8 *p, size_t n);
typedef struct { int (*read)(void *ctx, u8 *buf, u32 cap, u32 *got); void *ctx; } sz_reader;

#define SZ_OBJ_MAX (SZ_MAXS * 3 + 8)

typedef struct {
    const sz_streams *st;
    const sz_folder *f;
    const sz_coder *co;           /* the folder's coders */
    const u8 *map;                /* the folder's in-stream map */
    const u64 *us;                /* the folder's coder unpack sizes */
    gz_src *s;
    gz_ctx *c;
    const gzch *pw;
    u32 busy;                     /* decoder kinds running (1 << K_*) */
    int pump_busy;                /* ctx buffer in use */
    u64 held;                     /* bytes of materialised streams */
    u32 nobj;
    struct { void *p; size_t big; void (*fr)(void *); } obj[SZ_OBJ_MAX];
} sz_dec;

static void *dec_keep(sz_dec *d, void *p, size_t big, void (*fr)(void *))
{
    if (!p) return 0;
    if (d->nobj >= SZ_OBJ_MAX) {
        if (big) gz_free_big(p, big); else if (fr) fr(p); else gz_free(p);
        return 0;
    }
    d->obj[d->nobj].p = p;
    d->obj[d->nobj].big = big;
    d->obj[d->nobj].fr = fr;
    d->nobj++;
    return p;
}

static void *dec_alloc(sz_dec *d, size_t n) { return dec_keep(d, gz_alloc(n), 0, 0); }

static void dec_free_all(sz_dec *d)
{
    while (d->nobj) {
        d->nobj--;
        void *p = d->obj[d->nobj].p;
        if (d->obj[d->nobj].big) gz_free_big(p, d->obj[d->nobj].big);
        else if (d->obj[d->nobj].fr) d->obj[d->nobj].fr(p);
        else gz_free(p);
    }
}

/* -- readers -- */

typedef struct { sz_reader in; u64 left; } sz_lim_rd;

static int lim_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    sz_lim_rd *l = (sz_lim_rd *)ctx;
    *got = 0;
    if (!l->left) return GZ_OK;
    if (cap > l->left) cap = (u32)l->left;
    int r = l->in.read(l->in.ctx, buf, cap, got);
    l->left -= *got;
    return r;
}

#define SZ_AES_BUF (64u << 10)
typedef struct {
    gz_aes k;
    u8 iv[16];
    sz_reader in;
    u64 left;                     /* output still allowed (coder unpack size) */
    u32 pos, have, carry;         /* buf[pos..have) plain, buf[have..have+carry) raw tail */
    int eof;
    u8 buf[SZ_AES_BUF];
} sz_aes_rd;

static int aes_read(void *ctx, u8 *out, u32 cap, u32 *got)
{
    sz_aes_rd *a = (sz_aes_rd *)ctx;
    *got = 0;
    if (a->pos == a->have) {
        if (a->eof || !a->left) return GZ_OK;
        u32 n = a->carry;
        if (n) __builtin_memmove(a->buf, a->buf + a->have, n);
        a->pos = a->have = a->carry = 0;
        while (n < 16) {
            u32 g = 0;
            int r = a->in.read(a->in.ctx, a->buf + n, SZ_AES_BUF - n, &g);
            if (r) return r;
            if (!g) { a->eof = 1; break; }
            n += g;
        }
        u32 dn = n & ~15u;              /* a partial last block is ignored */
        gz_aes_cbc_decrypt(&a->k, a->iv, a->buf, dn);
        a->have = dn;
        a->carry = n - dn;
        if (!dn) return GZ_OK;
    }
    u32 k = a->have - a->pos;
    if (k > cap) k = cap;
    if (k > a->left) k = (u32)a->left;
    __builtin_memcpy(out, a->buf + a->pos, k);
    a->pos += k;
    a->left -= k;
    *got = k;
    return GZ_OK;
}

/* -- 7zAES key derivation with a small per-thread cache -- */

#define SZ_KC_PW 128
typedef struct {
    u32 pwn;
    u8 power, ns, used;
    u8 ok;                        /* check_password confirmed this key */
    u8 salt[16], key[32];
    gzch pw[SZ_KC_PW];
} sz_kc_ent;
typedef struct { sz_kc_ent e[4]; u32 next; } sz_keycache;

static void *kc_new(void) { return gz_alloc(sizeof(sz_keycache)); }
static void kc_free(void *p)
{
    volatile u8 *q = (volatile u8 *)p;
    for (size_t i = 0; i < sizeof(sz_keycache); i++) q[i] = 0;
    gz_free(p);
}

/* 7zAES props: byte 0 = NumCyclesPower | salt bit 7 | iv bit 6; byte 1 = extra salt
 * size << 4 | extra iv size; then salt and iv. AES-256-CBC, iv zero padded. */
typedef struct { u32 power, ns, ni; const u8 *salt, *iv; } sz_aes_par;

static int aes_params(const u8 *p, u32 n, sz_aes_par *a)
{
    a->ns = a->ni = 0;
    if (n < 1) return GZ_E_METHOD;
    if (p[0] & 0xC0) {
        if (n < 2) return GZ_E_METHOD;
        a->ns = ((p[0] >> 7) & 1u) + (p[1] >> 4);
        a->ni = ((p[0] >> 6) & 1u) + (p[1] & 15u);
        if (n < 2 + a->ns + a->ni) return GZ_E_METHOD;
    }
    a->power = p[0] & 0x3Fu;
    a->salt = p + 2;
    a->iv = p + 2 + a->ns;
    return a->power > 24 && a->power != 0x3F ? GZ_E_METHOD : GZ_OK;
}

static sz_kc_ent *kc_find(gz_ctx *c, const gzch *pw, const sz_aes_par *ap, sz_keycache **pkc)
{
    size_t pn = gz_wcslen(pw);
    sz_keycache *kc = (c && pn <= SZ_KC_PW) ? (sz_keycache *)gz_ctx_slot(c, GZ_SLOT_MISC4, kc_new, kc_free) : 0;
    if (pkc) *pkc = kc;
    for (u32 i = 0; kc && i < 4; i++) {
        sz_kc_ent *e = &kc->e[i];
        if (!e->used || e->pwn != pn || e->power != ap->power || e->ns != ap->ns) continue;
        if (ap->ns && __builtin_memcmp(e->salt, ap->salt, ap->ns)) continue;
        if (pn && __builtin_memcmp(e->pw, pw, pn * sizeof(gzch))) continue;
        return e;
    }
    return 0;
}

static int derive_key(gz_ctx *c, const gzch *pw, const sz_aes_par *ap, u8 key[32])
{
    sz_keycache *kc;
    sz_kc_ent *e = kc_find(c, pw, ap, &kc);
    if (e) { __builtin_memcpy(key, e->key, 32); return GZ_OK; }
    /* gzch units are the UTF-16LE password bytes 7-Zip hashes (little-endian targets) */
    size_t pn = gz_wcslen(pw);
    int r = gz_7z_kdf(ap->salt, ap->ns, (const u8 *)pw, pn * sizeof(gzch), ap->power, key);
    if (r) return r == GZ_E_LIMIT ? GZ_E_METHOD : r;
    if (kc) {
        e = &kc->e[kc->next++ & 3];
        e->used = 1;
        e->ok = 0;
        e->pwn = (u32)pn;
        e->power = (u8)ap->power;
        e->ns = (u8)ap->ns;
        if (ap->ns) __builtin_memcpy(e->salt, ap->salt, ap->ns);
        if (pn) __builtin_memcpy(e->pw, pw, pn * sizeof(gzch));
        __builtin_memcpy(e->key, key, 32);
    }
    return GZ_OK;
}

static int aes_setup(sz_dec *d, const sz_coder *cd, sz_aes_rd *a)
{
    sz_aes_par ap;
    int r = aes_params(d->st->props + cd->prop, cd->nprop, &ap);
    if (r) return r;
    if (!d->pw) return GZ_E_PASSWORD;
    u8 key[32];
    if ((r = derive_key(d->c, d->pw, &ap, key))) return r;
    r = gz_aes_set_decrypt_key(&a->k, key, 32);
    __builtin_memset(key, 0, sizeof key);
    if (r) return r;
    __builtin_memset(a->iv, 0, 16);
    if (ap.ni) __builtin_memcpy(a->iv, ap.iv, ap.ni);
    return GZ_OK;
}

static int push_coder(sz_dec *d, u32 ci, sz_sink sink, void *sctx);

static int packed_reader(sz_dec *d, u32 k, sz_reader *rd)
{
    u32 g = d->f->pack0 + k;
    u64 off = d->st->ppos[g], n = d->st->psz[g];
    if (off > d->s->size || n > d->s->size - off) return GZ_E_TRUNC;
    gz_range_reader *rr = (gz_range_reader *)dec_alloc(d, sizeof *rr);
    if (!rr) return GZ_E_NOMEM;
    rr->src = d->s;
    rr->pos = off;
    rr->end = off + n;
    rr->cancel = d->c ? d->c->cancel : 0;
    rd->read = gz_range_read;
    rd->ctx = rr;
    return GZ_OK;
}

typedef struct { u8 *p; u64 cap, n; } sz_mem;

static int mem_wr(void *ctx, const u8 *p, size_t n)
{
    sz_mem *m = (sz_mem *)ctx;
    if (n > m->cap - m->n) return GZ_E_DATA;
    __builtin_memcpy(m->p + m->n, p, n);
    m->n += n;
    return GZ_OK;
}

static int coder_reader(sz_dec *d, u32 ci, sz_reader *rd);

static int stream_reader(sz_dec *d, u32 in, sz_reader *rd)
{
    u8 v = d->map[in];
    return (v & 0x80) ? packed_reader(d, v & 0x7Fu, rd) : coder_reader(d, v, rd);
}

/* reader over the output of coder ci */
static int coder_reader(sz_dec *d, u32 ci, sz_reader *rd)
{
    const sz_coder *cd = &d->co[ci];
    int r;
    if (cd->kind == K_AES) {
        sz_aes_rd *a = (sz_aes_rd *)dec_alloc(d, sizeof *a);
        if (!a) return GZ_E_NOMEM;
        if ((r = aes_setup(d, cd, a))) return r;
        if ((r = stream_reader(d, cd->in0, &a->in))) return r;
        a->left = d->us[ci];
        rd->read = aes_read;
        rd->ctx = a;
        return GZ_OK;
    }
    if (cd->kind == K_COPY) {
        sz_lim_rd *l = (sz_lim_rd *)dec_alloc(d, sizeof *l);
        if (!l) return GZ_E_NOMEM;
        if ((r = stream_reader(d, cd->in0, &l->in))) return r;
        l->left = d->us[ci];
        rd->read = lim_read;
        rd->ctx = l;
        return GZ_OK;
    }
    /* materialise: run the coder into memory first */
    u64 n = d->us[ci];
    if (n > SZ_MAT_MAX - d->held) return GZ_E_LIMIT;
    size_t big = (size_t)n ? (size_t)n : 1;
    u8 *buf = (u8 *)dec_keep(d, gz_alloc_big(big), big, 0);
    if (!buf) return GZ_E_NOMEM;
    d->held += n;
    sz_mem m = { buf, n, 0 };
    if ((r = push_coder(d, ci, mem_wr, &m))) return r == GZ_E_SKIP ? GZ_E_DATA : r;
    if (m.n != n) return GZ_E_DATA;
    gz_bcj2_mem *mm = (gz_bcj2_mem *)dec_alloc(d, sizeof *mm);
    if (!mm) return GZ_E_NOMEM;
    mm->p = buf;
    mm->n = (size_t)n;
    rd->read = gz_bcj2_mem_read;
    rd->ctx = mm;
    return GZ_OK;
}

/* copy exactly want bytes from a reader into a sink */
static int pump(sz_dec *d, sz_reader *rd, u64 want, sz_sink sink, void *sctx)
{
    u32 cap = 256u << 10;
    u8 *buf = 0;
    int own = 0;
    if (!d->pump_busy && d->c && (buf = gz_ctx_buffer(d->c, cap))) d->pump_busy = 1;
    else { cap = 64u << 10; buf = (u8 *)gz_alloc(cap); own = 1; }
    if (!buf) return GZ_E_NOMEM;
    int r = GZ_OK;
    while (want) {
        u32 n = want < cap ? (u32)want : cap, g = 0;
        if ((r = rd->read(rd->ctx, buf, n, &g))) break;
        if (!g) { r = GZ_E_DATA; break; }
        if ((r = sink(sctx, buf, g))) break;
        want -= g;
    }
    if (own) gz_free(buf); else d->pump_busy = 0;
    return r;
}

static int push_stream(sz_dec *d, u32 in, sz_sink sink, void *sctx)
{
    u8 v = d->map[in];
    if (!(v & 0x80)) return push_coder(d, v, sink, sctx);
    sz_reader rd;
    int r = packed_reader(d, v & 0x7Fu, &rd);
    return r ? r : pump(d, &rd, d->st->psz[d->f->pack0 + (v & 0x7Fu)], sink, sctx);
}

/* -- push adapters -- */

typedef struct { sz_reader rd; sz_sink sink; void *sctx; } sz_io;
static int io_rd(void *ctx, u8 *b, u32 cap, u32 *got) { sz_io *x = (sz_io *)ctx; return x->rd.read(x->rd.ctx, b, cap, got); }
static int io_wr(void *ctx, const u8 *p, size_t n) { sz_io *x = (sz_io *)ctx; return x->sink(x->sctx, p, n); }

typedef struct { sz_sink sink; void *sctx; u64 left; } sz_limit;
static int limit_wr(void *ctx, const u8 *p, size_t n)
{
    sz_limit *l = (sz_limit *)ctx;
    if (n > l->left) return GZ_E_DATA;
    l->left -= n;
    return l->sink(l->sctx, p, n);
}

/* Swap2 / Swap4: byte order of each 16/32-bit word (an incomplete tail is copied) */
typedef struct { sz_sink sink; void *sctx; u32 w, n; u8 buf[16384]; } sz_swap;

static int swap_wr(void *ctx, const u8 *p, size_t n)
{
    sz_swap *s = (sz_swap *)ctx;
    while (n) {
        size_t k = sizeof s->buf - s->n;
        if (k > n) k = n;
        __builtin_memcpy(s->buf + s->n, p, k);
        p += k;
        n -= k;
        u32 have = s->n + (u32)k, full = have - have % s->w;
        for (u32 i = 0; i < full; i += s->w) {
            u8 *q = s->buf + i;
            if (s->w == 2) { u8 t = q[0]; q[0] = q[1]; q[1] = t; }
            else wr32(q, __builtin_bswap32(rd32(q)));
        }
        int r = full ? s->sink(s->sctx, s->buf, full) : GZ_OK;
        if (r) return r;
        s->n = have - full;
        if (s->n) __builtin_memmove(s->buf, s->buf + full, s->n);
    }
    return GZ_OK;
}

static void *lzma_new(void) { return gz_lzma_dec_new(); }
static void lzma_del(void *p) { gz_lzma_dec_free((gz_lzma_dec *)p); }
static void *bz_new(void) { return gz_bzip2_dec_new(); }
static void bz_del(void *p) { gz_bzip2_dec_free((gz_bzip2_dec *)p); }
static void bcj2_del(void *p) { gz_bcj2_dec_free((gz_bcj2_dec *)p); }
static void *zs_new(void) { return gz_zstd_dec_new(); }
static void zs_del(void *p) { gz_zstd_dec_free((gz_zstd_dec *)p); }
static int ppmd_decode(sz_dec *d, const u8 *props, u32 np, const gz_stream_io *io, u64 osz)
{
#if SZ_HAVE_PPMD
    u32 order, mem;
    int r = gz_ppmd7z_props(props, np, &order, &mem);
    if (r) return r == GZ_E_FORMAT ? GZ_E_METHOD : r;
    gz_ppmd_cache *pc = (gz_ppmd_cache *)gz_ctx_slot(d->c, GZ_SLOT_PPMD, gz_ppmd_cache_new, gz_ppmd_cache_free);
    gz_ppmd7 *p = pc ? gz_ppmd_cache_7(pc) : 0;
    if (!p) return GZ_E_NOMEM;
    return gz_ppmd7z_decode(p, order, mem, io, osz);
#else
    (void)d; (void)props; (void)np; (void)io; (void)osz;
    return GZ_E_METHOD;
#endif
}

/* run a decoder coder: input from x->rd, output to x->sink */
static int run_decoder(sz_dec *d, const sz_coder *cd, u64 osz, sz_io *x)
{
    const u8 *pp = d->st->props + cd->prop;
    gz_stream_io io = { io_rd, io_wr, x };
    u32 bit = 1u << cd->kind;
    if (d->busy & bit) return GZ_E_METHOD;       /* cannot happen in a validated graph */
    if (!d->c) return GZ_E_NOMEM;
    int r = GZ_E_METHOD;
    d->busy |= bit;
    switch (cd->kind) {
    case K_LZMA:
    case K_LZMA2: {
        if (cd->nprop < (cd->kind == K_LZMA ? 5u : 1u)) break;
        gz_lzma_dec *z = (gz_lzma_dec *)gz_ctx_slot(d->c, GZ_SLOT_LZMA, lzma_new, lzma_del);
        if (!z) { r = GZ_E_NOMEM; break; }
        gz_lzma_dec_set_flags(z, 0);
        r = cd->kind == K_LZMA ? gz_lzma_decode(z, pp, &io, osz, 0) : gz_lzma2_decode(z, pp[0], &io, osz, 0);
        break;
    }
    case K_BZIP2: {
        gz_bzip2_dec *z = (gz_bzip2_dec *)gz_ctx_slot(d->c, GZ_SLOT_BZIP2, bz_new, bz_del);
        r = z ? gz_bzip2_decode(z, &io, osz, 1, 0) : GZ_E_NOMEM;
        if (r == GZ_E_FORMAT) r = GZ_E_DATA;
        break;
    }
    case K_DEFLATE:
    case K_DEFLATE64: {
        gz_inflater *z = gz_ctx_inflater(d->c);
        if (!z) { r = GZ_E_NOMEM; break; }
        sz_limit lim = { x->sink, x->sctx, osz };
        sz_io y = { x->rd, limit_wr, &lim };
        gz_stream_io io2 = { io_rd, io_wr, &y };
        r = gz_inflate_run(z, &io2, cd->kind == K_DEFLATE64);
        if (!r && lim.left) r = GZ_E_DATA;
        break;
    }
    case K_ZSTD: {
        gz_zstd_dec *z = (gz_zstd_dec *)gz_ctx_slot(d->c, GZ_SLOT_ZSTD, zs_new, zs_del);
        r = z ? gz_zstd_decode(z, &io, osz, 0) : GZ_E_NOMEM;
        if (r == GZ_E_FORMAT) r = GZ_E_DATA;
        break;
    }
    case K_LZ4:
        r = gz_lz4f_decode(&io, osz, 0);
        if (r == GZ_E_FORMAT) r = GZ_E_DATA;
        break;
    case K_PPMD:
        r = ppmd_decode(d, pp, cd->nprop, &io, osz);
        break;
    }
    d->busy &= ~bit;
    return r;
}

/* push the output of coder ci into sink */
static int push_coder(sz_dec *d, u32 ci, sz_sink sink, void *sctx)
{
    const sz_coder *cd = &d->co[ci];
    const u8 *pp = d->st->props + cd->prop;
    u64 osz = d->us[ci];
    int r;
    if (gz_cancelled(d->c)) return GZ_E_CANCEL;
    switch (cd->kind) {
    case K_COPY:
    case K_AES: {
        sz_reader rd;
        if ((r = coder_reader(d, ci, &rd))) return r;
        return pump(d, &rd, osz, sink, sctx);
    }
    case K_FILTER: {
        u32 param = 0;
        if (cd->bcj == GZ_BCJ_DELTA) {
            if (cd->nprop != 1) return GZ_E_METHOD;
            param = pp[0] + 1u;
        } else {
            if (cd->nprop == 4) param = rd32(pp);
            else if (cd->nprop) return GZ_E_METHOD;
            if (param % gz_bcj_align(cd->bcj)) return GZ_E_METHOD;
        }
        gz_filter_push *fp = (gz_filter_push *)dec_alloc(d, sizeof *fp);
        if (!fp) return GZ_E_NOMEM;
        gz_filter_push_init(fp, cd->bcj, param, 0, sink, sctx);
        r = push_stream(d, cd->in0, gz_filter_push_write, fp);
        return r ? r : gz_filter_push_finish(fp);
    }
    case K_SWAP2:
    case K_SWAP4: {
        sz_swap *sw = (sz_swap *)dec_alloc(d, sizeof *sw);
        if (!sw) return GZ_E_NOMEM;
        sw->sink = sink;
        sw->sctx = sctx;
        sw->w = cd->kind == K_SWAP2 ? 2 : 4;
        r = push_stream(d, cd->in0, swap_wr, sw);
        return r ? r : (sw->n ? sink(sctx, sw->buf, sw->n) : GZ_OK);
    }
    case K_BCJ2: {
        sz_reader in[3];
        gz_stream_io io[3];
        for (u32 k = 0; k < 3; k++) {
            if ((r = stream_reader(d, cd->in0 + 1 + k, &in[k]))) return r;
            io[k].read = in[k].read;
            io[k].write = 0;
            io[k].ctx = in[k].ctx;
        }
        gz_bcj2_dec *b = (gz_bcj2_dec *)dec_keep(d, gz_bcj2_dec_new(), 0, bcj2_del);
        if (!b) return GZ_E_NOMEM;
        if ((r = gz_bcj2_dec_init(b, &io[0], &io[1], &io[2], osz, sink, sctx))) return r;
        r = push_stream(d, cd->in0, gz_bcj2_dec_write, b);
        return r ? r : gz_bcj2_dec_finish(b);
    }
    default: {
        sz_io x;
        x.sink = sink;
        x.sctx = sctx;
        if ((r = stream_reader(d, cd->in0, &x.rd))) return r;
        return run_decoder(d, cd, osz, &x);
    }
    }
}

/* Decode folder fi of st into sink (the sink may stop early with GZ_E_SKIP, which is
 * returned). pw: password for 7zAES coders (NULL: GZ_E_PASSWORD). */
static int folder_run(const sz_streams *st, u32 fi, gz_src *s, gz_ctx *c, const gzch *pw,
                      sz_sink sink, void *sctx)
{
    const sz_folder *f = &st->fo[fi];
    if (f->flags & SZF_UNSUP) return GZ_E_METHOD;
    sz_dec *d = (sz_dec *)gz_alloc(sizeof(sz_dec));
    if (!d) return GZ_E_NOMEM;
    d->st = st;
    d->f = f;
    d->co = st->co + f->coder0;
    d->map = st->map + f->map0;
    d->us = st->usz + f->coder0;
    d->s = s;
    d->c = c;
    d->pw = pw;
    int r = push_coder(d, f->main, sink, sctx);
    dec_free_all(d);
    gz_free(d);
    return r;
}

/* decode folder fi into a new buffer (headers, additional streams) */
static int folder_to_mem(const sz_streams *st, u32 fi, gz_src *s, gz_ctx *c, const gzch *pw,
                         u64 limit, sz_buf *out)
{
    const sz_folder *f = &st->fo[fi];
    u64 n = folder_size(st, f);
    out->p = 0;
    out->n = 0;
    if (n > limit) return GZ_E_LIMIT;
    u8 *buf = (u8 *)gz_alloc_big((size_t)n ? (size_t)n : 1);
    if (!buf) return GZ_E_NOMEM;
    sz_mem m = { buf, n, 0 };
    int r = folder_run(st, fi, s, c, pw, mem_wr, &m);
    if (!r && m.n != n) r = GZ_E_DATA;
    if (!r && f->has_crc && gz_crc32(0, buf, (size_t)n) != f->crc) r = GZ_E_CRC;
    if (r) { gz_free_big(buf, (size_t)n ? (size_t)n : 1); return r; }
    out->p = buf;
    out->n = (size_t)n;
    return GZ_OK;
}

/* ---------------- FilesInfo ---------------- */

typedef struct { const u8 *def, *data; int all, present; } sz_vec;

/* times / attributes: defined vector, External switch, one value per defined item */
static int read_vec(br *pr, u64 nf, u32 width, const sz_dvec *dv, sz_vec *v)
{
    v->all = br_u8(pr);
    v->def = v->all ? 0 : br_take(pr, (nf + 7) >> 3);
    if (pr->err) return pr->err;
    u64 nd = v->all ? nf : count_bits(v->def, nf);
    int e = ext_switch(pr, dv);
    if (e) return e;
    v->data = br_take(pr, nd * width);
    v->present = 1;
    return pr->err;
}

static int parse_files(gz_archive *a, sz_priv *p, br *r, const sz_dvec *dv, gz_ctx *c)
{
    sz_streams *st = &p->st;
    u64 nf = br_num(r);
    if (r->err) return r->err;
    if (nf > SZ_COUNT_MAX || nf > GZ_MAX((u64)st->nss, br_left(r) * 8 + 8)) return GZ_E_FORMAT;
    const u8 *es = 0, *ef = 0, *anti = 0, *names = 0;
    u64 nempty = 0, ef_bits = 0, anti_bits = 0, names_len = 0;
    sz_vec mt = { 0 }, at = { 0 };
    int e;
    for (;;) {
        u64 t = br_num(r);
        if (r->err) return r->err;
        if (t == P_END) break;
        u64 size = br_num(r);
        const u8 *q = br_take(r, size);
        if (r->err) return r->err;
        br pr = { q, q + size, 0 };
        switch (t) {
        case P_EMPTY_STREAM:
            es = br_take(&pr, (nf + 7) >> 3);
            nempty = es ? count_bits(es, nf) : 0;
            ef = anti = 0;
            ef_bits = anti_bits = 0;
            break;
        case P_EMPTY_FILE:
            ef = br_take(&pr, (nempty + 7) >> 3);
            ef_bits = nempty;
            break;
        case P_ANTI:
            anti = br_take(&pr, (nempty + 7) >> 3);
            anti_bits = nempty;
            break;
        case P_NAME:
            if ((e = ext_switch(&pr, dv))) return e;
            names = pr.p;
            names_len = br_left(&pr);
            break;
        case P_MTIME:
            if ((e = read_vec(&pr, nf, 8, dv, &mt))) return e;
            break;
        case P_WIN_ATTRIB:
            if ((e = read_vec(&pr, nf, 4, dv, &at))) return e;
            break;
        default:                          /* CTime, ATime, StartPos, Dummy, ... */
            break;
        }
        if (pr.err) return pr.err;
    }
    if (nf - nempty != st->nss) return GZ_E_FORMAT;
    /* every name takes at least its terminator; nameless archives stay small */
    if (names ? nf > names_len / 2 : nf > (u64)st->nss + 65536) return GZ_E_FORMAT;
    if (nf && !a->e) {
        a->e = (gz_entry *)gz_alloc((size_t)nf * sizeof(gz_entry));
        if (a->e) a->cap = (u32)nf;
    }
    u64 eidx = 0, np = 0, mi = 0, ai = 0, foff = 0;
    u32 ss = 0, nextf = 0, cur = 0, left = 0, kin = 0;
    for (u64 i = 0; i < nf; i++) {
        if (c && !(i & 0xFFFF)) {
            if (gz_cancelled(c)) return GZ_E_CANCEL;
            if (c->progress && i) c->progress(c->progress_user, i, nf);
        }
        int empty = es && bit_at(es, i), dir = 0, is_anti = 0;
        if (empty) {
            dir = !(ef && eidx < ef_bits && bit_at(ef, eidx));
            is_anti = anti && eidx < anti_bits && bit_at(anti, eidx);
            eidx++;
        }
        const u8 *nm = 0;
        u64 nl = 0;
        if (names) {
            u64 j = np;
            while (j + 1 < names_len && rd16(names + j)) j += 2;
            if (j + 1 >= names_len) return GZ_E_FORMAT;
            nm = names + np;
            nl = j - np;
            np = j + 2;
        }
        u64 mtime = 0;
        u32 attr = 0;
        int has_mt = 0, has_at = 0;
        if (mt.present && (mt.all || bit_at(mt.def, i))) { mtime = rd64(mt.data + 8 * mi++); has_mt = 1; }
        if (at.present && (at.all || bit_at(at.def, i))) { attr = rd32(at.data + 4 * ai++); has_at = 1; }
        if (is_anti) continue;                    /* deletion marker of an update */
        gz_entry *x;
        if ((e = gz_arc_add_named(a, nm ? nm : (const u8 *)"", (u32)nl, GZ_NE_UTF16LE, &x))) return e;
        if (has_mt) { x->mtime = mtime; x->mtime_kind = GZ_MT_FILETIME; }
        if (has_at) {
            x->attr = attr & 0x7FFFu;
            if (attr & 0x8000u) x->unix_mode = attr >> 16;
        }
        x->aux32 = SZ_NONE;
        x->usize = x->csize = 0;
        if (empty) {
            x->is_dir = (u8)dir;
            if (dir) x->attr |= 0x10;
        } else {
            x->attr &= ~0x10u;
            if (ss >= st->nss) return GZ_E_FORMAT;
            while (!left) {
                while (nextf < st->nfo && !st->fo[nextf].nsub) nextf++;
                if (nextf >= st->nfo) return GZ_E_FORMAT;
                cur = nextf++;
                left = st->fo[cur].nsub;
                foff = 0;
                kin = 0;
            }
            sz_folder *f = &st->fo[cur];
            x->aux32 = cur;
            x->aux = kin;
            x->off = foff;
            x->usize = st->ssz[ss];
            x->crc = st->scrc[ss];
            x->has_crc = st->shas[ss];
            if (!kin) {
                f->first_entry = a->n - 1;
                for (u32 k = 0; k < f->npack; k++) x->csize += st->psz[f->pack0 + k];
            }
            if (f->flags & SZF_AES) x->enc = GZ_ENC_AES;
            foff += x->usize;
            kin++;
            left--;
            ss++;
        }
        if ((x->unix_mode & 0xF000u) == 0xA000u && !x->is_dir) x->is_link = 1;
    }
    if (ss != st->nss) return GZ_E_FORMAT;
    return GZ_OK;
}

/* ---------------- header ---------------- */

static int decode_all(const sz_streams *st, gz_src *s, gz_ctx *c, const gzch *pw, sz_dvec *dv)
{
    dv->b = (sz_buf *)gz_alloc((size_t)st->nfo * sizeof(sz_buf) + 8);
    if (!dv->b) return GZ_E_NOMEM;
    u64 total = 0;
    for (u32 i = 0; i < st->nfo; i++) {
        int r = folder_to_mem(st, i, s, c, pw, SZ_HDR_MAX - total, &dv->b[i]);
        if (r) return r;
        dv->n = i + 1;
        total += dv->b[i].n;
    }
    return GZ_OK;
}

static int parse_header(gz_archive *a, sz_priv *p, br *r, gz_src *s, gz_ctx *c)
{
    sz_dvec dv = { 0, 0 };
    int e = GZ_OK;
    u64 t = br_num(r);
    if (t == P_ARCHIVE_PROPS) {
        for (;;) {
            u64 x = br_num(r);
            if (r->err || x == P_END) break;
            br_skip_data(r);
        }
        t = br_num(r);
    }
    if (!r->err && t == P_ADD_STREAMS) {
        sz_streams ad;
        __builtin_memset(&ad, 0, sizeof ad);
        e = parse_streams(r, &ad, p->base, 0);
        if (!e) e = decode_all(&ad, s, c, a->password, &dv);
        streams_free(&ad);
        t = br_num(r);
    }
    if (!e && !r->err && t == P_MAIN_STREAMS) {
        e = parse_streams(r, &p->st, p->base, &dv);
        t = br_num(r);
    }
    if (!e && !r->err) {
        if (t == P_FILES) {
            e = parse_files(a, p, r, &dv, c);
            t = br_num(r);
        } else if (p->st.nss) {
            e = GZ_E_FORMAT;                /* data without file records */
        }
    }
    if (!e) e = r->err;
    if (!e && t != P_END) e = GZ_E_FORMAT;
    dvec_free(&dv);
    return e;
}

static int retryable(int r) { return r == GZ_E_DATA || r == GZ_E_CRC || r == GZ_E_FORMAT || r == GZ_E_PASSWORD; }

/* kEncodedHeader: decode the real header (asking for the password if it is encrypted) */
static int decode_header(gz_archive *a, sz_priv *p, br *r, gz_src *s, const gz_open_opts *o, gz_ctx *c,
                         sz_buf *out)
{
    sz_streams t;
    __builtin_memset(&t, 0, sizeof t);
    int e = parse_streams(r, &t, p->base, 0);
    if (!e && t.nfo != 1) e = GZ_E_FORMAT;
    if (e) { streams_free(&t); return e; }
    int enc = (t.fo[0].flags & SZF_AES) != 0;
    const gzch *pw = o->password;
    gzch *ask = 0;
    int retry = 0;
    for (u32 tries = 0;; tries++) {
        if (enc && !pw) {
            if (!o->ask_password || tries >= 32) { e = GZ_E_PASSWORD; break; }
            if (!ask && !(ask = (gzch *)gz_alloc(SZ_PW_CAP * sizeof(gzch)))) { e = GZ_E_NOMEM; break; }
            ask[0] = 0;
            int ar = o->ask_password(o->user, ask, SZ_PW_CAP, retry);
            if (ar) { e = ar == GZ_E_CANCEL ? GZ_E_CANCEL : GZ_E_PASSWORD; break; }
            ask[SZ_PW_CAP - 1] = 0;
            pw = ask;
        }
        e = folder_to_mem(&t, 0, s, c, pw, SZ_HDR_MAX, out);
        if (!e && (!out->n || out->p[0] != P_HEADER)) {
            gz_free_big(out->p, out->n ? out->n : 1);
            out->p = 0;
            e = GZ_E_FORMAT;
        }
        if (!e || !enc || !retryable(e)) break;
        pw = 0;
        retry = 1;
    }
    if (!e && enc) {
        gz_free(a->password);
        a->password = gz_wcsdup(pw);
        a->headers_enc = 1;
        if (!a->password) e = GZ_E_NOMEM;
    }
    if (ask) {
        for (u32 i = 0; i < SZ_PW_CAP; i++) ((volatile gzch *)ask)[i] = 0;
        gz_free(ask);
    }
    streams_free(&t);
    return e;
}

/* ---------------- signature / SFX ---------------- */

static int start_ok(const u8 *h)
{
    return !__builtin_memcmp(h, sz_sig, 6) && h[6] == 0 && gz_crc32(0, h + 12, 20) == rd32(h + 8);
}

/* end of the last PE section's raw data (where SFX stubs append their payload) */
static u64 pe_overlay(const u8 *h, u32 n)
{
    if (n < 0x40 || h[0] != 'M' || h[1] != 'Z') return 0;
    u32 pe = rd32(h + 0x3C);
    if (pe > n - 24 || rd32(h + pe) != 0x00004550u) return 0;
    u32 nsec = rd16(h + pe + 6), sec = pe + 24 + rd16(h + pe + 20);
    u64 end = 0;
    for (u32 i = 0; i < nsec && sec <= n - 40; i++, sec += 40) {
        u32 sz = rd32(h + sec + 16);
        u64 x = (u64)rd32(h + sec + 20) + sz;
        if (sz && x > end) end = x;
    }
    return end;
}

/* 7z archive appended to an executable stub: offset of a valid signature header */
static int find_sfx(gz_src *s, const u8 *h, u32 n, u64 *at)
{
    if (n < 64 || !((h[0] == 'M' && h[1] == 'Z') || rd32(h) == 0x464C457Fu)) return 0;
    u8 b[32];
    u64 ov = pe_overlay(h, n);
    if (ov && ov + 32 <= s->size && !gz_src_read_exact(s, ov, b, 32) && start_ok(b)) { *at = ov; return 1; }
    u32 cap = 1u << 16;
    u8 *buf = (u8 *)gz_alloc(cap + 32);
    if (!buf) return 0;
    u64 lim = GZ_MIN(s->size, (u64)SZ_SFX_SCAN), pos = 0;
    int found = 0;
    while (!found && pos + 32 <= lim) {
        u32 len = (u32)GZ_MIN((u64)cap + 31, s->size - pos);
        if (gz_src_read_exact(s, pos, buf, len)) break;
        for (u32 i = 0; i + 32 <= len && i < cap; i++) {
            if (buf[i] != '7' || buf[i + 1] != 'z' || buf[i + 2] != 0xBC) continue;
            if (pos + i && start_ok(buf + i)) { *at = pos + i; found = 1; break; }
        }
        pos += cap;
    }
    gz_free(buf);
    return found;
}

static int sz_probe(gz_src *s, const u8 *h, u32 n)
{
    if (n >= 6 && !__builtin_memcmp(h, sz_sig, 6)) return n >= 32 && start_ok(h) ? 95 : 60;
    u64 at;
    return find_sfx(s, h, n, &at) ? 80 : 0;
}

static int sz_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    u8 h[32];
    u64 base = 0;
    if (s->size < 32) return GZ_E_FORMAT;
    int r = gz_src_read_exact(s, 0, h, 32);
    if (r) return r;
    if (__builtin_memcmp(h, sz_sig, 6)) {
        u32 hn = (u32)GZ_MIN(s->size, (u64)65536);
        u8 *head = (u8 *)gz_alloc(hn);
        if (!head) return GZ_E_NOMEM;
        r = gz_src_read_exact(s, 0, head, hn);
        int ok = !r && find_sfx(s, head, hn, &base);
        gz_free(head);
        if (!ok) return r ? r : GZ_E_FORMAT;
        if ((r = gz_src_read_exact(s, base, h, 32))) return r;
    }
    if (h[6] != 0) return GZ_E_METHOD;                  /* major version */
    if (!start_ok(h)) return GZ_E_CRC;
    sz_priv *p = (sz_priv *)gz_alloc(sizeof(sz_priv));
    if (!p) return GZ_E_NOMEM;
    a->priv = p;
    p->base = base;
    a->sfx_shift = base;
    u64 nh_off = rd64(h + 12), nh_size = rd64(h + 20);
    u32 nh_crc = rd32(h + 28);
    if (!nh_size) return nh_off ? GZ_E_FORMAT : GZ_OK;  /* empty archive */
    if (nh_off > s->size || nh_size > s->size || base + 32 + nh_off > s->size - nh_size) return GZ_E_TRUNC;
    if (nh_size > SZ_HDR_MAX) return GZ_E_LIMIT;
    u8 *buf = (u8 *)gz_alloc((size_t)nh_size);
    if (!buf) return GZ_E_NOMEM;
    r = gz_src_read_exact(s, base + 32 + nh_off, buf, (u32)nh_size);
    if (!r && gz_crc32(0, buf, (size_t)nh_size) != nh_crc) r = GZ_E_CRC;
    sz_buf dec = { 0, 0 };
    br rr = { buf, buf + nh_size, 0 };
    u64 t = r ? 0 : br_num(&rr);
    if (!r && t == P_ENCODED_HEADER) {
        r = decode_header(a, p, &rr, s, o, c, &dec);
        if (!r) {
            rr.p = dec.p + 1;                 /* past kHeader */
            rr.end = dec.p + dec.n;
            rr.err = 0;
        }
    } else if (!r && t != P_HEADER) {
        r = GZ_E_FORMAT;
    }
    if (!r) r = parse_header(a, p, &rr, s, c);
    if (dec.p) gz_free_big(dec.p, dec.n ? dec.n : 1);
    gz_free(buf);
    if (r) return r;
    gz_free(p->st.ssz); gz_free(p->st.scrc); gz_free(p->st.shas);
    p->st.ssz = 0; p->st.scrc = 0; p->st.shas = 0;
    for (u32 i = 0; i < p->st.nfo; i++)
        if (p->st.fo[i].nsub > 1) a->solid = 1;
    return GZ_OK;
}

static void sz_close(gz_archive *a)
{
    sz_priv *p = (sz_priv *)a->priv;
    if (!p) return;
    streams_free(&p->st);
    gz_free(p);
    a->priv = 0;
}

/* ---------------- extraction ---------------- */

/* Output dispatcher for one folder: routes the folder's bytes to its files in order,
 * opens selected ones, checks CRCs and stops the decoder after the last wanted byte. */
typedef struct {
    gz_archive *a;
    gz_out *out;
    gz_ctx *c;
    const u8 *sel;          /* NULL: only `want`, opened by the caller */
    u32 want, fi;
    u32 scan;               /* next a->e index to look at */
    u32 left;               /* files of the folder not reached yet */
    u32 cur;                /* file being produced, SZ_NONE between files */
    int wr;                 /* cur is open and healthy */
    int enc;                /* encrypted folder: data errors mean a wrong password */
    int fatal;              /* cancel / open failure: abort the pass */
    int want_st, want_cr, want_done;
    u32 crc;
    u64 pos, cur_end, stop;
} dsink;

static int ds_wanted(const dsink *k, u32 i)
{
    return k->a->e[i].usize && (k->sel ? k->sel[i] != 0 : i == k->want);
}

static int ds_map(const dsink *k, int st)
{
    return k->enc && (st == GZ_E_DATA || st == GZ_E_CRC) ? GZ_E_PASSWORD : st;
}

/* close the current file if it is open (st == GZ_OK: verify its CRC) */
static int ds_close(dsink *k, int st)
{
    if (!k->wr) return GZ_OK;
    k->wr = 0;
    const gz_entry *e = &k->a->e[k->cur];
    if (!st && e->has_crc && k->crc != e->crc) st = GZ_E_CRC;
    st = ds_map(k, st);
    int r = k->out->close(k->out, k->cur, st);
    if (k->cur == k->want) { k->want_st = st; k->want_cr = r; k->want_done = 1; }
    if (st == GZ_E_CANCEL || r == GZ_E_CANCEL) { k->fatal = GZ_E_CANCEL; return GZ_E_CANCEL; }
    return GZ_OK;
}

static u32 ds_find(dsink *k)
{
    const gz_archive *a = k->a;
    u32 i = k->scan;
    while (i < a->n && a->e[i].aux32 != k->fi) i++;
    k->scan = i + 1;
    k->left--;
    return i < a->n ? i : SZ_NONE;
}

/* move to the next file with data (zero-length files are handled before decoding) */
static int ds_next(dsink *k)
{
    k->cur = SZ_NONE;
    while (k->left) {
        u32 i = ds_find(k);
        if (i == SZ_NONE) { k->left = 0; break; }
        const gz_entry *e = &k->a->e[i];
        if (!e->usize) continue;
        k->cur = i;
        k->cur_end = k->pos + e->usize;
        k->crc = 0;
        k->wr = 0;
        if (ds_wanted(k, i)) {
            int r = k->sel ? k->out->open(k->out, i) : GZ_OK;
            if (!r) k->wr = 1;
            else if (r != GZ_E_SKIP) { k->fatal = r; return r; }
        }
        return GZ_OK;
    }
    return GZ_OK;
}

static int ds_write(void *ctx, const u8 *p, size_t n)
{
    dsink *k = (dsink *)ctx;
    if (gz_cancelled(k->c)) { k->fatal = GZ_E_CANCEL; return GZ_E_CANCEL; }
    while (n) {
        if (!k->sel && k->want_done) return GZ_E_SKIP;
        if (k->cur == SZ_NONE) {
            if (k->pos >= k->stop) return GZ_E_SKIP;
            int r = ds_next(k);
            if (r) return r;
            if (k->cur == SZ_NONE) return GZ_E_SKIP;    /* data beyond the last file */
        }
        u64 room = k->cur_end - k->pos;
        size_t m = n < room ? n : (size_t)room;
        if (k->wr) {
            k->crc = gz_crc32(k->crc, p, m);
            int r = k->out->write(k->out, p, m);
            if (r && ds_close(k, r)) return GZ_E_CANCEL;
        }
        k->pos += m;
        p += m;
        n -= m;
        if (k->pos == k->cur_end) {
            if (ds_close(k, GZ_OK)) return GZ_E_CANCEL;
            k->cur = SZ_NONE;
        }
    }
    return GZ_OK;
}

/* after decoding with status st: fail the open file and the wanted files not reached */
static int ds_end(dsink *k, int st)
{
    if (st == GZ_E_SKIP) st = GZ_OK;
    if (k->fatal && k->fatal != GZ_E_CANCEL) {
        if (k->cur != SZ_NONE) ds_close(k, k->fatal);
        if (!k->sel && !k->want_done) { k->want_st = k->fatal; k->want_cr = k->out->close(k->out, k->want, k->fatal); }
        return k->fatal;
    }
    if (k->fatal) st = GZ_E_CANCEL;
    if (k->cur != SZ_NONE && ds_close(k, st ? st : GZ_E_DATA)) st = GZ_E_CANCEL;
    k->cur = SZ_NONE;
    if (!k->sel) {
        if (!k->want_done) {
            int es = ds_map(k, st ? st : GZ_E_DATA);
            k->want_st = es;
            k->want_cr = k->out->close(k->out, k->want, es);
        }
        return st == GZ_E_CANCEL ? GZ_E_CANCEL : GZ_OK;
    }
    if (st == GZ_E_CANCEL) return GZ_E_CANCEL;
    while (k->left) {
        u32 i = ds_find(k);
        if (i == SZ_NONE) break;
        if (!ds_wanted(k, i)) continue;
        int es = ds_map(k, st ? st : GZ_E_DATA);
        int r = k->out->open(k->out, i);
        if (r == GZ_E_SKIP) continue;
        if (r) return r;
        r = k->out->close(k->out, i, es);
        if (r == GZ_E_CANCEL || gz_cancelled(k->c)) return GZ_E_CANCEL;
    }
    return GZ_OK;
}

/* decode folder fi for the selected files (sel) or one file (want, already open) */
static int run_folder(gz_archive *a, gz_src *s, u32 fi, const u8 *sel, u32 want, u64 stop,
                      gz_out *out, gz_ctx *c, dsink *k)
{
    sz_priv *p = (sz_priv *)a->priv;
    const sz_folder *f = &p->st.fo[fi];
    __builtin_memset(k, 0, sizeof *k);
    k->a = a;
    k->out = out;
    k->c = c;
    k->sel = sel;
    k->want = want;
    k->fi = fi;
    k->scan = f->first_entry;
    k->left = f->nsub;
    k->cur = SZ_NONE;
    k->stop = stop;
    k->enc = (f->flags & SZF_AES) != 0;
    int st;
    if (f->first_entry == SZ_NONE) st = GZ_E_FORMAT;
    else if (k->enc && !c->password) st = GZ_E_PASSWORD;
    else st = folder_run(&p->st, fi, s, c, c->password, ds_write, k);
    return ds_end(k, st);
}

/* entries without data: directories, empty files, zero-length files of a folder */
static int extract_plain(gz_archive *a, u32 idx, gz_out *out)
{
    const gz_entry *e = &a->e[idx];
    int r = out->open(out, idx);
    if (r) return r;
    int st = e->has_crc && e->crc && !e->usize ? GZ_E_CRC : GZ_OK;
    r = out->close(out, idx, st);
    return st ? st : r;
}

static int sz_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    sz_priv *p = (sz_priv *)a->priv;
    const gz_entry *e = &a->e[idx];
    if (e->aux32 == SZ_NONE || !e->usize) return extract_plain(a, idx, out);
    const sz_folder *f = &p->st.fo[e->aux32];
    if (f->flags & SZF_UNSUP) return GZ_E_METHOD;
    if ((f->flags & SZF_AES) && !c->password) return GZ_E_PASSWORD;
    int r = out->open(out, idx);
    if (r) return r;
    dsink k;
    r = run_folder(a, s, e->aux32, 0, idx, e->off + e->usize, out, c, &k);
    if (k.want_st) return k.want_st;
    return r ? r : k.want_cr;
}

static int sz_extract_solid(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_ctx *c)
{
    sz_priv *p = (sz_priv *)a->priv;
    int r;
    for (u32 i = 0; i < a->n; i++) {
        const gz_entry *e = &a->e[i];
        if (!sel[i] || (e->aux32 != SZ_NONE && e->usize)) continue;
        if (gz_cancelled(c)) return GZ_E_CANCEL;
        r = extract_plain(a, i, out);
        if (r == GZ_E_CANCEL) return r;
    }
    for (u32 fi = 0; fi < p->st.nfo; fi++) {
        const sz_folder *f = &p->st.fo[fi];
        if (gz_cancelled(c)) return GZ_E_CANCEL;
        if (f->first_entry == SZ_NONE) continue;
        u64 stop = 0;
        int any = 0;
        u32 i = f->first_entry;
        for (u32 left = f->nsub; left && i < a->n; i++) {
            const gz_entry *e = &a->e[i];
            if (e->aux32 != fi) continue;
            left--;
            if (sel[i] && e->usize) { stop = e->off + e->usize; any = 1; }
        }
        if (!any) continue;
        dsink k;
        r = run_folder(a, s, fi, sel, SZ_NONE, stop, out, c, &k);
        if (r) return r;
    }
    return GZ_OK;
}

/* checker sink: CRC of the first `limit` bytes, then stop */
typedef struct { u64 limit, n; u32 crc; } sz_probe_sink;

static int probe_wr(void *ctx, const u8 *p, size_t n)
{
    sz_probe_sink *k = (sz_probe_sink *)ctx;
    u64 room = k->limit - k->n;
    size_t m = n < room ? n : (size_t)room;
    k->crc = gz_crc32(k->crc, p, m);
    k->n += m;
    return k->n >= k->limit ? GZ_E_SKIP : GZ_OK;
}

static int sz_check_password(gz_archive *a, gz_src *s, u32 idx, gz_ctx *c)
{
    sz_priv *p = (sz_priv *)a->priv;
    const gz_entry *e = &a->e[idx];
    if (!e->enc || e->aux32 == SZ_NONE) return GZ_OK;
    if (!c->password) return GZ_E_PASSWORD;
    const sz_folder *f = &p->st.fo[e->aux32];
    if ((f->flags & SZF_UNSUP) || f->first_entry == SZ_NONE) return GZ_OK;
    /* one AES coder whose key this thread already confirmed: nothing to decode */
    const sz_coder *aes = 0;
    for (u32 k = 0; k < f->ncoders; k++) {
        const sz_coder *cd = &p->st.co[f->coder0 + k];
        if (cd->kind == K_AES) aes = aes ? (const sz_coder *)-1 : cd;
    }
    sz_aes_par ap;
    int one = aes && aes != (const sz_coder *)-1 && !aes_params(p->st.props + aes->prop, aes->nprop, &ap);
    sz_kc_ent *ke = one ? kc_find(c, c->password, &ap, 0) : 0;
    if (ke && ke->ok) return GZ_OK;
    const gz_entry *e0 = &a->e[f->first_entry];
    u64 fs = folder_size(&p->st, f);
    sz_probe_sink k = { GZ_MIN(fs, (u64)256 << 10), 0, 0 };
    int full = e0->has_crc && e0->usize && e0->usize <= (1u << 20);
    if (full) k.limit = e0->usize;
    if (!k.limit) return GZ_OK;
    int r = folder_run(&p->st, e->aux32, s, c, c->password, probe_wr, &k);
    if (r == GZ_E_SKIP) r = GZ_OK;
    if (!r && full && (k.n != k.limit || k.crc != e0->crc)) return GZ_E_PASSWORD;
    if (r == GZ_E_DATA || r == GZ_E_CRC || r == GZ_E_PASSWORD) return GZ_E_PASSWORD;
    if (!r && full && one && (ke = kc_find(c, c->password, &ap, 0))) ke->ok = 1;   /* CRC-proven */
    return r == GZ_E_CANCEL ? r : GZ_OK;
}

/* stored, unencrypted files can be read in place */
static gz_src *sz_view(gz_archive *a, gz_src *s, u32 idx)
{
    sz_priv *p = (sz_priv *)a->priv;
    const gz_entry *e = &a->e[idx];
    if (e->aux32 == SZ_NONE || e->is_dir) return 0;
    const sz_folder *f = &p->st.fo[e->aux32];
    if (f->ncoders != 1 || f->npack != 1 || p->st.co[f->coder0].kind != K_COPY) return 0;
    u64 off = p->st.ppos[f->pack0] + e->off;
    if (e->off + e->usize > p->st.psz[f->pack0] || off > s->size || e->usize > s->size - off) return 0;
    return gz_src_sub(s, off, e->usize);
}

/* ---------------- method names (as 7-Zip shows them) ---------------- */

typedef struct { char *b; u32 cap, i; } sz_str;

static void ps(sz_str *s, const char *t) { while (*t && s->i + 1 < s->cap) s->b[s->i++] = *t++; }
static void pu(sz_str *s, u32 v)
{
    char t[12];
    int n = 0;
    do { t[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (n && s->i + 1 < s->cap) s->b[s->i++] = t[--n];
}
/* 2^n -> "n", else "<v>m" / "<v>k" / "<v>b" */
static void psize(sz_str *s, u32 v)
{
    for (u32 i = 0; i < 32; i++) if (v == (1u << i)) { pu(s, i); return; }
    const char *u = "b";
    if (!(v & ((1u << 20) - 1))) { v >>= 20; u = "m"; }
    else if (!(v & ((1u << 10) - 1))) { v >>= 10; u = "k"; }
    pu(s, v);
    ps(s, u);
}

static void coder_text(sz_str *s, const sz_coder *cd, const u8 *pp)
{
    static const char *const names[] = {
        0, "Copy", "LZMA", "LZMA2", "PPMD", "BZip2", "Deflate", "Deflate64", 0,
        "BCJ2", "7zAES", "Swap2", "Swap4", "ZSTD", "LZ4"
    };
    const char *n = cd->kind == K_FILTER ? gz_bcj_name(cd->bcj) : names[cd->kind];
    if (!n) {
        switch (cd->id) {
        case 0x04F71102: n = "BROTLI"; break;
        case 0x04F71105: n = "LZ5"; break;
        case 0x04F71106: n = "LIZARD"; break;
        }
    }
    if (!n) {
        static const char hx[] = "0123456789ABCDEF";
        char t[17];
        int k = 0;
        u64 v = cd->id;
        do { t[k++] = hx[v & 15]; v >>= 4; } while (v);
        while (k && s->i + 1 < s->cap) s->b[s->i++] = t[--k];
        return;
    }
    ps(s, n);
    u32 np = cd->nprop;
    switch (cd->kind) {
    case K_LZMA:
        if (np >= 5) {
            ps(s, ":");
            psize(s, rd32(pp + 1));
            u32 d = pp[0];
            if (d != 0x5D) {
                u32 lc = d % 9, lp = (d / 9) % 5, pb = d / 45;
                if (lc != 3) { ps(s, ":lc"); pu(s, lc); }
                if (lp != 0) { ps(s, ":lp"); pu(s, lp); }
                if (pb != 2) { ps(s, ":pb"); pu(s, pb); }
            }
        }
        break;
    case K_LZMA2:
        if (np >= 1 && pp[0] <= 40) {
            ps(s, ":");
            if (pp[0] & 1) psize(s, 3u << (pp[0] / 2 + 11));
            else pu(s, pp[0] / 2u + 12);
        }
        break;
    case K_PPMD:
        if (np >= 5) { ps(s, ":o"); pu(s, pp[0]); ps(s, ":mem"); psize(s, rd32(pp + 1)); }
        break;
    case K_AES:
        if (np >= 1) { ps(s, ":"); pu(s, pp[0] & 0x3Fu); }
        break;
    case K_FILTER:
        if (cd->bcj == GZ_BCJ_DELTA && np == 1) { ps(s, ":"); pu(s, pp[0] + 1u); }
        else if (np == 4 && rd32(pp)) { ps(s, ":"); pu(s, rd32(pp)); }
        break;
    }
}

static void sz_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    const sz_priv *p = (const sz_priv *)a->priv;
    sz_str s = { buf, cap, 0 };
    if (e->aux32 != SZ_NONE && p) {
        const sz_folder *f = &p->st.fo[e->aux32];
        for (u32 k = f->ncoders; k-- > 0;) {        /* 7-Zip lists the last coder first */
            if (s.i) ps(&s, " ");
            const sz_coder *cd = &p->st.co[f->coder0 + k];
            coder_text(&s, cd, p->st.props + cd->prop);
        }
    }
    if (cap) buf[s.i] = 0;
}

GZ_FORMAT(gz_fmt_7z)
const gz_format gz_fmt_7z = {
    "7z", "7z",
    0, sz_probe, sz_open, sz_close, sz_extract, sz_extract_solid, sz_check_password, sz_method, sz_view, 0
};
