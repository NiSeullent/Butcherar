/*
 * 고깃ZIP - SquashFS 4.0 and 3.x images (Linux compressed read-only file system)
 *
 *   Compressors: gzip (zlib streams, Adler-32 checked), lzma (squashfs-lzma: .lzma
 *   "alone" header of 5 property bytes + 64-bit size, or properties only), xz (one xz
 *   stream per block: LZMA2 with optional BCJ / Delta filters, CRC32/CRC64/SHA-256
 *   checks), lzo (LZO1X), lz4 (raw blocks), zstd. Uncompressed metadata, data,
 *   fragments and id tables (-noI -noD -noF -noId) are read as they are.
 *
 *   The inode and directory tables are decoded at open (sizes capped); every file,
 *   directory and symbolic link is listed (devices, fifos and sockets are skipped,
 *   extended attributes and the export table are ignored). A hard link is listed
 *   once per name, each with the full data. Files: block lists with uncompressed
 *   and sparse blocks, tails packed in shared fragment blocks (small per-thread
 *   cache, see sq_rd), random-access views with a one-block cache.
 *
 *   SquashFS 3.0 / 3.1: little- and big-endian (bit-packed inodes and directory entries),
 *   zlib, check-data marker bytes, uid / gid tables, and the LZMA variants of vendor
 *   firmware that 7-Zip reads: raw LZMA blocks without properties (first metadata
 *   byte 0) and the "shsq" magic with a 13-byte LZMA header or zlib chosen per block.
 *   1.x / 2.x images are reported as unsupported (GZ_E_METHOD).
 *
 *   Hostile images: metadata blocks must be 1..8192 bytes, every inode reference,
 *   directory position, name and block list is bounds-checked against the decoded
 *   tables, directories are visited once (inode set) and to a limited depth, data
 *   and fragment blocks are at most one block long and must decode to exactly the
 *   size the file needs.
 *
 *   Thread safety: the archive state is read-only after open. Extraction uses a
 *   per-thread sq_rd (gz_ctx slot) whose fragment cache is keyed by the archive
 *   and a random nonce, so a later archive at the same address never sees stale
 *   blocks. Views own a private sq_rd.
 */
#include "fs1.h"
#include "sqfs.h"
#include "crc32.h"
#include "crc64.h"
#include "sha256.h"
#include "lzma.h"
#include "bcj.h"
#include "lzo.h"
#include "lz4.h"
#include "zstd.h"
#include "cpu.h"
#if defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#elif defined(__aarch64__)
#include <arm_neon.h>
#endif

#define SQ_MAGIC        0x73717368u      /* "hsqs" */
#define SQ_MAGIC_BE     0x68737173u      /* "sqsh": big-endian 1.x - 3.x */
#define SQ_MAGIC_LZ     0x71736873u      /* "shsq": 3.x, zlib or LZMA chosen per block */
#define SQ_MAGIC_LZ_BE  0x73687371u
#define SQ_META         8192u            /* uncompressed metadata block size */
#define SQ_NOFRAG       0xFFFFFFFFu
#define SQ_RAW          (1u << 24)       /* data / fragment block stored uncompressed */
#define SQ_LENMASK      0x00FFFFFFu
#define SQ_NAME_MAX     256u
#define SQ_DIR_COUNT    256u
#define SQ_LINK_MAX     65535u

enum { C_GZIP = 1, C_LZMA, C_LZO, C_XZ, C_LZ4, C_ZSTD, C_COUNT,
       C_LZMA_RAW = C_COUNT,             /* 3.x: raw LZMA, lc3 lp0 pb2, no header */
       C_MIXED,                          /* 3.x "shsq": 0x5D = .lzma header, else zlib */
       C_ALL };
enum { F_COMP_OPT = 0x0400 };
enum { T_DIR = 1, T_FILE, T_LINK, T_LDIR = 8, T_LFILE, T_LLINK };

/* Decoded inode / directory tables (32-bit positions) and entry names: absolute caps,
 * and at most SQ_RATIO times the bytes they come from (real tables compress < 20:1). */
#if UINTPTR_MAX > 0xFFFFFFFFu
#  define SQ_TAB_MAX ((size_t)1 << 31)
#  define SQ_NAMES_MAX ((size_t)1 << 30)
#else
#  define SQ_TAB_MAX ((size_t)256 << 20)
#  define SQ_NAMES_MAX ((size_t)256 << 20)
#endif
#define SQ_RATIO 64u
#define SQ_WIN_MIN (512u << 10)           /* input window of a reader */
#define SQ_NFC 4                          /* cached fragment blocks per reader */

/* ================================================================ codecs */

typedef struct {
    gz_inflater *z;
    gz_lzma_dec *lz;
    gz_zstd_dec *zs;
} sq_codec;

static void codec_free(sq_codec *k)
{
    if (k->z) gz_inflater_free(k->z);
    if (k->lz) gz_lzma_dec_free(k->lz);
    if (k->zs) gz_zstd_dec_free(k->zs);
    k->z = 0; k->lz = 0; k->zs = 0;
}

/* memory in -> bounded memory out */
typedef struct { const u8 *in; size_t n, pos; u8 *out; size_t on, ocap; int full; } sq_mio;

static int mio_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    sq_mio *m = (sq_mio *)ctx;
    size_t k = m->n - m->pos;
    if (k > cap) k = cap;
    __builtin_memcpy(buf, m->in + m->pos, k);
    m->pos += k;
    *got = (u32)k;
    return GZ_OK;
}

static int mio_write(void *ctx, const u8 *p, size_t n)
{
    sq_mio *m = (sq_mio *)ctx;
    if (n > m->ocap - m->on) { m->full = 1; return GZ_E_DATA; }
    __builtin_memcpy(m->out + m->on, p, n);
    m->on += n;
    return GZ_OK;
}

/* ---- Adler-32 (zlib trailer): scalar, SSE2 and NEON kernels ---- */

#define ADLER_MOD 65521u
#define ADLER_VMAX 5536u            /* 16-byte blocks between reductions (<= 5552, the zlib NMAX) */

static void adler_scalar(u32 *pa, u32 *pb, const u8 *p, size_t n)
{
    u32 a = *pa, b = *pb;
    while (n) {
        size_t k = n < 5552 ? n : 5552;
        n -= k;
        for (; k >= 8; k -= 8, p += 8) {       /* weighted sum: short dependency chain */
            b += 8 * a + 8u * p[0] + 7u * p[1] + 6u * p[2] + 5u * p[3] + 4u * p[4] + 3u * p[5] + 2u * p[6] + p[7];
            a += (u32)p[0] + p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7];
        }
        while (k--) { a += *p++; b += a; }
        a %= ADLER_MOD;
        b %= ADLER_MOD;
    }
    *pa = a;
    *pb = b;
}

/* Per chunk of 16-byte blocks: s1 = byte sums, ps = sum of s1 before each block,
 * s2 = bytes weighted 16..1; then b += 16 * blocks * a + 16 * ps + s2, a += s1. */
static void adler_fold(u32 *pa, u32 *pb, u64 s1, u64 ps, u64 s2, u32 blocks)
{
    u64 b = *pb + (u64)*pa * 16 * blocks + 16 * ps + s2;
    *pa = (u32)((*pa + s1) % ADLER_MOD);
    *pb = (u32)(b % ADLER_MOD);
}

#if defined(__i386__) || defined(__x86_64__)
__attribute__((target("sse2"))) static void adler_sse2(u32 *pa, u32 *pb, const u8 *p, size_t n)
{
    const __m128i z = _mm_setzero_si128();
    const __m128i w1 = _mm_setr_epi16(16, 15, 14, 13, 12, 11, 10, 9), w2 = _mm_setr_epi16(8, 7, 6, 5, 4, 3, 2, 1);
    while (n >= 16) {
        u32 k = n < ADLER_VMAX ? (u32)n & ~15u : ADLER_VMAX, blocks = k / 16;
        n -= k;
        __m128i s1 = z, ps = z, s2 = z;
        for (; k; k -= 16, p += 16) {
            __m128i x = _mm_loadu_si128((const __m128i *)p);
            ps = _mm_add_epi32(ps, s1);
            s1 = _mm_add_epi32(s1, _mm_sad_epu8(x, z));
            s2 = _mm_add_epi32(s2, _mm_madd_epi16(_mm_unpacklo_epi8(x, z), w1));
            s2 = _mm_add_epi32(s2, _mm_madd_epi16(_mm_unpackhi_epi8(x, z), w2));
        }
        u32 v1[4], vp[4], v2[4];
        _mm_storeu_si128((__m128i *)v1, s1);
        _mm_storeu_si128((__m128i *)vp, ps);
        _mm_storeu_si128((__m128i *)v2, s2);
        adler_fold(pa, pb, (u64)v1[0] + v1[1] + v1[2] + v1[3], (u64)vp[0] + vp[1] + vp[2] + vp[3],
                   (u64)v2[0] + v2[1] + v2[2] + v2[3], blocks);
    }
    if (n) adler_scalar(pa, pb, p, n);
}
#endif

#if defined(__aarch64__)
static void adler_neon(u32 *pa, u32 *pb, const u8 *p, size_t n)
{
    static const u8 w[16] = { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
    const uint8x8_t w1 = vld1_u8(w), w2 = vld1_u8(w + 8);
    while (n >= 16) {
        u32 k = n < ADLER_VMAX ? (u32)n & ~15u : ADLER_VMAX, blocks = k / 16;
        n -= k;
        uint32x4_t s1 = vdupq_n_u32(0), ps = s1, s2 = s1;
        for (; k; k -= 16, p += 16) {
            uint8x16_t x = vld1q_u8(p);
            ps = vaddq_u32(ps, s1);
            s1 = vpadalq_u16(s1, vpaddlq_u8(x));
            s2 = vpadalq_u16(s2, vmull_u8(vget_low_u8(x), w1));
            s2 = vpadalq_u16(s2, vmull_u8(vget_high_u8(x), w2));
        }
        adler_fold(pa, pb, vaddvq_u32(s1), vaddvq_u32(ps), vaddvq_u32(s2), blocks);
    }
    if (n) adler_scalar(pa, pb, p, n);
}
#endif

static u32 adler32(const u8 *p, size_t n)
{
    u32 a = 1, b = 0;
#if defined(__i386__) || defined(__x86_64__)
    if (g_cpu.active >= GZ_TIER_SSE2) adler_sse2(&a, &b, p, n);
    else adler_scalar(&a, &b, p, n);
#elif defined(__aarch64__)
    adler_neon(&a, &b, p, n);
#else
    adler_scalar(&a, &b, p, n);
#endif
    return b << 16 | a;
}

int gz_sqfs_zlib(gz_inflater **z, const u8 *in, u32 n, u8 *out, u32 cap, u32 *on)
{
    *on = 0;
    if (n < 6 || (in[0] & 15) != 8 || (in[0] >> 4) > 7 || ((in[0] << 8) | in[1]) % 31 || (in[1] & 0x20))
        return GZ_E_DATA;
    if (!*z && !(*z = gz_inflater_new())) return GZ_E_NOMEM;
    sq_mio m = { in + 2, n - 2, 0, out, 0, cap, 0 };
    gz_stream_io io = { mio_read, mio_write, &m };
    int r = gz_inflate_run(*z, &io, 0);
    if (r) return r;
    size_t used = 2 + m.pos - (*z)->rest_len;        /* end of the deflate data */
    if (n - used < 4) return GZ_E_DATA;
    if (rd32be(in + used) != adler32(out, m.on)) return GZ_E_CRC;
    *on = (u32)m.on;
    return GZ_OK;
}

/* Smallest LZMA dictionary that covers cap bytes of output: the decoder's window never
 * has to be larger than the block, whatever the header says (bounds memory). */
static u32 dict_cap(u32 dict, u32 cap)
{
    if (cap < 4096) cap = 4096;
    return dict > cap ? cap : dict;
}

static int dec_lzma(sq_codec *k, const u8 *in, u32 n, u8 *out, u32 cap, u32 *on)
{
    if (n < 6) return GZ_E_DATA;
    u8 props[5];
    __builtin_memcpy(props, in, 5);
    u32 hl = 13;
    u64 osz = GZ_SIZE_UNKNOWN, usz = n >= 13 ? rd64(in + 5) : ~(u64)0 - 1;
    if (usz <= cap) osz = usz;
    else if (usz != ~(u64)0) hl = 5;                  /* properties only, no size field */
    wr32(props + 1, dict_cap(rd32(props + 1), cap));
    if (!k->lz && !(k->lz = gz_lzma_dec_new())) return GZ_E_NOMEM;
    sq_mio m = { 0, 0, 0, out, 0, cap, 0 };
    u64 used = 0;
    int r = gz_lzma_decode_mem(k->lz, props, in + hl, n - hl, osz, mio_write, &m, &used);
    if (r) return r;
    *on = (u32)m.on;
    return GZ_OK;
}

/* 3.x vendor variant: the block is a raw LZMA stream (lc 3, lp 0, pb 2). want = exact size
 * when known; otherwise it ends with an end marker or fills cap exactly. */
static int dec_lzma_raw(sq_codec *k, const u8 *in, u32 n, u8 *out, u32 cap, u32 want, u32 *on)
{
    u8 props[5] = { 0x5D };
    wr32(props + 1, cap < 4096 ? 4096 : cap);
    if (!k->lz && !(k->lz = gz_lzma_dec_new())) return GZ_E_NOMEM;
    sq_mio m = { 0, 0, 0, out, 0, cap, 0 };
    int r = gz_lzma_decode_mem(k->lz, props, in, n, want ? want : GZ_SIZE_UNKNOWN, mio_write, &m, 0);
    if (r && m.full && !want) {                       /* exactly cap bytes, no end marker */
        m.on = 0;
        m.full = 0;
        r = gz_lzma_decode_mem(k->lz, props, in, n, cap, mio_write, &m, 0);
    }
    *on = (u32)m.on;
    return r;
}

static u64 xz_vli(const u8 *p, u32 end, u32 *pos)
{
    u64 v = 0;
    for (u32 i = 0; i < 9 && *pos < end; i++) {
        u8 b = p[(*pos)++];
        v |= (u64)(b & 0x7F) << (7 * i);
        if (!(b & 0x80)) return (i && !b) ? ~(u64)0 : v;     /* no redundant zero bytes */
    }
    return ~(u64)0;
}

/* One xz stream (as written by liblzma's stream buffer encoder): blocks with LZMA2 and up
 * to three BCJ / Delta filters in front, integrity check verified; the index is ignored. */
static int dec_xz(sq_codec *k, const u8 *in, u32 n, u8 *out, u32 cap, u32 *on)
{
    static const u8 cklen[16] = { 0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64 };
    if (n < 24 || __builtin_memcmp(in, "\xFD" "7zXZ\0", 6) || in[6] || in[7] > 15) return GZ_E_DATA;
    if (gz_crc32(0, in + 6, 2) != rd32(in + 8)) return GZ_E_DATA;
    u32 ck = in[7], pos = 12;
    size_t total = 0;
    if (!k->lz && !(k->lz = gz_lzma_dec_new())) return GZ_E_NOMEM;
    while (pos < n && in[pos]) {                     /* 0x00: index indicator */
        u32 hs = (in[pos] + 1u) * 4, bstart = pos;
        if (hs > n - pos) return GZ_E_DATA;
        const u8 *h = in + pos;
        if (gz_crc32(0, h, hs - 4) != rd32(h + hs - 4)) return GZ_E_DATA;
        u32 fl = h[1], nf = (fl & 3) + 1, hp = 2, hend = hs - 4;
        if (fl & 0x3C) return GZ_E_METHOD;
        u64 csz = ~(u64)0, usz = ~(u64)0;
        if ((fl & 0x40) && (csz = xz_vli(h, hend, &hp)) == ~(u64)0) return GZ_E_DATA;
        if ((fl & 0x80) && (usz = xz_vli(h, hend, &hp)) == ~(u64)0) return GZ_E_DATA;
        int ft[3];
        u32 fp[3];
        u8 dprop = 0;
        for (u32 i = 0; i < nf; i++) {
            u64 id = xz_vli(h, hend, &hp), ps = xz_vli(h, hend, &hp);
            if (id == ~(u64)0 || ps > hend - hp) return GZ_E_DATA;
            if (i == nf - 1) {
                if (id != 0x21) return GZ_E_METHOD;
                if (ps != 1 || h[hp] > 40) return GZ_E_DATA;
                dprop = h[hp];
            } else {
                int t = gz_bcj_from_xz_id(id);
                if (!t) return GZ_E_METHOD;
                if (t == GZ_BCJ_DELTA) {
                    if (ps != 1) return GZ_E_DATA;
                    fp[i] = h[hp] + 1u;
                } else {
                    if (ps != 0 && ps != 4) return GZ_E_DATA;
                    fp[i] = ps ? rd32(h + hp) : 0;
                }
                ft[i] = t;
            }
            hp += (u32)ps;
        }
        for (; hp < hend; hp++) if (h[hp]) return GZ_E_DATA;
        pos += hs;
        size_t room = cap - total;
        if (usz != ~(u64)0 && usz > room) return GZ_E_DATA;
        while (dprop && gz_lzma2_dict_size((u8)(dprop - 1)) >= (room < 4096 ? 4096 : room)) dprop--;
        sq_mio m = { 0, 0, 0, out + total, 0, room, 0 };
        u64 used = 0;
        int r = gz_lzma2_decode_mem(k->lz, dprop, in + pos, n - pos, usz != ~(u64)0 ? usz : GZ_SIZE_UNKNOWN,
                                    mio_write, &m, &used);
        if (r) return r;
        if ((csz != ~(u64)0 && used != csz) || used > n - pos) return GZ_E_DATA;
        for (u32 i = nf - 1; i-- > 0;) {             /* filters in reverse chain order */
            gz_bcj f;
            gz_bcj_init(&f, ft[i], fp[i], 0);
            gz_bcj_code(&f, out + total, m.on);
        }
        pos += (u32)used;
        while ((pos - bstart) & 3) {                 /* block padding */
            if (pos >= n || in[pos]) return GZ_E_DATA;
            pos++;
        }
        u32 cl = cklen[ck];
        if (cl > n - pos) return GZ_E_DATA;
        const u8 *cv = in + pos, *ob = out + total;
        if (ck == 1 && gz_crc32(0, ob, m.on) != rd32(cv)) return GZ_E_CRC;
        if (ck == 4 && gz_crc64(0, ob, m.on) != rd64(cv)) return GZ_E_CRC;
        if (ck == 10) {
            u8 dg[32];
            gz_sha256_calc(ob, m.on, dg);
            if (__builtin_memcmp(dg, cv, 32)) return GZ_E_CRC;
        }
        pos += cl;
        total += m.on;
    }
    if (pos >= n) return GZ_E_DATA;                  /* no index: truncated stream */
    *on = (u32)total;
    return GZ_OK;
}

/* Decode one compressed block of in[0..n) into out (at most cap bytes; want = the exact size
 * when the caller knows it, else 0: only used where the stream itself cannot tell). */
static int sq_decomp(sq_codec *k, int comp, const u8 *in, u32 n, u8 *out, u32 cap, u32 want, u32 *on)
{
    *on = 0;
    switch (comp) {
    case C_GZIP: return gz_sqfs_zlib(&k->z, in, n, out, cap, on);
    case C_LZMA: return dec_lzma(k, in, n, out, cap, on);
    case C_LZMA_RAW: return dec_lzma_raw(k, in, n, out, cap, want, on);
    case C_MIXED: return n && in[0] == 0x5D ? dec_lzma(k, in, n, out, cap, on) : gz_sqfs_zlib(&k->z, in, n, out, cap, on);
    case C_XZ:   return dec_xz(k, in, n, out, cap, on);
    case C_LZO: {
        size_t o = 0, used = 0;
        int r = gz_lzo1x_decode(in, n, out, cap, &o, &used);
        if (!r && used != n) r = GZ_E_DATA;
        *on = (u32)o;
        return r;
    }
    case C_LZ4: return gz_lz4_block_decode(in, n, out, cap, on);
    case C_ZSTD: {
        if (!k->zs && !(k->zs = gz_zstd_dec_new())) return GZ_E_NOMEM;
        size_t o = 0;
        int r = gz_zstd_decode_mem(k->zs, in, n, out, cap, &o);
        *on = (u32)o;
        return r;
    }
    }
    return GZ_E_METHOD;
}

/* ================================================================ archive state */

typedef struct {
    u32 major, inodes, bs, blog, nfrag, nids;   /* 3.x: nids = uids + gids */
    u32 comp, flags;
    u32 nuids;               /* 3.x: uid table entries (gids follow in sq_priv.ids) */
    u8  be, check;           /* 3.x: big endian, marker byte after metadata headers */
    u64 root, bytes_used, id_tab, xattr_tab, ino_tab, dir_tab, frag_tab, lookup_tab, gid_tab;
} sq_sb;

typedef struct {
    sq_sb sb;
    u64 nonce;               /* reader cache key (with the priv address) */
    u8 *itab;                /* decoded inode table */
    size_t ilen;
    u8 *ftab;                /* fragment entries, 16 bytes each, little endian (NULL: unreadable) */
    u32 nfrag;
    u32 *ids;                /* uid/gid table (3.x: uids, then gids) */
    u32 nids;
} sq_priv;

/* image-endian loads (3.x big-endian images; 4.0 is always little endian) */
static u32 g16(const sq_sb *sb, const u8 *p) { return sb->be ? rd16be(p) : rd16(p); }
static u32 g32(const sq_sb *sb, const u8 *p) { return sb->be ? rd32be(p) : rd32(p); }
static u64 g64(const sq_sb *sb, const u8 *p) { return sb->be ? rd64be(p) : rd64(p); }

static int sb_check(const sq_sb *sb, u64 min_tab)
{
    return sb->blog >= 12 && sb->blog <= 20 && sb->bs == 1u << sb->blog && sb->ino_tab >= min_tab &&
           sb->ino_tab < sb->dir_tab && sb->dir_tab < sb->bytes_used;
}

static int sb_parse(const u8 *h, sq_sb *sb)
{
    __builtin_memset(sb, 0, sizeof *sb);
    if (rd32(h) != SQ_MAGIC || rd16(h + 28) != 4 || rd16(h + 30) != 0) return 0;
    sb->major = 4;
    sb->inodes = rd32(h + 4);
    sb->bs = rd32(h + 12);
    sb->nfrag = rd32(h + 16);
    sb->comp = rd16(h + 20);
    sb->blog = rd16(h + 22);
    sb->flags = rd16(h + 24);
    sb->nids = rd16(h + 26);
    sb->root = rd64(h + 32);
    sb->bytes_used = rd64(h + 40);
    sb->id_tab = rd64(h + 48);
    sb->xattr_tab = rd64(h + 56);
    sb->ino_tab = rd64(h + 64);
    sb->dir_tab = rd64(h + 72);
    sb->frag_tab = rd64(h + 80);
    sb->lookup_tab = rd64(h + 88);
    return sb_check(sb, 96);
}

/* 3.x superblock (packed, 119 bytes; byte-aligned fields, so big endian is a plain swap) */
static int sb_parse3(const u8 *h, sq_sb *sb)
{
    __builtin_memset(sb, 0, sizeof *sb);
    u32 m = rd32(h);
    sb->be = m == SQ_MAGIC_BE || m == SQ_MAGIC_LZ_BE;
    if (!sb->be && m != SQ_MAGIC && m != SQ_MAGIC_LZ) return 0;
    if (g16(sb, h + 28) != 3) return 0;
    sb->major = 3;
    sb->comp = (m == SQ_MAGIC_LZ || m == SQ_MAGIC_LZ_BE) ? C_MIXED : C_GZIP;
    sb->inodes = g32(sb, h + 4);
    sb->blog = g16(sb, h + 34);
    sb->flags = h[36];
    sb->check = (h[36] & 4) != 0;
    sb->nuids = h[37];
    sb->nids = (u32)h[37] + h[38];
    sb->root = g64(sb, h + 43);
    sb->bs = g32(sb, h + 51);
    sb->nfrag = g32(sb, h + 55);
    sb->bytes_used = g64(sb, h + 63);
    sb->id_tab = g64(sb, h + 71);
    sb->gid_tab = g64(sb, h + 79);
    sb->ino_tab = g64(sb, h + 87);
    sb->dir_tab = g64(sb, h + 95);
    sb->frag_tab = g64(sb, h + 103);
    sb->lookup_tab = g64(sb, h + 111);
    sb->xattr_tab = ~(u64)0;
    return sb_check(sb, 119);
}

static int sq_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 120) return 0;
    sq_sb sb;
    if (sb_parse(h, &sb) || sb_parse3(h, &sb)) return 95;
    u32 m = rd32(h);
    if (m == SQ_MAGIC || m == SQ_MAGIC_BE) {         /* other versions: say "unsupported" */
        u16 maj = m == SQ_MAGIC ? rd16(h + 28) : rd16be(h + 28);
        if (maj >= 1 && maj <= 4) return 40;
    }
    return 0;
}

/* ================================================================ per-thread reader */

typedef struct { u32 idx, len, age; u8 *p; } sq_fc;

typedef struct sq_rd {
    const void *owner;       /* archive (priv) the cached fragments belong to */
    u64 nonce;
    u32 bs;
    sq_codec k;
    u8 *win;                 /* compressed input window */
    u32 wcap, wlen;
    u64 woff;
    u8 *blk;                 /* one decoded block (bs bytes) */
    int blk_zero;            /* blk holds zeros (sparse blocks) */
    sq_fc fc[SQ_NFC];
    u32 tick;
} sq_rd;

static void *sq_rd_new(void) { return gz_alloc(sizeof(sq_rd)); }

static void rd_drop(sq_rd *rd)
{
    gz_free(rd->win);
    gz_free(rd->blk);
    for (int i = 0; i < SQ_NFC; i++) gz_free(rd->fc[i].p);
    __builtin_memset(rd->fc, 0, sizeof rd->fc);
    rd->win = rd->blk = 0;
    rd->wcap = rd->wlen = 0;
    rd->bs = 0;
}

static void sq_rd_free(void *p)
{
    sq_rd *rd = (sq_rd *)p;
    if (!rd) return;
    rd_drop(rd);
    codec_free(&rd->k);
    gz_free(rd);
}

/* Prepare a reader for archive pv: buffers for its block size, fragment cache only
 * kept when it belongs to the same archive. The input window is always dropped
 * (the caller's source may be a different view of the image). */
static int rd_bind(sq_rd *rd, const sq_priv *pv)
{
    rd->wlen = 0;
    if (rd->owner != (const void *)pv || rd->nonce != pv->nonce || rd->bs != pv->sb.bs) {
        if (rd->bs != pv->sb.bs) rd_drop(rd);
        for (int i = 0; i < SQ_NFC; i++) { rd->fc[i].idx = SQ_NOFRAG; rd->fc[i].len = 0; }
        rd->owner = pv;
        rd->nonce = pv->nonce;
    }
    if (!rd->win) {
        u32 bs = pv->sb.bs;
        rd->wcap = 2 * bs > SQ_WIN_MIN ? 2 * bs : SQ_WIN_MIN;
        rd->win = (u8 *)gz_alloc(rd->wcap);
        rd->blk = (u8 *)gz_alloc(bs > SQ_META ? bs : SQ_META);
        rd->blk_zero = 0;
        rd->bs = bs;
        if (!rd->win || !rd->blk) { rd_drop(rd); return GZ_E_NOMEM; }
    }
    return GZ_OK;
}

/* Bytes [off, off+len) of the image through the window; ahead = how much will be read
 * sequentially from off (read-ahead hint). */
static int rd_fetch(sq_rd *rd, gz_src *s, u64 off, u32 len, u64 ahead, const u8 **p)
{
    if (rd->wlen && off >= rd->woff && off - rd->woff <= rd->wlen && len <= rd->wlen - (off - rd->woff)) {
        *p = rd->win + (off - rd->woff);
        return GZ_OK;
    }
    if (len > rd->wcap) return GZ_E_DATA;
    if (off >= s->size || len > s->size - off) return GZ_E_TRUNC;
    u64 want = ahead > len ? ahead : len;
    if (want > rd->wcap) want = rd->wcap;
    if (want > s->size - off) want = s->size - off;
    rd->wlen = 0;
    int r = gz_src_read_exact(s, off, rd->win, (u32)want);
    if (r) return r;
    rd->woff = off;
    rd->wlen = (u32)want;
    *p = rd->win;
    return GZ_OK;
}

/* Decoded fragment block fi (cached). */
static int rd_frag(sq_rd *rd, const sq_priv *pv, gz_src *s, u32 fi, const u8 **p, u32 *n)
{
    if (!pv->ftab || fi >= pv->nfrag) return GZ_E_DATA;
    sq_fc *v = &rd->fc[0];
    for (int i = 0; i < SQ_NFC; i++) {
        sq_fc *f = &rd->fc[i];
        if (f->p && f->len && f->idx == fi) {
            f->age = ++rd->tick;
            *p = f->p;
            *n = f->len;
            return GZ_OK;
        }
        if (f->age < v->age) v = f;
    }
    const u8 *fe = pv->ftab + (size_t)fi * 16;
    u64 off = rd64(fe);
    u32 w = rd32(fe + 8), len = w & SQ_LENMASK, bs = pv->sb.bs;
    if (!len || len > bs) return GZ_E_DATA;
    v->idx = SQ_NOFRAG;
    v->len = 0;
    if (!v->p && !(v->p = (u8 *)gz_alloc(bs))) return GZ_E_NOMEM;
    const u8 *in;
    int r = rd_fetch(rd, s, off, len, len, &in);
    if (r) return r;
    u32 on = len;
    if (w & SQ_RAW) __builtin_memcpy(v->p, in, len);
    else if ((r = sq_decomp(&rd->k, (int)pv->sb.comp, in, len, v->p, bs, 0, &on))) return r;
    if (!on) return GZ_E_DATA;
    v->idx = fi;
    v->len = on;
    v->age = ++rd->tick;
    *p = v->p;
    *n = on;
    return GZ_OK;
}

/* ================================================================ metadata tables */

typedef struct {
    u8 *p;
    size_t n, cap;
    u32 *bd, *bo;            /* per block: disk offset (from the table start), decoded offset */
    u32 nb, bcap;
} sq_tab;

static void tab_free(sq_tab *t)
{
    gz_free(t->p);
    gz_free(t->bd);
    gz_free(t->bo);
    __builtin_memset(t, 0, sizeof *t);
}

/* Read one metadata block at off (absolute) into out (SQ_META bytes). */
static int meta_block(sq_rd *rd, gz_src *s, const sq_sb *sb, u64 off, u64 ahead, u8 *out, u32 *on, u32 *disk)
{
    const u8 *h;
    u32 hl = sb->check ? 3 : 2;                   /* 3.x check data: 0xFF marker after the length */
    int r = rd_fetch(rd, s, off, hl, ahead, &h);
    if (r) return r;
    u32 hv = g16(sb, h), len = hv & 0x7FFF;
    if (!len || len > SQ_META) return GZ_E_FORMAT;
    if ((r = rd_fetch(rd, s, off + hl, len, ahead > hl ? ahead - hl : 0, &h))) return r;
    *disk = hl + len;
    if (hv & 0x8000) {
        __builtin_memcpy(out, h, len);
        *on = len;
        return GZ_OK;
    }
    return sq_decomp(&rd->k, (int)sb->comp, h, len, out, SQ_META, 0, on);
}

/* Decode the metadata blocks in [start, end) one after the other. Stops quietly at the
 * first bad block (what was decoded stays usable); GZ_E_LIMIT above max bytes. */
static int tab_load(sq_rd *rd, gz_src *s, const sq_sb *sb, u64 start, u64 end, size_t max, gz_ctx *c, sq_tab *t)
{
    u64 off = start;
    while (off < end && end - off >= 3 && off - start <= 0xFFFFFFFFu) {
        if (gz_cancelled(c)) return GZ_E_CANCEL;
        if (t->n + SQ_META > max) return GZ_E_LIMIT;
        if (t->n + SQ_META > t->cap) {
            size_t nc = t->cap ? t->cap * 2 : 65536;
            if (nc > max) nc = max;
            u8 *np = (u8 *)gz_realloc(t->p, nc);
            if (!np) return GZ_E_NOMEM;
            t->p = np;
            t->cap = nc;
        }
        if (t->nb == t->bcap) {
            u32 nc = t->bcap ? t->bcap * 2 : 64;
            u32 *a = (u32 *)gz_realloc(t->bd, (size_t)nc * 4), *b = a ? (u32 *)gz_realloc(t->bo, (size_t)nc * 4) : 0;
            if (a) t->bd = a;
            if (!b) return GZ_E_NOMEM;
            t->bo = b;
            t->bcap = nc;
        }
        u32 on = 0, disk = 0;
        int r = meta_block(rd, s, sb, off, end - off, t->p + t->n, &on, &disk);
        if (r == GZ_E_NOMEM) return r;
        if (r) break;
        t->bd[t->nb] = (u32)(off - start);
        t->bo[t->nb] = (u32)t->n;
        t->nb++;
        t->n += on;
        off += disk;
    }
    return GZ_OK;
}

/* Position in the decoded table of (block, offset); 0 when invalid. */
static int tab_pos(const sq_tab *t, u32 blk, u32 off, size_t *pos)
{
    u32 lo = 0, hi = t->nb;
    while (lo < hi) {
        u32 mid = (lo + hi) / 2;
        if (t->bd[mid] < blk) lo = mid + 1; else hi = mid;
    }
    if (lo >= t->nb || t->bd[lo] != blk || off >= SQ_META) return 0;
    size_t p = (size_t)t->bo[lo] + off;
    if (p >= t->n) return 0;
    *pos = p;
    return 1;
}

/* Table behind an index of u64 block pointers (fragments, ids): bytes decoded bytes. */
static int idx_load(sq_rd *rd, gz_src *s, const sq_sb *sb, u64 idx_off, size_t bytes, u8 **out)
{
    *out = 0;
    u32 nblk = (u32)((bytes + SQ_META - 1) / SQ_META);
    if (!nblk) return GZ_OK;
    if (idx_off >= s->size || (u64)nblk * 8 > s->size - idx_off) return GZ_E_FORMAT;
    u64 *ix = (u64 *)gz_alloc((size_t)nblk * 8);
    u8 *buf = (u8 *)gz_alloc((size_t)nblk * SQ_META);
    int r = (ix && buf) ? gz_src_read_exact(s, idx_off, ix, nblk * 8) : GZ_E_NOMEM;
    for (u32 i = 0; !r && i < nblk; i++) {
        u32 on = 0, disk;
        size_t want = i + 1 < nblk ? SQ_META : bytes - (size_t)i * SQ_META;
        r = meta_block(rd, s, sb, g64(sb, (const u8 *)(ix + i)), SQ_META + 3, buf + (size_t)i * SQ_META, &on, &disk);
        if (!r && on != want) r = GZ_E_FORMAT;
    }
    gz_free(ix);
    if (r) { gz_free(buf); return r; }
    *out = buf;
    return GZ_OK;
}

/* ================================================================ inodes */

typedef struct {
    u32 type, mode, uid, gid, mtime;
    u64 size;                /* file size, directory listing size + 3, link length */
    u64 start;               /* file: first data block */
    u32 dblk, doff;          /* directory: listing position */
    u32 frag, foff;          /* file: fragment index and offset */
    u32 nblk;                /* file: entries in the block list */
    size_t list;             /* file: block list position; link: target position */
} sq_ino;

/* block count of a file: tail in a fragment, or one more partial block */
static int ino_blocks(sq_ino *x, u32 blog, size_t pos, u32 hl, size_t left)
{
    u64 nb = x->size >> blog;
    if (x->frag == SQ_NOFRAG && (x->size & ((1u << blog) - 1))) nb++;
    if (left < hl || nb > (left - hl) / 4) return GZ_E_FORMAT;
    x->nblk = (u32)nb;
    x->list = pos + hl;
    return GZ_OK;
}

static int ino_parse4(const u8 *T, size_t tn, size_t pos, u32 blog, sq_ino *x)
{
    const u8 *p = T + pos;
    size_t left = tn - pos;
    x->type = rd16(p);
    x->mode = rd16(p + 2) & 07777;
    x->uid = rd16(p + 4);
    x->gid = rd16(p + 6);
    x->mtime = rd32(p + 8);
    switch (x->type) {
    case T_DIR:
        if (left < 32) return GZ_E_FORMAT;
        x->dblk = rd32(p + 16);
        x->size = rd16(p + 24);
        x->doff = rd16(p + 26);
        return GZ_OK;
    case T_LDIR:
        if (left < 40) return GZ_E_FORMAT;
        x->size = rd32(p + 20);
        x->dblk = rd32(p + 24);
        x->doff = rd16(p + 34);
        return GZ_OK;
    case T_FILE:
        if (left < 32) return GZ_E_FORMAT;
        x->start = rd32(p + 16);
        x->frag = rd32(p + 20);
        x->foff = rd32(p + 24);
        x->size = rd32(p + 28);
        return ino_blocks(x, blog, pos, 32, left);
    case T_LFILE:
        if (left < 56) return GZ_E_FORMAT;
        x->start = rd64(p + 16);
        x->size = rd64(p + 24);
        x->frag = rd32(p + 44);
        x->foff = rd32(p + 48);
        return ino_blocks(x, blog, pos, 56, left);
    case T_LINK:
    case T_LLINK:
        if (left < 24) return GZ_E_FORMAT;
        x->size = rd32(p + 20);
        if (x->size > SQ_LINK_MAX || x->size > left - 24) return GZ_E_FORMAT;
        x->list = pos + 24;
        return GZ_OK;
    }
    return x->type >= 4 && x->type <= 14 ? GZ_OK : GZ_E_FORMAT;   /* devices, fifos, sockets */
}

/* 3.x: 4-bit type and 12-bit mode share 16 bits (bit fields from the top in big endian),
 * 8-bit uid / gid indexes, packed directory size / offset fields */
static int ino_parse3(const sq_sb *sb, const u8 *T, size_t tn, size_t pos, sq_ino *x)
{
    const u8 *p = T + pos;
    size_t left = tn - pos;
    u32 t = g16(sb, p), w, w2;
    x->type = sb->be ? t >> 12 : t & 15;
    x->mode = sb->be ? t & 0xFFF : t >> 4;
    x->uid = p[2];
    x->gid = p[3];
    x->mtime = g32(sb, p + 4);
    switch (x->type) {
    case T_DIR:                                       /* size:19 offset:13, start, parent */
        if (left < 28) return GZ_E_FORMAT;
        w = g32(sb, p + 16);
        x->size = sb->be ? w >> 13 : w & 0x7FFFF;
        x->doff = sb->be ? w & 0x1FFF : w >> 19;
        x->dblk = g32(sb, p + 20);
        return GZ_OK;
    case T_LDIR:                                      /* size:27 offset:13, start, i_count, parent */
        if (left < 31) return GZ_E_FORMAT;
        w = g32(sb, p + 16);
        w2 = g16(sb, p + 19);
        x->size = sb->be ? w >> 5 : w & 0x7FFFFFF;
        x->doff = sb->be ? w2 & 0x1FFF : w2 >> 3;
        x->dblk = g32(sb, p + 21);
        return GZ_OK;
    case T_FILE:
        if (left < 32) return GZ_E_FORMAT;
        x->start = g64(sb, p + 12);
        x->frag = g32(sb, p + 20);
        x->foff = g32(sb, p + 24);
        x->size = g32(sb, p + 28);
        return ino_blocks(x, sb->blog, pos, 32, left);
    case T_LFILE:
        if (left < 40) return GZ_E_FORMAT;
        x->start = g64(sb, p + 16);
        x->frag = g32(sb, p + 24);
        x->foff = g32(sb, p + 28);
        x->size = g64(sb, p + 32);
        return ino_blocks(x, sb->blog, pos, 40, left);
    case T_LINK:
        if (left < 18) return GZ_E_FORMAT;
        x->size = g16(sb, p + 16);
        if (x->size > left - 18) return GZ_E_FORMAT;
        x->list = pos + 18;
        return GZ_OK;
    }
    return x->type >= 4 && x->type <= 7 ? GZ_OK : GZ_E_FORMAT;
}

static int ino_parse(const sq_sb *sb, const u8 *T, size_t tn, size_t pos, sq_ino *x)
{
    __builtin_memset(x, 0, sizeof *x);
    x->frag = SQ_NOFRAG;
    if (pos > tn || tn - pos < 16) return GZ_E_FORMAT;
    return sb->major == 3 ? ino_parse3(sb, T, tn, pos, x) : ino_parse4(T, tn, pos, sb->blog, x);
}

/* ================================================================ open */

typedef struct {
    gz_archive *a;
    gz_ctx *c;
    sq_priv *pv;
    sq_tab it, dt;
    gz_fs1_tree t;
    gz_fs1_set seen;
    u64 scan;                /* block-list words left to sum for csize (hard-link bomb guard) */
    size_t names_max;        /* cap of a->raw (paths): deep trees x many links amplify names */
} sq_walk;

static void sq_close(gz_archive *a)
{
    sq_priv *pv = (sq_priv *)a->priv;
    if (!pv) return;
    gz_free(pv->itab);
    gz_free(pv->ftab);
    gz_free(pv->ids);
    gz_free(pv);
    a->priv = 0;
}

/* uid | gid << 32. 3.x: separate uid and gid tables, gid index 255 = same as uid */
static u64 owner(const sq_priv *pv, const sq_ino *x)
{
    u32 nu = pv->sb.major == 3 ? pv->sb.nuids : pv->nids, uid = 0, gid = 0;
    if (!pv->ids) return 0;
    if (x->uid < nu) uid = pv->ids[x->uid];
    if (pv->sb.major != 3) gid = x->gid < pv->nids ? pv->ids[x->gid] : 0;
    else if (x->gid == 255) gid = uid;
    else if (nu + x->gid < pv->nids) gid = pv->ids[nu + x->gid];
    return uid | (u64)gid << 32;
}

static int add_entry(sq_walk *w, i32 node, size_t ipos, const u8 *nm, u32 nl)
{
    sq_priv *pv = w->pv;
    sq_ino x;
    if (ino_parse(&pv->sb, w->it.p, w->it.n, ipos, &x)) return GZ_OK;          /* bad inode: skip */
    u32 kind = x.type > 7 ? x.type - 7 : x.type;
    if (kind > 3) return GZ_OK;                                               /* special files */
    if (w->a->raw_len > w->names_max) return GZ_E_LIMIT;
    gz_entry *e;
    int r = gz_fs1_add_entry(w->a, &w->t, node, nm, nl, GZ_NE_LEGACY, &e);
    if (r) return r;
    e->is_dir = kind == T_DIR;
    e->unix_mode = x.mode | (kind == T_DIR ? 0040000u : kind == T_FILE ? 0100000u : 0120000u);
    e->attr = (e->is_dir ? 0x10 : 0) | ((x.mode & 0200) ? 0 : 1);
    e->mtime = gz_unix_to_filetime(x.mtime);
    e->mtime_kind = GZ_MT_FILETIME;
    e->aux = owner(pv, &x);
    e->off = ipos;
    e->flags = (u16)x.type;
    if (kind == T_DIR) {
        int nw = gz_fs1_set_add(&w->seen, ipos);
        if (nw < 0) return GZ_E_NOMEM;
        if (nw && gz_fs1_tree_add(&w->t, node, nm, nl, GZ_NE_LEGACY, ipos, 0, 0) == -1) return GZ_E_NOMEM;
        return GZ_OK;
    }
    if (kind == T_LINK) {
        e->is_link = 1;
        if (!x.size) return GZ_OK;
        u32 lo;
        if ((r = gz_arc_raw_append(w->a, w->it.p + x.list, (size_t)x.size, &lo))) return r;
        e->link_off = lo;
        e->link_len = (u32)x.size;
        return GZ_OK;
    }
    /* regular file: packed size = its blocks (+ the fragment block for the file at offset 0,
     * as 7-Zip counts it); stored when no block / fragment is compressed */
    e->usize = x.size;
    u64 cs = 0;
    int packed = 0;
    if (x.nblk <= w->scan) {
        w->scan -= x.nblk;
        const u8 *bl = w->it.p + x.list;
        for (u32 i = 0; i < x.nblk; i++) {
            u32 bw = g32(&pv->sb, bl + 4 * i);
            cs += bw & SQ_LENMASK;
            if ((bw & SQ_LENMASK) && !(bw & SQ_RAW)) packed = 1;
        }
    } else {
        cs = GZ_SIZE_UNKNOWN;
        packed = 1;
    }
    if (x.frag != SQ_NOFRAG && (x.size & (pv->sb.bs - 1))) {
        if (pv->ftab && x.frag < pv->nfrag) {
            u32 fw = rd32(pv->ftab + (size_t)x.frag * 16 + 8);
            if (!(fw & SQ_RAW)) packed = 1;
            if (!x.foff && cs != GZ_SIZE_UNKNOWN) cs += fw & SQ_LENMASK;
        } else {
            packed = 1;
        }
    }
    e->csize = cs;
    e->method = packed ? (u16)pv->sb.comp : 0;
    return GZ_OK;
}

/* 3.x listing: headers of count:8, start, inode number (9 bytes); entries of offset:13,
 * type:3 (16 bits), name size - 1, inode number delta (5 bytes), name */
static int walk_dir3(sq_walk *w, i32 node, const u8 *p, const u8 *end)
{
    const sq_sb *sb = &w->pv->sb;
    size_t base = 0;
    while (end - p >= 9) {
        u32 cnt = p[0] + 1u;
        int ok = tab_pos(&w->it, g32(sb, p + 1), 0, &base);
        p += 9;
        for (u32 k = 0; k < cnt; k++) {
            if (end - p < 5) return GZ_E_FORMAT;
            u32 t = g16(sb, p), eo = sb->be ? t >> 3 : t & 0x1FFF, nl = p[2] + 1u;
            if (nl > (size_t)(end - p) - 5) return GZ_E_FORMAT;
            const u8 *nm = p + 5;
            p += 5 + nl;
            if (!ok || base + eo >= w->it.n) continue;
            int r = add_entry(w, node, base + eo, nm, nl);
            if (r) return r;
        }
    }
    return GZ_OK;
}

static int walk_dir(sq_walk *w, i32 node)
{
    sq_ino d;
    size_t ipos = (size_t)w->t.n[node].loc, pos, base = 0;
    if (ino_parse(&w->pv->sb, w->it.p, w->it.n, ipos, &d) || (d.type != T_DIR && d.type != T_LDIR))
        return GZ_E_FORMAT;
    if (d.size <= 3) return GZ_OK;
    if (!tab_pos(&w->dt, d.dblk, d.doff, &pos)) return GZ_E_FORMAT;
    u64 len = d.size - 3;
    if (len > w->dt.n - pos) len = w->dt.n - pos;
    const u8 *p = w->dt.p + pos, *end = p + len;
    if (w->pv->sb.major == 3) return walk_dir3(w, node, p, end);
    while (end - p >= 12) {
        u32 cnt = rd32(p) + 1, sblk = rd32(p + 4);
        p += 12;
        if (!cnt || cnt > SQ_DIR_COUNT) return GZ_E_FORMAT;
        int ok = tab_pos(&w->it, sblk, 0, &base);
        for (u32 k = 0; k < cnt; k++) {
            if (end - p < 8) return GZ_E_FORMAT;
            u32 eo = rd16(p), nl = rd16(p + 6) + 1u;
            if (nl > SQ_NAME_MAX || nl > (size_t)(end - p) - 8) return GZ_E_FORMAT;
            const u8 *nm = p + 8;
            p += 8 + nl;
            /* the inode may sit in a later block than its header names (offset >= 8192 is invalid) */
            if (!ok || eo >= SQ_META || base + eo >= w->it.n) continue;
            int r = add_entry(w, node, base + eo, nm, nl);
            if (r) return r;
        }
    }
    return GZ_OK;
}

static size_t tab_cap(u64 span)
{
    u64 m = span < SQ_TAB_MAX / SQ_RATIO ? span * SQ_RATIO : SQ_TAB_MAX;
    return m < (16u << 20) ? (16u << 20) : (size_t)m;
}

/* end of the directory table: the first structure written after it */
static u64 dir_end(gz_src *s, const sq_sb *sb)
{
    u64 lo = sb->dir_tab, end = sb->bytes_used < s->size ? sb->bytes_used : s->size;
    u64 cand[9];
    u32 nc = 0;
    u8 b[8];
    cand[nc++] = sb->frag_tab;
    cand[nc++] = sb->lookup_tab;
    cand[nc++] = sb->id_tab;
    cand[nc++] = sb->xattr_tab;
    if (sb->nfrag && sb->frag_tab < s->size && !gz_src_read_exact(s, sb->frag_tab, b, 8)) cand[nc++] = g64(sb, b);
    if (sb->lookup_tab < s->size && !gz_src_read_exact(s, sb->lookup_tab, b, 8)) cand[nc++] = g64(sb, b);
    if (sb->major == 3) {
        cand[nc++] = sb->gid_tab;                   /* plain uid / gid arrays */
    } else {
        if (sb->id_tab < s->size && !gz_src_read_exact(s, sb->id_tab, b, 8)) cand[nc++] = rd64(b);
        if (sb->xattr_tab < s->size && !gz_src_read_exact(s, sb->xattr_tab, b, 8)) cand[nc++] = rd64(b);
    }
    for (u32 i = 0; i < nc; i++) if (cand[i] > lo && cand[i] < end) end = cand[i];
    return end;
}

/* 3.x: plain uid and gid arrays (image endian) -> ids[uids..., gids...] */
static int ids_load3(sq_priv *pv, gz_src *s)
{
    const sq_sb *sb = &pv->sb;
    u32 nu = sb->nuids, n = sb->nids;
    if (!n) return GZ_OK;
    u32 *ids = (u32 *)gz_alloc((size_t)n * 4);
    if (!ids) return GZ_E_NOMEM;
    if ((nu && gz_src_read_exact(s, sb->id_tab, ids, nu * 4)) ||
        (n > nu && gz_src_read_exact(s, sb->gid_tab, ids + nu, (n - nu) * 4))) {
        gz_free(ids);
        return GZ_OK;                                  /* owners unknown */
    }
    for (u32 i = 0; i < n; i++) ids[i] = g32(sb, (const u8 *)(ids + i));
    pv->ids = ids;
    pv->nids = n;
    return GZ_OK;
}

static int sq_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    u8 h[120 + 2 + 64];
    int r = gz_src_read_exact(s, 0, h, s->size < 120 ? 96 : 120);
    if (r) return r;
    sq_priv *pv = (sq_priv *)gz_alloc(sizeof(sq_priv));
    if (!pv) return GZ_E_NOMEM;
    a->priv = pv;
    sq_sb *sb = &pv->sb;
    if (!sb_parse(h, sb) && (s->size < 120 || !sb_parse3(h, sb))) {
        u32 m = rd32(h);                               /* 1.x / 2.x: recognised, not supported */
        u16 maj = m == SQ_MAGIC ? rd16(h + 28) : rd16be(h + 28);
        return ((m == SQ_MAGIC || m == SQ_MAGIC_BE) && maj >= 1 && maj <= 3) ? GZ_E_METHOD : GZ_E_FORMAT;
    }
    if (!sb->comp || sb->comp >= C_ALL) return GZ_E_METHOD;
    if (sb->ino_tab >= s->size) return GZ_E_TRUNC;
    if (gz_plat_random(&pv->nonce, sizeof pv->nonce))
        pv->nonce = (u64)(uintptr_t)pv ^ ((u64)rd32(h + 8) << 32) ^ sb->bytes_used ^ s->size;
    if (sb->major == 4 && (sb->flags & F_COMP_OPT) && sb->comp == C_LZ4) {   /* compressor options */
        if (!gz_src_read_exact(s, 96, h + 96, 6)) {
            u32 hv = rd16(h + 96);
            if ((hv & 0x8000) && (hv & 0x7FFF) >= 4 && rd32(h + 98) != 1) return GZ_E_METHOD;   /* LZ4_LEGACY only */
        }
    }
    if (sb->major == 3 && sb->comp == C_GZIP) {
        /* raw LZMA variant: the first metadata block starts with 0 (a zlib stream never does) */
        u8 b[4];
        u32 hl = sb->check ? 3 : 2;
        if (!gz_src_read_exact(s, sb->ino_tab, b, hl + 1) && !(g16(sb, b) & 0x8000) && !b[hl]) sb->comp = C_LZMA_RAW;
    }
    gz_arc_set_type(a, "SquashFS");

    sq_rd tmp;
    __builtin_memset(&tmp, 0, sizeof tmp);
    sq_rd *rd = c ? (sq_rd *)gz_ctx_slot(c, GZ_SLOT_MISC1, sq_rd_new, sq_rd_free) : &tmp;
    if (!rd) return GZ_E_NOMEM;
    if ((r = rd_bind(rd, pv))) return r;

    sq_walk w;
    __builtin_memset(&w, 0, sizeof w);
    w.a = a; w.c = c; w.pv = pv;
    u64 dend = dir_end(s, sb);
    r = tab_load(rd, s, sb, sb->ino_tab, sb->dir_tab, tab_cap(sb->dir_tab - sb->ino_tab), c, &w.it);
    if (!r) r = tab_load(rd, s, sb, sb->dir_tab, dend, tab_cap(dend - sb->dir_tab), c, &w.dt);
    if (!r && !w.it.nb) r = GZ_E_FORMAT;
    w.names_max = s->size < SQ_NAMES_MAX / SQ_RATIO / 4 ? (size_t)s->size * SQ_RATIO * 4 + (16u << 20) : SQ_NAMES_MAX;
    /* fragment and id tables: optional for listing (files that need them fail later) */
    if (!r && sb->nfrag && (u64)sb->nfrag * 16 <= w.it.n + 65536) {
        int fr = idx_load(rd, s, sb, sb->frag_tab, (size_t)sb->nfrag * 16, &pv->ftab);
        if (fr == GZ_E_NOMEM) r = fr;
        if (pv->ftab) {
            pv->nfrag = sb->nfrag;
            if (sb->be)                                /* entries to little endian: start u64, size u32 */
                for (u32 i = 0; i < pv->nfrag; i++) {
                    u8 *fe = pv->ftab + (size_t)i * 16;
                    wr64(fe, rd64be(fe));
                    wr32(fe + 8, rd32be(fe + 8));
                }
        }
    }
    if (!r && sb->nids) {
        if (sb->major == 3) r = ids_load3(pv, s);
        else {
            int ir = idx_load(rd, s, sb, sb->id_tab, (size_t)sb->nids * 4, (u8 **)&pv->ids);
            if (ir == GZ_E_NOMEM) r = ir;
            if (pv->ids) pv->nids = sb->nids;
        }
    }
    size_t rpos = 0;
    if (!r && !tab_pos(&w.it, (u32)(sb->root >> 16), (u32)(sb->root & 0xFFFF), &rpos)) r = GZ_E_FORMAT;
    if (!r && (sb->root >> 48)) r = GZ_E_FORMAT;
    if (!r) r = gz_fs1_tree_init(&w.t, GZ_NE_LEGACY, GZ_CP_UTF8);
    if (!r) {
        w.t.n[0].loc = rpos;
        w.scan = w.it.n / 2 + 65536;
        if (gz_fs1_set_add(&w.seen, rpos) < 0) r = GZ_E_NOMEM;
    }
    for (u32 i = 0; !r && i < w.t.nn; i++) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        int rr = walk_dir(&w, (i32)i);
        if (rr == GZ_E_NOMEM || rr == GZ_E_CANCEL || rr == GZ_E_LIMIT || (rr && i == 0)) r = rr;
        if (c && c->progress && !(i & 63)) c->progress(c->progress_user, i, w.t.nn);
    }
    gz_fs1_tree_free(&w.t);
    gz_fs1_set_free(&w.seen);
    tab_free(&w.dt);
    if (!r) {
        /* keep the decoded inode table (block lists) for extraction */
        pv->itab = w.it.p;
        pv->ilen = w.it.n;
        w.it.p = 0;
    }
    tab_free(&w.it);
    if (rd == &tmp) { rd_drop(&tmp); codec_free(&tmp.k); }
    return r;
}

/* ================================================================ extraction */

static int sq_file(const sq_priv *pv, sq_rd *rd, gz_src *s, const gz_entry *e, gz_out *out, gz_ctx *c)
{
    sq_ino x;
    u32 bs = pv->sb.bs;
    if (ino_parse(&pv->sb, pv->itab, pv->ilen, (size_t)e->off, &x) || (x.type != T_FILE && x.type != T_LFILE))
        return GZ_E_FORMAT;
    if (x.size != e->usize) return GZ_E_FORMAT;
    const u8 *bl = pv->itab + x.list;
    u64 span = 0, pos = x.start, left = x.size;
    for (u32 i = 0; i < x.nblk; i++) span += g32(&pv->sb, bl + 4 * i) & SQ_LENMASK;
    int r = GZ_OK;
    for (u32 i = 0; i < x.nblk && !r; i++) {
        if (gz_cancelled(c)) return GZ_E_CANCEL;
        u32 bw = g32(&pv->sb, bl + 4 * i), len = bw & SQ_LENMASK;
        u32 want = left < bs ? (u32)left : bs;
        if (!len) {                                    /* sparse block */
            if (!rd->blk_zero) { __builtin_memset(rd->blk, 0, bs); rd->blk_zero = 1; }
            r = out->write(out, rd->blk, want);
        } else {
            const u8 *in;
            if (len > bs) return GZ_E_DATA;
            if ((r = rd_fetch(rd, s, pos, len, span, &in))) return r;
            if (bw & SQ_RAW) {
                if (len != want) return GZ_E_DATA;
                r = out->write(out, in, len);
            } else {
                u32 on = 0;
                rd->blk_zero = 0;
                if ((r = sq_decomp(&rd->k, (int)pv->sb.comp, in, len, rd->blk, bs, want, &on))) return r;
                if (on != want) return GZ_E_DATA;
                r = out->write(out, rd->blk, on);
            }
            pos += len;
            span -= len;
        }
        left -= want;
    }
    if (!r && left) {                                  /* tail in a fragment block */
        const u8 *fp;
        u32 fn;
        if (x.frag == SQ_NOFRAG) return GZ_E_DATA;
        if ((r = rd_frag(rd, pv, s, x.frag, &fp, &fn))) return r;
        if (x.foff > fn || left > fn - x.foff) return GZ_E_DATA;
        r = out->write(out, fp + x.foff, (size_t)left);
    }
    return r;
}

static int sq_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    const sq_priv *pv = (const sq_priv *)a->priv;
    const gz_entry *e = &a->e[idx];
    int r = out->open(out, idx);
    if (r) return r;
    if (e->is_dir || e->is_link || !e->usize) return out->close(out, idx, GZ_OK);
    sq_rd tmp;
    __builtin_memset(&tmp, 0, sizeof tmp);
    sq_rd *rd = c ? (sq_rd *)gz_ctx_slot(c, GZ_SLOT_MISC1, sq_rd_new, sq_rd_free) : &tmp;
    int st = rd ? rd_bind(rd, pv) : GZ_E_NOMEM;
    if (!st) st = sq_file(pv, rd, s, e, out, c);
    if (rd == &tmp) { rd_drop(&tmp); codec_free(&tmp.k); }
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static void sq_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    static const char *const nm[C_ALL] = { "Store", "Deflate", "LZMA", "LZO", "XZ", "LZ4", "Zstd", "LZMA", "LZMA" };
    (void)a;
    const char *m = e->method < C_ALL ? nm[e->method] : "?";
    u32 i = 0;
    for (; m[i] && i + 1 < cap; i++) buf[i] = m[i];
    if (cap) buf[i] = 0;
}

/* ================================================================ views */

typedef struct {
    gz_src s;
    gz_src *img;
    sq_priv pv;              /* copy of the superblock + this file's fragment entry only */
    u8 fent[16];
    sq_rd *rd;
    u64 *boff;               /* on-disk offset of each block */
    u32 *bw;                 /* size word of each block */
    u32 nblk, foff;
    i64 cur;                 /* block decoded in rd->blk, -1 = none */
} sq_view;

static int view_read(gz_src *src, u64 off, void *buf, u32 n, u32 *got)
{
    sq_view *v = (sq_view *)src;
    u8 *o = (u8 *)buf;
    u32 bs = v->pv.sb.bs, blog = v->pv.sb.blog;
    *got = 0;
    if (off >= src->size) return GZ_OK;
    if (n > src->size - off) n = (u32)(src->size - off);
    while (n) {
        u64 b = off >> blog;
        u32 in = (u32)(off & (bs - 1)), take;
        u64 bsz = src->size - (b << blog);
        u32 want = bsz < bs ? (u32)bsz : bs;           /* bytes this block holds */
        take = want - in < n ? want - in : n;
        int r = GZ_OK;
        if (b < v->nblk) {
            u32 w = v->bw[b], len = w & SQ_LENMASK;
            if (!len) {
                __builtin_memset(o, 0, take);
            } else if (w & SQ_RAW) {
                if (len != want) return GZ_E_DATA;
                if ((r = gz_src_read_exact(v->img, v->boff[b] + in, o, take))) return r;
            } else {
                if (v->cur != (i64)b) {
                    const u8 *p;
                    u32 on = 0;
                    v->cur = -1;
                    if (len > bs) return GZ_E_DATA;
                    if ((r = rd_fetch(v->rd, v->img, v->boff[b], len, len, &p))) return r;
                    if ((r = sq_decomp(&v->rd->k, (int)v->pv.sb.comp, p, len, v->rd->blk, bs, want, &on))) return r;
                    if (on != want) return GZ_E_DATA;
                    v->cur = (i64)b;
                }
                __builtin_memcpy(o, v->rd->blk + in, take);
            }
        } else {
            const u8 *fp;
            u32 fn;
            if ((r = rd_frag(v->rd, &v->pv, v->img, 0, &fp, &fn))) return r;
            if (v->foff > fn || want > fn - v->foff) return GZ_E_DATA;
            __builtin_memcpy(o, fp + v->foff + in, take);
        }
        o += take;
        off += take;
        n -= take;
        *got += take;
    }
    return GZ_OK;
}

static void view_free(gz_src *src)
{
    sq_view *v = (sq_view *)src;
    sq_rd_free(v->rd);
    gz_free(v->boff);
    gz_free(v->bw);
    gz_free(v);
}

static gz_src *sq_view_new(gz_archive *a, gz_src *s, u32 idx)
{
    const sq_priv *pv = (const sq_priv *)a->priv;
    const gz_entry *e = &a->e[idx];
    if (e->is_dir || e->is_link) return 0;
    if (!e->usize) return gz_src_sub(s, 0, 0);
    sq_ino x;
    if (ino_parse(&pv->sb, pv->itab, pv->ilen, (size_t)e->off, &x) || (x.type != T_FILE && x.type != T_LFILE))
        return 0;
    const u8 *bl = pv->itab + x.list;
    u32 bs = pv->sb.bs;
    int tail = (x.size & (bs - 1)) && x.frag != SQ_NOFRAG;
    /* all blocks stored and no fragment: the data is one contiguous run */
    int raw = !tail;
    for (u32 i = 0; raw && i < x.nblk; i++) {
        u32 w = g32(&pv->sb, bl + 4 * i), want = i + 1 < x.nblk ? bs : (u32)(x.size - ((u64)i << pv->sb.blog));
        if (!(w & SQ_RAW) || (w & SQ_LENMASK) != want) raw = 0;
    }
    if (raw) return x.start <= s->size && x.size <= s->size - x.start ? gz_src_sub(s, x.start, x.size) : 0;
    if (tail && (!pv->ftab || x.frag >= pv->nfrag)) return 0;
    if (x.nblk > (1u << 26)) return 0;
    sq_view *v = (sq_view *)gz_alloc(sizeof(sq_view));
    if (!v) return 0;
    v->s.read_at = view_read;
    v->s.size = x.size;
    v->s.free = view_free;
    v->img = s;
    v->pv.sb = pv->sb;
    v->pv.nonce = 0;
    v->cur = -1;
    v->nblk = x.nblk;
    v->foff = x.foff;
    if (tail) {                                        /* the view's fragment table: one entry */
        __builtin_memcpy(v->fent, pv->ftab + (size_t)x.frag * 16, 16);
        v->pv.ftab = v->fent;
        v->pv.nfrag = 1;
    }
    v->rd = (sq_rd *)sq_rd_new();
    v->boff = (u64 *)gz_alloc((size_t)x.nblk * 8 + 8);
    v->bw = (u32 *)gz_alloc((size_t)x.nblk * 4 + 4);
    if (!v->rd || !v->boff || !v->bw || rd_bind(v->rd, &v->pv)) { view_free(&v->s); return 0; }
    u64 p = x.start;
    for (u32 i = 0; i < x.nblk; i++) {
        v->bw[i] = g32(&pv->sb, bl + 4 * i);
        v->boff[i] = p;
        p += v->bw[i] & SQ_LENMASK;
    }
    return &v->s;
}

GZ_FORMAT(gz_fmt_squashfs)
const gz_format gz_fmt_squashfs = {
    "SquashFS", "sqfs squashfs squash sfs snap img", 0, sq_probe, sq_open, sq_close, sq_extract, 0, 0, sq_method,
    sq_view_new, 0
};
