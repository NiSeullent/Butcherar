/*
 * 고깃ZIP - ZIP writer
 *
 * Methods: Store (0), Deflate (8, levels 1-9, the default), BZip2 (12), LZMA (14: raw
 * LZMA after the 4-byte version/size header and the 5 property bytes, always with the
 * end-of-stream marker, flag bit 1) and PPMd var.I rev.1 (98, 7-Zip's parameters per
 * level). Level 0 = Store. o->dict_size overrides the LZMA dictionary, the PPMd model
 * size (MiB, 1..256) and the BZip2 block size (100 kB units, 1..9).
 *
 * Encryption (password bytes are UTF-8, as 7-Zip, Bandizip and WinZip do for AES; our
 * reader tries the ANSI code page and UTF-8):
 *   - WinZip AES-256, the default when a password is given: method 99 + extra 0x9901
 *     with the real method, 16-byte random salt, PBKDF2-HMAC-SHA1 x1000 -> AES key,
 *     HMAC key and the 2-byte password verifier, AES-CTR (little-endian counter from
 *     1), 10-byte HMAC-SHA1 code after the data. WinZip's convention: AE-2 (CRC field
 *     0) for files under 20 bytes so the CRC does not leak their content, AE-1 (CRC
 *     kept as an extra integrity check) otherwise.
 *   - ZipCrypto: 12-byte header of 10 random bytes + 2 check bytes (CRC bits 16-31,
 *     or the DOS time when the entry has a data descriptor, like Info-ZIP).
 *   Directories are never encrypted; empty files and symlinks are (like 7-Zip).
 *   Random bytes come from gz_plat_random in batches.
 *
 * Data flow per file:
 *   - Files of up to MEM_MAX (4 MiB) are read into memory and compressed into a
 *     buffer capped below their size; when compression does not make them smaller
 *     they are stored. Their local header is written once with the final CRC and
 *     sizes: no patching and no data descriptor, also on pipes.
 *   - Larger files (and files that turn out larger than announced) are streamed:
 *     local header, data, then the header is rewritten with gz_sink_patch. On an
 *     output without write_at the entry gets a data descriptor instead (flag bit 3,
 *     with signature; 8-byte sizes when the local header has a ZIP64 extra) and the
 *     compressed data is kept even if it did not shrink. Streamed ZipCrypto entries
 *     always get a descriptor: their check byte must be known before the data, so it
 *     comes from the DOS time.
 *     When a streamed file did not shrink and the output can be patched, the file is
 *     opened again and stored over its compressed data ("rewind and re-store", as
 *     7-Zip does). The sink cannot be truncated, so the write cursor then lags
 *     behind out->pos and the following entries are written through write_at into
 *     the freed bytes; whatever is left at the end becomes zero filler in front of
 *     the central directory (entries stay contiguous for streaming readers).
 *     A read error ends the entry with what was read and is reported to o->on_error
 *     afterwards; a failure before anything was written skips the item.
 *
 * ZIP64: local ZIP64 extra (both sizes) for files announced at >= 3.75 GiB or larger
 * than announced; central ZIP64 extra for sizes and offsets >= 4 GiB; ZIP64 end record
 * + locator for >= 65535 entries or a directory beyond 4 GiB. A file that grows past
 * 4 GiB although its local header has no ZIP64 extra fails with GZ_E_LIMIT.
 *
 * Names: UTF-8 with flag bit 11 when not plain ASCII (names that came from non-UTF-8
 * POSIX bytes, U+DC80..U+DCFF, are written back as those bytes without the flag).
 * With o->legacy_names: the system code page (gz_plat_acp) when the name converts
 * there and back exactly, plus the Info-ZIP Unicode Path extra 0x7075; otherwise UTF-8
 * with the flag.
 *
 * Times: the core has no time zone, so the DOS date/time fields hold the UTC time
 * (rounded up to 2 s, clamped to 1980..2107). The exact times are in the NTFS extra
 * 0x000A (mtime, atime, ctime; unknown ones = mtime) and the extended timestamp
 * 0x5455 (mtime + atime local, mtime central) that 7-Zip, Info-ZIP, WinZip, Bandizip
 * and our reader prefer; only tools that read nothing but the DOS fields show UTC.
 *
 * Attributes: Windows attributes (RO, hidden, system, directory, archive) in the low
 * byte; when the item has a unix mode (or is a symlink) the mode is in the high 16
 * bits and "version made by" says Unix (3), else MS-DOS (0). Directories end in '/'.
 * Symlinks: mode 0120000, the target (UTF-8) is the stored data. No archive comment.
 *
 * Single-threaded; the in-memory path (compress_mem) only touches its own buffers so
 * per-file parallel compression can be added on top of it.
 */
#include "gz_write.h"
#include "crc32.h"
#include "deflate_enc.h"
#include "lzma_enc.h"
#include "bzip2_enc.h"
#include "ppmd8.h"

#define SIG_LOCAL   0x04034b50u
#define SIG_CENTRAL 0x02014b50u
#define SIG_DESC    0x08074b50u
#define SIG_EOCD    0x06054b50u
#define SIG_EOCD64  0x06064b50u
#define SIG_LOC64   0x07064b50u

#define MEM_MAX   (4u << 20)          /* files up to this size are compressed in memory   */
#define IOBUF     (256u << 10)        /* streaming read / encryption chunk                */
#define CD_BLK    (256u << 10)        /* the central directory is collected in blocks     */
#define Z64_HINT  0xF0000000ull       /* announced sizes from here on: local ZIP64 extra  */
#define U32V      0xFFFFFFFFull
#define ZW_FULL   0x5A57              /* private: in-memory output reached the input size */
#define PW_MAX    4096u               /* password characters                              */
#define MADE_VER  63                  /* APPNOTE 6.3                                      */
#define DOS_MIN   0x00210000u         /* 1980-01-01 00:00:00                              */

typedef struct cdblk { struct cdblk *next; u32 n; u8 d[CD_BLK]; } cdblk;

typedef struct zent {
    const u8 *name; u32 nlen;     /* name bytes as stored in the headers                 */
    const u8 *uni; u32 ulen;      /* UTF-8 name for the Unicode Path extra, or NULL      */
    u32 name_crc;                 /* CRC-32 of name (Unicode Path extra)                 */
    u64 hdr_off;                  /* local header offset                                 */
    u64 usize, csize;             /* csize includes the encryption overhead              */
    u32 crc;
    u32 ext_attr;
    u16 made_by, method, flags;   /* method: the real one (Store when re-stored)         */
    u16 dtime, ddate;
    u8 enc;                       /* GZ_WE_* applied to this entry                       */
    u8 aes_ver;                   /* 1 = AE-1, 2 = AE-2                                  */
    u8 z64_local;                 /* local header has a ZIP64 extra                      */
    u8 desc;                      /* a data descriptor follows the data                  */
    u8 is_dir;
    u8 times;                     /* NTFS + UT extras present                            */
    u8 ut_flags;                  /* UT: bit 0 mtime, bit 1 atime                        */
    u8 pad_;
    u32 ut[2];
    u64 ft[3];                    /* NTFS: mtime, atime, ctime                           */
} zent;

typedef struct zw {
    const gz_wopts *o;
    gz_sink *out;
    gz_ctx *c;
    u64 wpos;                     /* write cursor: out->pos, or behind it after a re-store */
    int method, level, enc;       /* ZIP method for files (0 = store), level 1..9, GZ_WE_* */
    u8 *pw; u32 pwn;              /* password, UTF-8                                       */
    /* codecs: created on first use, reused for every file */
    gz_deflate_enc *defl;
    gz_bzip2_enc *bz;
    gz_lzma_enc *lz; u8 lz_props[5];
    gz_ppmd8 *ppmd;
    /* encryption of the current entry */
    int cenc;
    gz_zipcrypto zc;
    gz_hmac_sha1 hmac;
    gz_aes_ctr *aes;              /* 16-byte aligned inside aes_mem (heaps may give 8) */
    u8 *aes_mem;
    u8 rnd[512]; u32 rnd_pos;     /* random bytes pool                                     */
    /* buffers */
    u8 *ib; u32 icap;             /* in-memory input (+ one read chunk)                    */
    u8 *ob; u32 ocap;             /* in-memory compressed output                           */
    u8 *iob;                      /* streaming read / encryption chunk (IOBUF)             */
    u8 *nb; u32 ncap;             /* UTF-8 name                                            */
    u8 *lb; u32 lcap;             /* legacy (code page) name                               */
    u8 *wb; u32 wcap;             /* code page round-trip check (UTF-16)                   */
    u8 *hb; u32 hcap;             /* header assembly                                       */
    cdblk *cd, *cd_last;
    u64 cd_size, count;
    u64 total, done;
} zw;

/* codec input: an optional prefix already in memory (and CRC'd), then the source */
typedef struct zfeed {
    zw *z;
    gz_wsrc *src;                 /* NULL: prefix only / source exhausted                  */
    const u8 *pre; u32 pre_n;
    u32 crc;                      /* CRC-32 of everything delivered                         */
    u64 n;                        /* bytes delivered                                        */
    int err;                      /* read error: the input was cut here                     */
    int progress;                 /* count delivered bytes as progress                      */
} zfeed;

/* gz_stream_io context: feed first (zfeed_read casts ctx), codec output after */
typedef struct zpipe {
    zfeed f;
    u64 out_n;                    /* codec output bytes                                     */
    u8 *mem; u32 mem_cap;         /* in-memory output (cap: ZW_FULL), NULL = archive        */
} zpipe;

static int zw_cancelled(const zw *z)
{
    return (z->o->cancel && *z->o->cancel) || gz_cancelled(z->c);
}

static int grow(u8 **p, u32 *cap, u64 need)
{
    if (need <= *cap) return GZ_OK;
    if (need > (64u << 20)) return GZ_E_LIMIT;
    u64 nc = *cap ? *cap : 256;
    while (nc < need) nc *= 2;
    u8 *np = (u8 *)gz_realloc(*p, (size_t)nc);
    if (!np) return GZ_E_NOMEM;
    *p = np;
    *cap = (u32)nc;
    return GZ_OK;
}

static void wipe_free(u8 *p, u32 n)
{
    if (!p) return;
    volatile u8 *v = p;
    for (u32 i = 0; i < n; i++) v[i] = 0;
    gz_free(p);
}

/* UTF-16 -> UTF-8; lone U+DC80..U+DCFF stand for raw bytes of non-UTF-8 POSIX names */
static u32 w2u(const gzch *s, size_t n, u8 *o)
{
    u32 k = 0;
    for (size_t i = 0; i < n; i++) {
        u32 c = s[i];
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < n && s[i + 1] >= 0xDC00 && s[i + 1] < 0xE000) {
            c = 0x10000 + ((c - 0xD800) << 10) + (s[i + 1] - 0xDC00);
            i++;
        } else if (c >= 0xDC80 && c <= 0xDCFF) {
            o[k++] = (u8)(c - 0xDC00);
            continue;
        } else if (c >= 0xD800 && c < 0xE000) {
            c = 0xFFFD;
        }
        if (c < 0x80) o[k++] = (u8)c;
        else if (c < 0x800) { o[k++] = (u8)(0xC0 | (c >> 6)); o[k++] = (u8)(0x80 | (c & 63)); }
        else if (c < 0x10000) {
            o[k++] = (u8)(0xE0 | (c >> 12)); o[k++] = (u8)(0x80 | ((c >> 6) & 63)); o[k++] = (u8)(0x80 | (c & 63));
        } else {
            o[k++] = (u8)(0xF0 | (c >> 18)); o[k++] = (u8)(0x80 | ((c >> 12) & 63));
            o[k++] = (u8)(0x80 | ((c >> 6) & 63)); o[k++] = (u8)(0x80 | (c & 63));
        }
    }
    return k;
}

static int rnd(zw *z, u8 *p, u32 n)
{
    if (z->rnd_pos + n > sizeof z->rnd) {
        if (gz_plat_random(z->rnd, sizeof z->rnd)) return GZ_E_IO;
        z->rnd_pos = 0;
    }
    __builtin_memcpy(p, z->rnd + z->rnd_pos, n);
    __builtin_memset(z->rnd + z->rnd_pos, 0, n);
    z->rnd_pos += n;
    return GZ_OK;
}

static void progress(zw *z, u64 n)
{
    z->done += n;
    if (z->o->progress) z->o->progress(z->o->user, z->done, z->total);
}

/* ---------------- output ---------------- */

/* Write at the cursor: through write_at while it lags behind out->pos, then append. */
static int put(zw *z, const void *p, size_t n)
{
    gz_sink *k = z->out;
    const u8 *b = (const u8 *)p;
    if (z->wpos < k->pos) {
        u64 room = k->pos - z->wpos;
        size_t m = n < room ? n : (size_t)room;
        int r = gz_sink_patch(k, z->wpos, b, m);
        if (r) return r;
        z->wpos += m;
        b += m;
        n -= m;
    }
    if (!n) return GZ_OK;
    int r = gz_sink_write(k, b, n);
    if (!r) z->wpos += n;
    return r;
}

static void crypt_buf(zw *z, u8 *p, size_t n)
{
    if (z->cenc == GZ_WE_ZIPCRYPTO) {
        gz_zc_encrypt(&z->zc, p, n);
    } else if (z->cenc == GZ_WE_AES256) {
        gz_aes_ctr_kernel(z->aes, p, n);
        gz_hmac_update(&z->hmac, p, n);
    }
}

/* entry data: encrypted copy through iob (p is const) */
static int data_out(zw *z, const u8 *p, size_t n)
{
    if (!z->cenc) return put(z, p, n);
    while (n) {
        size_t k = n < IOBUF ? n : IOBUF;
        __builtin_memcpy(z->iob, p, k);
        crypt_buf(z, z->iob, k);
        int r = put(z, z->iob, k);
        if (r) return r;
        p += k;
        n -= k;
    }
    return GZ_OK;
}

static u32 enc_overhead(int enc) { return enc == GZ_WE_ZIPCRYPTO ? 12 : enc == GZ_WE_AES256 ? 28 : 0; }

/* encryption header of an entry; check = CRC, or DOS time << 16 with a descriptor */
static int enc_begin(zw *z, int enc, u32 check)
{
    z->cenc = enc;
    if (enc == GZ_WE_ZIPCRYPTO) {
        u8 h[12];
        if (rnd(z, h, 10)) return GZ_E_IO;
        h[10] = (u8)(check >> 16);
        h[11] = (u8)(check >> 24);
        gz_zc_init(&z->zc, z->pw, z->pwn);
        gz_zc_encrypt(&z->zc, h, 12);
        return put(z, h, 12);
    }
    if (enc == GZ_WE_AES256) {
        u8 h[18], dk[66];
        if (rnd(z, h, 16)) return GZ_E_IO;
        gz_pbkdf2_sha1(z->pw, z->pwn, h, 16, 1000, dk, sizeof dk);
        gz_aes_ctr_setup(z->aes, dk, 32);
        gz_hmac_init(&z->hmac, dk + 32, 32);
        h[16] = dk[64];
        h[17] = dk[65];
        volatile u8 *v = dk;
        for (u32 i = 0; i < sizeof dk; i++) v[i] = 0;
        return put(z, h, 18);
    }
    return GZ_OK;
}

static int enc_end(zw *z)
{
    int r = GZ_OK;
    if (z->cenc == GZ_WE_AES256) {
        u8 mac[20];
        gz_hmac_final(&z->hmac, mac);
        r = put(z, mac, 10);
    }
    z->cenc = 0;
    return r;
}

/* central directory, collected in blocks */
static int cd_add(zw *z, const u8 *p, u32 n)
{
    if (z->cd_size + n > ((u64)1 << 32)) return GZ_E_LIMIT;
    while (n) {
        cdblk *b = z->cd_last;
        if (!b || b->n == CD_BLK) {
            b = (cdblk *)gz_alloc(sizeof(cdblk));
            if (!b) return GZ_E_NOMEM;
            if (z->cd_last) z->cd_last->next = b;
            else z->cd = b;
            z->cd_last = b;
        }
        u32 k = CD_BLK - b->n < n ? CD_BLK - b->n : n;
        __builtin_memcpy(b->d + b->n, p, k);
        b->n += k;
        p += k;
        n -= k;
        z->cd_size += k;
    }
    return GZ_OK;
}

/* ---------------- headers ---------------- */

static u16 ver_needed(const zent *e)
{
    u16 v = 10;
    if (e->is_dir || e->method == 8 || e->enc == GZ_WE_ZIPCRYPTO) v = 20;
    if (e->z64_local || e->hdr_off >= U32V || e->usize >= U32V || e->csize >= U32V) v = 45;
    if (e->method == 12 && v < 46) v = 46;
    if (e->enc == GZ_WE_AES256 && v < 51) v = 51;
    if (e->method == 14 || e->method == 98) v = 63;
    return v;
}

static u32 crc_field(const zent *e)
{
    return (e->enc == GZ_WE_AES256 && e->aes_ver == 2) ? 0 : e->crc;
}

static u8 *put_extras(const zent *e, u8 *x, int central)
{
    if (e->times) {
        wr16(x, 0x000A); wr16(x + 2, 32); wr32(x + 4, 0); wr16(x + 8, 1); wr16(x + 10, 24);
        wr64(x + 12, e->ft[0]); wr64(x + 20, e->ft[1]); wr64(x + 28, e->ft[2]);
        x += 36;
        if (e->ut_flags) {
            u32 k = central ? 1 : 1 + ((e->ut_flags >> 1) & 1);
            wr16(x, 0x5455); wr16(x + 2, (u16)(1 + 4 * k));
            x[4] = e->ut_flags;
            wr32(x + 5, e->ut[0]);
            if (k == 2) wr32(x + 9, e->ut[1]);
            x += 5 + 4 * k;
        }
    }
    if (e->uni) {
        wr16(x, 0x7075); wr16(x + 2, (u16)(5 + e->ulen));
        x[4] = 1;
        wr32(x + 5, e->name_crc);
        __builtin_memcpy(x + 9, e->uni, e->ulen);
        x += 9 + e->ulen;
    }
    if (e->enc == GZ_WE_AES256) {
        wr16(x, 0x9901); wr16(x + 2, 7); wr16(x + 4, e->aes_ver);
        x[6] = 'A'; x[7] = 'E'; x[8] = 3;
        wr16(x + 9, e->method);
        x += 11;
    }
    return x;
}

/* bytes a header of e can take beyond the fixed part and the name */
static u32 extras_max(const zent *e) { return 20 + 28 + 36 + 13 + 9 + e->ulen + 11; }

static u32 local_hdr(const zent *e, u8 *h)
{
    u64 cs = e->desc ? 0 : e->csize, us = e->desc ? 0 : e->usize;
    int big = e->z64_local && !e->desc;
    wr32(h, SIG_LOCAL);
    wr16(h + 4, ver_needed(e));
    wr16(h + 6, e->flags);
    wr16(h + 8, e->enc == GZ_WE_AES256 ? 99 : e->method);
    wr16(h + 10, e->dtime);
    wr16(h + 12, e->ddate);
    wr32(h + 14, e->desc ? 0 : crc_field(e));
    wr32(h + 18, big ? 0xFFFFFFFFu : (u32)cs);
    wr32(h + 22, big ? 0xFFFFFFFFu : (u32)us);
    wr16(h + 26, (u16)e->nlen);
    __builtin_memcpy(h + 30, e->name, e->nlen);
    u8 *x0 = h + 30 + e->nlen, *x = x0;
    if (e->z64_local) {
        wr16(x, 1); wr16(x + 2, 16); wr64(x + 4, us); wr64(x + 12, cs);
        x += 20;
    }
    x = put_extras(e, x, 0);
    wr16(h + 28, (u16)(x - x0));
    return (u32)(x - h);
}

static u32 central_hdr(const zent *e, u8 *h)
{
    int zu = e->usize >= U32V, zc = e->csize >= U32V, zo = e->hdr_off >= U32V;
    wr32(h, SIG_CENTRAL);
    wr16(h + 4, e->made_by);
    wr16(h + 6, ver_needed(e));
    wr16(h + 8, e->flags);
    wr16(h + 10, e->enc == GZ_WE_AES256 ? 99 : e->method);
    wr16(h + 12, e->dtime);
    wr16(h + 14, e->ddate);
    wr32(h + 16, crc_field(e));
    wr32(h + 20, zc ? 0xFFFFFFFFu : (u32)e->csize);
    wr32(h + 24, zu ? 0xFFFFFFFFu : (u32)e->usize);
    wr16(h + 28, (u16)e->nlen);
    wr16(h + 32, 0);                    /* comment */
    wr16(h + 34, 0);                    /* disk    */
    wr16(h + 36, 0);                    /* internal attributes */
    wr32(h + 38, e->ext_attr);
    wr32(h + 42, zo ? 0xFFFFFFFFu : (u32)e->hdr_off);
    __builtin_memcpy(h + 46, e->name, e->nlen);
    u8 *x0 = h + 46 + e->nlen, *x = x0;
    if (zu || zc || zo) {
        wr16(x, 1); wr16(x + 2, (u16)(8 * (zu + zc + zo)));
        x += 4;
        if (zu) { wr64(x, e->usize); x += 8; }
        if (zc) { wr64(x, e->csize); x += 8; }
        if (zo) { wr64(x, e->hdr_off); x += 8; }
    }
    x = put_extras(e, x, 1);
    wr16(h + 30, (u16)(x - x0));
    return (u32)(x - h);
}

/* append the local header at the cursor, or rewrite it in place (same length) */
static int write_local(zw *z, const zent *e, int patch)
{
    int r = grow(&z->hb, &z->hcap, 46 + (u64)e->nlen + extras_max(e));
    if (r) return r;
    u32 n = local_hdr(e, z->hb);
    return patch ? gz_sink_patch(z->out, e->hdr_off, z->hb, n) : put(z, z->hb, n);
}

static int add_central(zw *z, const zent *e)
{
    int r = grow(&z->hb, &z->hcap, 46 + (u64)e->nlen + extras_max(e));
    if (r) return r;
    r = cd_add(z, z->hb, central_hdr(e, z->hb));
    if (!r) z->count++;
    return r;
}

static int write_desc(zw *z, const zent *e)
{
    u8 d[24];
    wr32(d, SIG_DESC);
    wr32(d + 4, crc_field(e));
    if (e->z64_local) {
        wr64(d + 8, e->csize);
        wr64(d + 16, e->usize);
        return put(z, d, 24);
    }
    wr32(d + 8, (u32)e->csize);
    wr32(d + 12, (u32)e->usize);
    return put(z, d, 16);
}

static void set_method_flags(zw *z, zent *e)
{
    e->flags &= (u16)~6u;
    if (e->method == 8) e->flags |= z->level >= 8 ? 2 : z->level == 2 ? 4 : z->level == 1 ? 6 : 0;
    else if (e->method == 14) e->flags |= 2;          /* end-of-stream marker */
}

/* ---------------- entry metadata ---------------- */

/* FILETIME (UTC) -> DOS date << 16 | time, rounded up to 2 s, clamped to 1980..2107 */
static u32 ft_to_dos(u64 ft)
{
    if (!ft) return DOS_MIN;
    u64 s = ft / 10000000u + (ft % 10000000u != 0);
    s += s & 1;
    if (s < 11644473600ull + 315532800ull) return DOS_MIN;
    u64 t = s - 11644473600ull;
    u64 days = t / 86400, sod = t % 86400;
    /* civil from days (Howard Hinnant) */
    u64 zd = days + 719468, era = zd / 146097, doe = zd - era * 146097;
    u64 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    u64 doy = doe - (365 * yoe + yoe / 4 - yoe / 100), mp = (5 * doy + 2) / 153;
    u32 d = (u32)(doy - (153 * mp + 2) / 5 + 1), m = (u32)(mp < 10 ? mp + 3 : mp - 9);
    u64 y = yoe + era * 400 + (m <= 2);
    if (y > 2107) return (127u << 25) | (12u << 21) | (31u << 16) | (23u << 11) | (59u << 5) | 29u;
    return ((u32)(y - 1980) << 25) | (m << 21) | (d << 16) | ((u32)(sod / 3600) << 11) |
           ((u32)(sod / 60 % 60) << 5) | (u32)(sod % 60 / 2);
}

static int unix32(u64 ft, u32 *out)
{
    i64 t = gz_filetime_to_unix(ft);
    if (t < -2147483647 - 1 || t > 2147483647) return 0;
    *out = (u32)(i32)t;
    return 1;
}

static void set_times(zent *e, const gz_witem *it)
{
    u32 dos = ft_to_dos(it->mtime);
    e->dtime = (u16)dos;
    e->ddate = (u16)(dos >> 16);
    if (!it->mtime) return;
    e->times = 1;
    e->ft[0] = it->mtime;
    e->ft[1] = it->atime ? it->atime : it->mtime;
    e->ft[2] = it->ctime ? it->ctime : it->mtime;
    if (unix32(it->mtime, &e->ut[0])) {
        e->ut_flags = 1;
        if (it->atime && unix32(it->atime, &e->ut[1])) e->ut_flags |= 2;
    }
}

static void set_attrs(zent *e, const gz_witem *it, int is_dir, int is_link)
{
    u32 attr = it->attr & 0x27;                      /* RO, hidden, system, archive */
    if (is_dir) attr |= 0x10;
    if (it->unix_mode || is_link) {
        u32 perm = it->unix_mode & 07777;
        if (!perm) perm = is_link ? 0777 : is_dir ? 0755 : (attr & 1) ? 0444 : 0644;
        if (!(perm & 0200)) attr |= 1;
        u32 mode = (is_link ? 0120000u : is_dir ? 0040000u : 0100000u) | perm;
        e->made_by = (3 << 8) | MADE_VER;
        e->ext_attr = (mode << 16) | attr;
    } else {
        e->made_by = MADE_VER;                       /* MS-DOS / FAT, like 7-Zip on Windows */
        e->ext_attr = attr;
    }
}

static int is_ascii(const u8 *p, u32 n)
{
    for (u32 i = 0; i < n; i++) if (p[i] & 0x80) return 0;
    return 1;
}

/* Header name of an item; GZ_E_SKIP for an empty name. */
static int make_name(zw *z, zent *e, const gzch *nm, int is_dir)
{
    while (*nm == '/') nm++;
    while (nm[0] == '.' && nm[1] == '/') { nm += 2; while (*nm == '/') nm++; }
    size_t n = gz_wcslen(nm);
    while (n && nm[n - 1] == '/') n--;
    if (!n || (n == 1 && nm[0] == '.')) return GZ_E_SKIP;
    if (n > 65535) return GZ_E_LIMIT;
    int r = grow(&z->nb, &z->ncap, (u64)n * 3 + 2);
    if (r) return r;
    u32 len = w2u(nm, n, z->nb);
    if (is_dir) z->nb[len++] = '/';
    if (len > 65535) return GZ_E_LIMIT;
    e->name = z->nb;
    e->nlen = len;
    if (is_ascii(z->nb, len)) return GZ_OK;
    int acp = gz_plat_acp();
    if (z->o->legacy_names && acp != GZ_CP_UTF8 && (u64)len + extras_max(e) <= 65535) {
        u32 cap = (u32)n * 4 + 8;
        if (!(r = grow(&z->lb, &z->lcap, cap)) && !(r = grow(&z->wb, &z->wcap, ((u64)n + 8) * 2))) {
            int k = gz_plat_wc2mb(acp, nm, (int)n, z->lb, (int)cap - 2);
            if (k > 0 && k + 1 < (int)cap &&
                gz_plat_mb2wc(acp, z->lb, k, (gzch *)z->wb, (int)n + 8) == (int)n &&
                !__builtin_memcmp(z->wb, nm, n * sizeof(gzch))) {
                if (is_dir) z->lb[k++] = '/';
                if (k <= 65535) {
                    e->name = z->lb;
                    e->nlen = (u32)k;
                    e->uni = z->nb;
                    e->ulen = len;
                    e->name_crc = gz_crc32(0, z->lb, (size_t)k);
                    return GZ_OK;
                }
            }
        } else if (r == GZ_E_NOMEM) {
            return r;
        }
    }
    if (gz_utf8_valid(z->nb, len)) e->flags |= 0x800;
    return GZ_OK;
}

/* ---------------- codecs ---------------- */

static int zfeed_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    zfeed *f = (zfeed *)ctx;
    u32 g = 0;
    *got = 0;
    if (zw_cancelled(f->z)) return GZ_E_CANCEL;
    if (f->n < f->pre_n) {
        u32 left = f->pre_n - (u32)f->n;
        g = left < cap ? left : cap;
        __builtin_memcpy(buf, f->pre + f->n, g);
    } else if (f->src) {
        int r = f->src->read(f->src, buf, cap, &g);
        if (r == GZ_E_CANCEL) return r;
        if (r) { f->err = r; g = 0; }          /* end the entry here, report it afterwards */
        if (g > cap) g = cap;
        if (!g) f->src = 0;                    /* never read an exhausted source again */
        f->crc = gz_crc32(f->crc, buf, g);
    }
    f->n += g;
    if (f->progress && g) progress(f->z, g);
    *got = g;
    return GZ_OK;
}

static int zpipe_write(void *ctx, const u8 *p, size_t n)
{
    zpipe *pp = (zpipe *)ctx;
    if (pp->mem) {
        if (n > pp->mem_cap - pp->out_n) return ZW_FULL;
        __builtin_memcpy(pp->mem + pp->out_n, p, n);
        pp->out_n += n;
        return GZ_OK;
    }
    pp->out_n += n;
    return data_out(pp->f.z, p, n);
}

/* LZMA encoder for an input of about hint bytes (0 = unknown); reused while the
 * resulting dictionary (and so the match finder tables) stays the same */
static int lzma_get(zw *z, u64 hint, gz_lzma_enc **out)
{
    gz_lzma_enc_opts lo;
    gz_lzma_enc_opts_init(&lo, z->level);
    if (z->o->dict_size) lo.dict_size = z->o->dict_size;
    lo.size_hint = hint;
    int r = gz_lzma_enc_check(&lo, 0);
    if (r) return r;
    gz_lzma_enc *e = gz_lzma_enc_new(&lo);
    if (!e) return GZ_E_NOMEM;
    u8 p[5];
    gz_lzma_enc_props(e, p);
    if (z->lz && !__builtin_memcmp(p, z->lz_props, 5)) {
        gz_lzma_enc_free(e);
    } else {
        gz_lzma_enc_free(z->lz);
        z->lz = e;
        __builtin_memcpy(z->lz_props, p, 5);
    }
    *out = z->lz;
    return GZ_OK;
}

/* run the method's encoder over io (hint: input size, 0 = unknown) */
static int encode(zw *z, int method, const gz_stream_io *io, u64 hint)
{
    const gz_wopts *o = z->o;
    int r;
    switch (method) {
    case 8:
        if (!z->defl && !(z->defl = gz_deflate_enc_new(z->level))) return GZ_E_NOMEM;
        return gz_deflate_encode(z->defl, io, 0, 0, 0);
    case 12:
        if (!z->bz) {
            int bl = z->level >= 5 ? 9 : z->level * 2 - 1;
            if (o->dict_size) bl = o->dict_size >= 900000 ? 9 : o->dict_size < 100000 ? 1 : (int)(o->dict_size / 100000);
            if (!(z->bz = gz_bzip2_enc_new(bl))) return GZ_E_NOMEM;
        }
        return gz_bzip2_encode(z->bz, io);
    case 14: {
        gz_lzma_enc *e;
        if ((r = lzma_get(z, hint, &e)) != GZ_OK) return r;
        u8 h[9] = { 9, 20, 5, 0 };              /* LZMA SDK version, property size */
        __builtin_memcpy(h + 4, z->lz_props, 5);
        if ((r = io->write(io->ctx, h, 9)) != GZ_OK) return r;
        return gz_lzma_encode(e, io, 0, 1);
    }
    case 98: {
        u32 order, mem, restore;
        if (!z->ppmd && !(z->ppmd = gz_ppmd8_new())) return GZ_E_NOMEM;
        gz_ppmd8_zip_level(z->level, hint ? hint : GZ_SIZE_UNKNOWN, &order, &mem, &restore);
        if (o->dict_size) mem = o->dict_size >= (256u << 20) ? 256 : o->dict_size < (1u << 20) ? 1 : o->dict_size >> 20;
        return gz_ppmd8_zip_encode(z->ppmd, order, mem, restore, io);
    }
    }
    return GZ_E_METHOD;
}

/* ---------------- entries ---------------- */

static int item_error(zw *z, const gz_witem *it, int err)
{
    if (err == GZ_E_CANCEL) return err;
    return z->o->on_error ? z->o->on_error(z->o->user, it, err) : err;
}

/* entry whose (final) data is in memory: data is encrypted in place */
static int emit_mem(zw *z, zent *e, u8 *data, u32 dn)
{
    e->aes_ver = e->usize < 20 ? 2 : 1;
    e->csize = (u64)dn + enc_overhead(e->enc);
    set_method_flags(z, e);
    e->hdr_off = z->wpos;
    int r = write_local(z, e, 0);
    if (!r) r = enc_begin(z, e->enc, e->crc);
    if (!r && dn) {
        crypt_buf(z, data, dn);
        r = put(z, data, dn);
    }
    if (!r) r = enc_end(z);
    if (!r) r = add_central(z, e);
    return r;
}

/* Compress in[0..n) into z->ob. GZ_OK: *out_n < n bytes; ZW_FULL: does not shrink. */
static int compress_mem(zw *z, const u8 *in, u32 n, u32 *out_n)
{
    if (n < 2) { if (n) progress(z, n); return ZW_FULL; }
    int r = grow(&z->ob, &z->ocap, n);
    if (r) return r;
    zpipe pp;
    __builtin_memset(&pp, 0, sizeof pp);
    pp.f.z = z;
    pp.f.pre = in;
    pp.f.pre_n = n;
    pp.f.progress = 1;
    pp.mem = z->ob;
    pp.mem_cap = n - 1;
    gz_stream_io io = { zfeed_read, zpipe_write, &pp };
    r = encode(z, z->method, &io, n);
    if (pp.f.n < n) progress(z, n - pp.f.n);         /* what the encoder did not pull */
    if (r) return r;
    *out_n = (u32)pp.out_n;
    return GZ_OK;
}

/* Read the whole file into z->ib while it fits MEM_MAX. *eof = 0: more data follows. */
static int read_mem(zw *z, gz_wsrc *src, u64 hint, u32 *n_out, u32 *crc_out, int *eof)
{
    u32 n = 0, crc = 0;
    u64 first = hint + 1 < 4096 ? 4096 : hint + 1;
    int r = grow(&z->ib, &z->icap, first < MEM_MAX ? first : MEM_MAX);
    *eof = 0;
    while (!r) {
        if (zw_cancelled(z)) return GZ_E_CANCEL;
        if (n == z->icap) {
            if (z->icap >= MEM_MAX + IOBUF) break;
            u64 nc = (u64)z->icap * 2;
            if (nc > MEM_MAX + IOBUF) nc = MEM_MAX + IOBUF;
            if ((r = grow(&z->ib, &z->icap, nc)) != GZ_OK) break;
        }
        u32 want = z->icap - n, got = 0;
        if (want > IOBUF) want = IOBUF;
        r = src->read(src, z->ib + n, want, &got);
        if (r) break;
        if (!got) { *eof = 1; break; }
        if (got > want) got = want;
        crc = gz_crc32(crc, z->ib + n, got);
        n += got;
        if (n > MEM_MAX) break;
    }
    *n_out = n;
    *crc_out = crc;
    return r;
}

/* store pass over a source: read into iob, encrypt in place, write */
static int copy_stored(zw *z, zfeed *f, u64 *out_n)
{
    for (;;) {
        u32 got = 0;
        int r = zfeed_read(f, z->iob, IOBUF, &got);
        if (r) return r;
        if (!got) return GZ_OK;
        crypt_buf(z, z->iob, got);
        if ((r = put(z, z->iob, got)) != GZ_OK) return r;
        *out_n += got;
    }
}

/* Read the item again and store it over its compressed data (output must be patchable). */
static int restore(zw *z, zent *e, const gz_witem *it, u64 data_off, u64 *raw, int *rd_err)
{
    const gz_wopts *o = z->o;
    gz_wsrc *src = 0;
    int r = o->open_item(o->user, it, &src);
    if (r == GZ_E_CANCEL) return r;
    if (r || !src) return GZ_OK;              /* cannot read it again: keep the compressed data */
    z->wpos = data_off;                       /* the cursor now lags behind out->pos */
    zfeed f;
    __builtin_memset(&f, 0, sizeof f);
    f.z = z;
    f.src = src;
    u64 n = 0;
    r = enc_begin(z, e->enc, (u32)e->dtime << 16);    /* fresh salt / random header */
    if (!r) r = copy_stored(z, &f, &n);
    o->close_item(o->user, it, src);
    if (!r) r = enc_end(z);
    if (r) return r;
    e->method = 0;
    e->crc = f.crc;
    e->usize = f.n;
    *raw = n;
    *rd_err = f.err;
    set_method_flags(z, e);
    return GZ_OK;
}

/* streamed file: src (owned, closed here) after pre_n bytes already in z->ib */
static int file_stream(zw *z, zent *e, const gz_witem *it, gz_wsrc *src, u32 pre_n, u32 pre_crc)
{
    const gz_wopts *o = z->o;
    int can_patch = z->out->write_at != 0;
    int hint_bad = pre_n > it->size;               /* larger than announced */
    u64 hint = hint_bad ? 0 : it->size;
    e->method = (u16)z->method;
    e->desc = !can_patch || e->enc == GZ_WE_ZIPCRYPTO;
    if (e->desc) e->flags |= 8;
    e->z64_local = hint_bad || it->size >= Z64_HINT;
    e->aes_ver = 1;
    set_method_flags(z, e);
    e->hdr_off = z->wpos;
    int r = write_local(z, e, 0);
    u64 data_off = z->wpos;
    if (!r) r = enc_begin(z, e->enc, (u32)e->dtime << 16);

    zpipe pp;
    __builtin_memset(&pp, 0, sizeof pp);
    pp.f.z = z;
    pp.f.src = src;
    pp.f.pre = z->ib;
    pp.f.pre_n = pre_n;
    pp.f.crc = pre_crc;
    pp.f.progress = 1;
    if (!r) {
        if (e->method) {
            gz_stream_io io = { zfeed_read, zpipe_write, &pp };
            r = encode(z, e->method, &io, hint);
        } else {
            r = copy_stored(z, &pp.f, &pp.out_n);
        }
    }
    o->close_item(o->user, it, src);
    if (!r) r = enc_end(z);
    if (r) return r;
    u64 raw = pp.out_n;
    int rd_err = pp.f.err;
    e->crc = pp.f.crc;
    e->usize = pp.f.n;
    if (can_patch && e->method && raw >= e->usize && !rd_err &&
        (r = restore(z, e, it, data_off, &raw, &rd_err)) != GZ_OK)
        return r;
    e->csize = raw + enc_overhead(e->enc);
    if (!e->z64_local && (e->usize >= U32V || e->csize >= U32V)) return GZ_E_LIMIT;
    if (e->desc) r = write_desc(z, e);
    if (!r && can_patch) r = write_local(z, e, 1);
    if (!r) r = add_central(z, e);
    if (!r && rd_err) r = item_error(z, it, rd_err);   /* the entry holds what could be read */
    return r;
}

static int write_item(zw *z, const gz_witem *it)
{
    const gz_wopts *o = z->o;
    int is_link = it->is_link && it->link_target;
    int is_dir = !is_link && it->is_dir;
    zent e;
    __builtin_memset(&e, 0, sizeof e);
    int r = make_name(z, &e, it->name, is_dir);
    if (r == GZ_E_SKIP) return GZ_OK;
    if (r) return r == GZ_E_LIMIT ? item_error(z, it, r) : r;
    e.is_dir = (u8)is_dir;
    set_times(&e, it);
    set_attrs(&e, it, is_dir, is_link);
    e.enc = is_dir ? GZ_WE_NONE : (u8)z->enc;
    if (e.enc) e.flags |= 1;

    if (is_dir) return emit_mem(z, &e, 0, 0);
    if (is_link) {
        size_t tn = gz_wcslen(it->link_target);
        if (tn > MEM_MAX / 3) return item_error(z, it, GZ_E_LIMIT);
        if ((r = grow(&z->ib, &z->icap, (u64)tn * 3 + 1)) != GZ_OK) return r;
        u32 n = w2u(it->link_target, tn, z->ib);
        e.usize = n;
        e.crc = gz_crc32(0, z->ib, n);
        return emit_mem(z, &e, z->ib, n);
    }

    gz_wsrc *src = 0;
    r = o->open_item ? o->open_item(o->user, it, &src) : GZ_E_IO;
    if (!r && !src) r = GZ_E_IO;
    if (r) return item_error(z, it, r);
    u32 n = 0, crc = 0;
    int eof = 0;
    if (it->size <= MEM_MAX) {
        r = read_mem(z, src, it->size, &n, &crc, &eof);
        if (r) {
            o->close_item(o->user, it, src);
            return r == GZ_E_NOMEM ? r : item_error(z, it, r);   /* nothing written yet */
        }
    }
    if (!eof) return file_stream(z, &e, it, src, n, crc);
    o->close_item(o->user, it, src);
    e.usize = n;
    e.crc = crc;
    u32 cn = 0;
    r = z->method ? compress_mem(z, z->ib, n, &cn) : ZW_FULL;
    if (r == GZ_OK) {
        e.method = (u16)z->method;
        return emit_mem(z, &e, z->ob, cn);
    }
    if (r != ZW_FULL) return r;
    if (!z->method && n) progress(z, n);
    return emit_mem(z, &e, z->ib, n);
}

/* ---------------- archive ---------------- */

static int zero_fill(zw *z, u64 n)
{
    __builtin_memset(z->iob, 0, IOBUF);
    while (n) {
        u32 k = n < IOBUF ? (u32)n : IOBUF;
        int r = put(z, z->iob, k);
        if (r) return r;
        n -= k;
    }
    return GZ_OK;
}

static int finish(zw *z)
{
    gz_sink *k = z->out;
    int r;
    int z64 = z->count >= 0xFFFF || z->cd_size >= U32V || z->wpos >= U32V;
    u64 gap = k->pos - z->wpos;
    if (gap > z->cd_size + 22 + (z64 ? 76 : 0)) {
        /* the cursor lags behind (re-stored files): filler in front of the directory so
         * the end record is the last thing in the file. The ZIP64 end records are written
         * then, so the tail size does not depend on where the directory lands. */
        z64 = 1;
        u64 tail = z->cd_size + 22 + 76;
        if (gap > tail && (r = zero_fill(z, gap - tail)) != GZ_OK) return r;
    }
    u64 cd_off = z->wpos;
    for (cdblk *b = z->cd; b; b = b->next)
        if ((r = put(z, b->d, b->n)) != GZ_OK) return r;
    u8 t[56 + 20 + 22];
    u32 tn = 0;
    if (z64) {
        u64 e64 = z->wpos;
        wr32(t, SIG_EOCD64);
        wr64(t + 4, 44);
        wr16(t + 12, MADE_VER);
        wr16(t + 14, 45);
        wr32(t + 16, 0);
        wr32(t + 20, 0);
        wr64(t + 24, z->count);
        wr64(t + 32, z->count);
        wr64(t + 40, z->cd_size);
        wr64(t + 48, cd_off);
        wr32(t + 56, SIG_LOC64);
        wr32(t + 60, 0);
        wr64(t + 64, e64);
        wr32(t + 72, 1);
        tn = 76;
    }
    u8 *e = t + tn;
    wr32(e, SIG_EOCD);
    wr16(e + 4, 0);
    wr16(e + 6, 0);
    wr16(e + 8, (u16)(z->count >= 0xFFFF ? 0xFFFF : z->count));
    wr16(e + 10, (u16)(z->count >= 0xFFFF ? 0xFFFF : z->count));
    wr32(e + 12, z->cd_size >= U32V ? 0xFFFFFFFFu : (u32)z->cd_size);
    wr32(e + 16, cd_off >= U32V ? 0xFFFFFFFFu : (u32)cd_off);
    wr16(e + 20, 0);
    return put(z, t, tn + 22);
}

static int zip_write(const gz_wopts *o, const gz_witem *items, u32 n, gz_sink *out, gz_ctx *c)
{
    zw *z = (zw *)gz_alloc(sizeof(zw));
    if (!z) return GZ_E_NOMEM;
    z->o = o;
    z->out = out;
    z->c = c;
    z->wpos = out->pos;
    z->rnd_pos = sizeof z->rnd;
    z->level = o->level < 0 ? 5 : o->level > 9 ? 9 : o->level;
    int r = GZ_OK;
    switch (o->method) {
    case GZ_WM_DEFAULT: case GZ_WM_DEFLATE: z->method = 8; break;
    case GZ_WM_STORE: z->method = 0; break;
    case GZ_WM_BZIP2: z->method = 12; break;
    case GZ_WM_LZMA: z->method = 14; break;
    case GZ_WM_PPMD: z->method = 98; break;
    default: r = GZ_E_METHOD;
    }
    if (!z->level) z->method = 0;
    z->enc = o->encryption;
    if (!z->enc && o->password) z->enc = GZ_WE_AES256;          /* AES is the default */
    if (z->enc != GZ_WE_NONE && z->enc != GZ_WE_ZIPCRYPTO && z->enc != GZ_WE_AES256) r = GZ_E_METHOD;
    if (!r && z->enc) {
        if (!o->password) r = GZ_E_PASSWORD;
        else {
            size_t wn = gz_wcslen(o->password);
            if (wn > PW_MAX) r = GZ_E_LIMIT;
            else if (!(z->pw = (u8 *)gz_alloc(wn * 3 + 1))) r = GZ_E_NOMEM;
            else z->pwn = (u32)gz_utf16_to_utf8(o->password, wn, z->pw);
        }
    }
    for (u32 i = 0; i < n; i++)
        if (!items[i].is_dir && !items[i].is_link) z->total += items[i].size;
    if (!r && !(z->iob = (u8 *)gz_alloc(IOBUF))) r = GZ_E_NOMEM;
    if (!r && z->enc == GZ_WE_AES256) {
        if (!(z->aes_mem = (u8 *)gz_alloc(sizeof(gz_aes_ctr) + 15))) r = GZ_E_NOMEM;
        else z->aes = (gz_aes_ctr *)(void *)(z->aes_mem + ((16 - ((uintptr_t)z->aes_mem & 15)) & 15));
    }
    for (u32 i = 0; i < n && !r; i++) {
        if (zw_cancelled(z)) { r = GZ_E_CANCEL; break; }
        r = write_item(z, &items[i]);
    }
    if (!r) r = finish(z);
    if (!r && o->progress) o->progress(o->user, z->done, z->total);

    for (cdblk *b = z->cd; b;) { cdblk *nx = b->next; gz_free(b); b = nx; }
    gz_deflate_enc_free(z->defl);
    gz_bzip2_enc_free(z->bz);
    gz_lzma_enc_free(z->lz);
    gz_ppmd8_free(z->ppmd);
    wipe_free(z->pw, z->pwn);
    wipe_free(z->aes_mem, (u32)sizeof(gz_aes_ctr) + 15);
    gz_free(z->iob);
    gz_free(z->ib);
    gz_free(z->ob);
    gz_free(z->nb);
    gz_free(z->lb);
    gz_free(z->wb);
    gz_free(z->hb);
    volatile u8 *v = (volatile u8 *)z;
    for (size_t i = 0; i < sizeof(zw); i++) v[i] = 0;     /* key schedules, random pool */
    gz_free(z);
    return r;
}

GZ_WRITER(gz_wr_zip)
const gz_writer gz_wr_zip = {
    GZ_WF_ZIP, "ZIP", "zip",
    (1u << GZ_WM_DEFAULT) | (1u << GZ_WM_STORE) | (1u << GZ_WM_DEFLATE) | (1u << GZ_WM_BZIP2) |
    (1u << GZ_WM_LZMA) | (1u << GZ_WM_PPMD),
    (1u << GZ_WE_ZIPCRYPTO) | (1u << GZ_WE_AES256),
    zip_write
};
