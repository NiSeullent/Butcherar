/*
 * 고깃ZIP - Inno Setup installer reader (setup.exe built by Inno Setup 1.3 .. 7.x,
 * ANSI and Unicode, "My Inno Setup Extensions")
 *
 * Layout of a single-file installer:
 *   [setup loader PE] .. offset table: RCDATA resource 11111 (5.1.5+), or a pointer
 *   at 0x30 ("Inno", offset, ~offset) for older loaders; the table ("rDlPtS..."
 *   magic, CRC-32 protected, revision 2 = 64-bit offsets since 6.5.0) gives
 *   Offset0 (setup-0, the headers) and Offset1 (setup-1, the file data).
 *   setup-0: 64-byte version string ("Inno Setup Setup Data (5.5.7) (u)"),
 *     [6.5.0+: CRC'd encryption header], then two compressed blocks, each
 *     { CRC, size, compressed flag } + 4 KiB pieces with their own CRC-32,
 *     compressed with zlib (< 4.1.6) or LZMA1:
 *       block 1: setup header + entry lists (languages, messages, permissions,
 *                types, components, tasks, directories, ISSig keys, files, icons,
 *                ini, registry, deletes, runs) + wizard images and DLLs;
 *       block 2: file locations (chunk offset/size, offset and size inside the
 *                chunk, checksum, time stamp, flags).
 *   setup-1: chunks "zlb\x1a" [ARC4 salt] + data compressed with the header's
 *     method (Stored / zlib / bzip2 / LZMA1 with 5 property bytes / LZMA2 with
 *     one), holding one file (default) or many (SolidCompression).
 * Field layouts depend on the data version; they follow innoextract's model of
 * Inno Setup's Struct.pas. Versions whose string is ambiguous or unknown are
 * parsed with the stated version first, then with the next known versions: the
 * first layout that consumes both blocks exactly wins.
 *
 * Entries: one per [Files] entry stored in the installer, named by its
 * destination with the constants kept ("{app}\x.txt" -> "{app}/x.txt",
 * "{{" -> "{", separators inside a constant -> '_'), the uninstaller of old
 * versions as "{app}/unins000.exe", plus [Dirs] entries. Colliding names
 * (language or architecture variants) are kept with an "@lang" / "@32bit" /
 * "$n" suffix before the extension. Files are checked with the stored Adler-32 /
 * CRC-32 / MD5 / SHA-1 / SHA-256 after undoing the x86 call filter (4.1.8 /
 * 5.2.0 / 5.3.9 variants). Encrypted chunks (ARC4 up to 6.3, XChaCha20 from
 * 6.4) are decrypted with the password; 6.5's "Encryption=full" (encrypted
 * headers) is GZ_E_METHOD. Installers whose chunks hold several files are
 * solid (a->solid): extract_solid decodes each chunk once, files sharing data
 * are buffered; single entries decode their chunk up to the file's end.
 * Disk-spanning installers and raw setup-0.bin files (setup-1 in external
 * "<name>-N.bin" / "-Na.bin" slices) read the slices through o->open_volume.
 */
#include "arc.h"
#include "crc32.h"
#include "lzma.h"
#include "bzip2.h"
#include "crypto.h"

#define IV(a, b, c, d) (((u32)(a) << 24) | ((u32)(b) << 16) | ((u32)(c) << 8) | (u32)(d))
#define V(a, b, c) IV(a, b, c, 0)

#if UINTPTR_MAX > 0xFFFFFFFFu
#define HDR_MAX   ((size_t)256 << 20)      /* largest decompressed header block   */
#else
#define HDR_MAX   ((size_t)128 << 20)
#endif
#define DUP_MAX   (64u << 20)              /* buffer data shared by several files  */
#define MAX_PASSES 16                      /* chunk passes for overlapping files   */
#define MAX_TRIES  4                       /* data versions tried per installer    */
#define MAX_SLICES 4096u
#define HDR_DICT_MAX (256u << 20)          /* LZMA dictionary of header blocks     */

enum { C_STORED = 0, C_ZLIB, C_BZIP2, C_LZMA1, C_LZMA2, C_BAD };
enum { CK_NONE = 0, CK_ADLER, CK_CRC, CK_MD5, CK_SHA1, CK_SHA256 };
enum { FI_NONE = 0, FI_4108, FI_5200, FI_5309 };
enum { EN_NONE = 0, EN_ARC4_MD5, EN_ARC4_SHA1, EN_XCHACHA };
enum { PW_NONE = 0, PW_CRC, PW_MD5, PW_SHA1, PW_XCHACHA };

/* gz_entry.flags */
#define IF_SOLID 1u            /* chunk holds several files */
#define IF_ENC   2u

static const u8 chunk_magic[4] = { 'z', 'l', 'b', 0x1a };

/* header parsing runs once per open: optimised for size, not speed */
#define INO_COLD __attribute__((cold, noinline))

/* ---------------- small hashes: MD5, Adler-32 ---------------- */

typedef struct { u32 h[4]; u64 len; u8 buf[64]; u32 n; } ino_md5;

static void md5_block(u32 *h, const u8 *p)
{
    static const u32 K[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
    static const u8 R[16] = { 7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21 };
    u32 m[16], a = h[0], b = h[1], c = h[2], d = h[3];
    for (int i = 0; i < 16; i++) m[i] = rd32(p + 4 * i);
    for (int i = 0; i < 64; i++) {
        u32 f, g;
        int q = i >> 4;
        if (q == 0) { f = (b & c) | (~b & d); g = (u32)i; }
        else if (q == 1) { f = (d & b) | (~d & c); g = (5u * i + 1) & 15; }
        else if (q == 2) { f = b ^ c ^ d; g = (3u * i + 5) & 15; }
        else { f = c ^ (b | ~d); g = (7u * i) & 15; }
        u32 t = d, s = R[q * 4 + (i & 3)];
        d = c;
        c = b;
        u32 x = a + f + K[i] + m[g];
        b = b + ((x << s) | (x >> (32 - s)));
        a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
}

static void md5_init(ino_md5 *m)
{
    m->h[0] = 0x67452301; m->h[1] = 0xefcdab89; m->h[2] = 0x98badcfe; m->h[3] = 0x10325476;
    m->len = 0;
    m->n = 0;
}

static void md5_update(ino_md5 *m, const u8 *p, size_t n)
{
    m->len += n;
    if (m->n) {
        u32 k = 64 - m->n;
        if (k > n) k = (u32)n;
        __builtin_memcpy(m->buf + m->n, p, k);
        m->n += k; p += k; n -= k;
        if (m->n < 64) return;
        md5_block(m->h, m->buf);
        m->n = 0;
    }
    for (; n >= 64; p += 64, n -= 64) md5_block(m->h, p);
    if (n) { __builtin_memcpy(m->buf, p, n); m->n = (u32)n; }
}

static void md5_final(ino_md5 *m, u8 out[16])
{
    u64 bits = m->len * 8;
    u8 pad[72] = { 0x80 };
    u32 k = m->n < 56 ? 56 - m->n : 120 - m->n;
    md5_update(m, pad, k);
    wr64(pad, bits);
    md5_update(m, pad, 8);
    for (int i = 0; i < 4; i++) wr32(out + 4 * i, m->h[i]);
}

static u32 adler32(u32 a, const u8 *p, size_t n)
{
    u32 s1 = a & 0xFFFF, s2 = a >> 16;
    while (n) {
        size_t k = n < 5552 ? n : 5552;
        n -= k;
        while (k--) { s1 += *p++; s2 += s1; }
        s1 %= 65521;
        s2 %= 65521;
    }
    return s2 << 16 | s1;
}

/* ---------------- ciphers: ARC4, XChaCha20 ---------------- */

typedef struct { u8 s[256]; u8 i, j; } ino_rc4;

static void rc4_crypt(ino_rc4 *r, u8 *p, size_t n)
{
    u8 i = r->i, j = r->j;
    for (size_t k = 0; k < n; k++) {
        i++;
        u8 t = r->s[i];
        j = (u8)(j + t);
        r->s[i] = r->s[j];
        r->s[j] = t;
        if (p) p[k] ^= r->s[(u8)(t + r->s[i])];
    }
    r->i = i;
    r->j = j;
}

static void rc4_init(ino_rc4 *r, const u8 *key, u32 kn)
{
    for (int i = 0; i < 256; i++) r->s[i] = (u8)i;
    u8 j = 0;
    for (int i = 0; i < 256; i++) {
        u8 t = r->s[i];
        j = (u8)(j + t + key[i % kn]);
        r->s[i] = r->s[j];
        r->s[j] = t;
    }
    r->i = r->j = 0;
    rc4_crypt(r, 0, 1000);           /* Inno discards the first 1000 key stream bytes */
}

typedef struct { u32 st[16], ks[16]; u32 pos; } ino_xc;

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a, b, c, d) \
    a += b; d ^= a; d = ROTL(d, 16); c += d; b ^= c; b = ROTL(b, 12); \
    a += b; d ^= a; d = ROTL(d, 8);  c += d; b ^= c; b = ROTL(b, 7)

static void chacha_rounds(u32 *x)
{
    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8], x[12]);  QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]); QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]); QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);  QR(x[3], x[4], x[9], x[14]);
    }
}

static void chacha_key(u32 *st, const u8 *key)
{
    st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) st[4 + i] = rd32(key + 4 * i);
}

/* XChaCha20 with a 64-bit block counter (libsodium / Inno Setup 6.4+) */
static void xc_init(ino_xc *x, const u8 key[32], const u8 nonce[24])
{
    u32 h[16];
    u8 sub[32];
    chacha_key(h, key);
    for (int i = 0; i < 4; i++) h[12 + i] = rd32(nonce + 4 * i);
    chacha_rounds(h);
    for (int i = 0; i < 4; i++) { wr32(sub + 4 * i, h[i]); wr32(sub + 16 + 4 * i, h[12 + i]); }
    chacha_key(x->st, sub);
    x->st[12] = x->st[13] = 0;
    x->st[14] = rd32(nonce + 16);
    x->st[15] = rd32(nonce + 20);
    x->pos = 64;
}

static void xc_crypt(ino_xc *x, u8 *p, size_t n)
{
    for (size_t k = 0; k < n; k++) {
        if (x->pos == 64) {
            __builtin_memcpy(x->ks, x->st, sizeof x->ks);
            chacha_rounds(x->ks);
            for (int i = 0; i < 16; i++) x->ks[i] += x->st[i];
            if (!++x->st[12]) x->st[13]++;
            x->pos = 0;
        }
        p[k] ^= (u8)(x->ks[x->pos >> 2] >> (8 * (x->pos & 3)));
        x->pos++;
    }
}

/* ---------------- byte reader for the header blocks ---------------- */

typedef struct {
    const u8 *p, *end;
    const u8 *b;         /* block start                                    */
    u32 v;               /* data version                                   */
    u8 uni, isx;
    u8 bad;              /* structure overrun: this layout does not fit    */
    u8 soft;             /* out-of-range value: prefer another layout      */
} ird;

static INO_COLD u8 *rget(ird *r, size_t n)
{
    if ((size_t)(r->end - r->p) < n) { r->bad = 1; r->p = r->end; return 0; }
    const u8 *q = r->p;
    r->p += n;
    return (u8 *)q;
}
static INO_COLD u8  g8(ird *r)  { const u8 *q = rget(r, 1); return q ? q[0] : 0; }
static INO_COLD u16 g16(ird *r) { const u8 *q = rget(r, 2); return q ? rd16(q) : 0; }
static INO_COLD u32 g32(ird *r) { const u8 *q = rget(r, 4); return q ? rd32(q) : 0; }
static INO_COLD u64 g64(ird *r) { const u8 *q = rget(r, 8); return q ? rd64(q) : 0; }
static INO_COLD void gskip(ird *r, size_t n) { rget(r, n); }

/* length-prefixed string */
static INO_COLD const u8 *gs(ird *r, u32 *n)
{
    u32 k = g32(r);
    const u8 *q = rget(r, k);
    *n = q ? k : 0;
    return q;
}
static INO_COLD void S(ird *r) { u32 n; gs(r, &n); }

/* enum byte with count values */
static INO_COLD u8 E(ird *r, u32 count)
{
    u8 x = g8(r);
    if (x >= count) r->soft = 1;
    return x;
}

/* Delphi set read flag by flag: 1 byte per 8 flags, 3-byte sets padded to 4 */
typedef struct { ird *r; u32 bytes, nbits; u8 pos, cur; } ifl;

static INO_COLD int F(ifl *f, int cond)
{
    if (!cond) return 0;
    f->nbits++;
    if (!f->pos) { f->cur = g8(f->r); f->bytes++; }
    int b = (f->cur >> f->pos) & 1;
    f->pos = (u8)((f->pos + 1) & 7);
    return b;
}

static INO_COLD void F_end(ifl *f, u32 width)
{
    if (width) while (f->bytes < width) { g8(f->r); f->bytes++; }
    else if (f->bytes == 3) g8(f->r);
}

/* ---------------- setup header and entry lists ---------------- */

typedef struct {
    u32 n_lang, n_msg, n_perm, n_type, n_comp, n_task, n_dir, n_issig, n_file, n_data,
        n_icon, n_ini, n_reg, n_del, n_udel, n_run, n_urun;
    u32 slices_per_disk;
    u8 comp, enc_used, sevenzip_lib, pw_type;
    u8 pw_hash[20];
    u8 salt[44]; u32 salt_len;
    u8 lead[32]; u8 has_lead;
    const u8 *base; u32 base_n;          /* base filename (slice names)         */
    u32 at_comp, at_pw, at_flags, enc_bit, at_lead;   /* positions (test tooling) */
} ino_hdr;

typedef struct {
    const u8 *dst; u32 dn;               /* destination                         */
    const u8 *lang; u32 ln;              /* Languages: expression               */
    const u8 *comp; u32 cn;              /* Components: expression              */
    u32 loc, attr;
    u8 arch;                             /* 1 = 32bit flag, 2 = 64bit flag      */
    u8 uninst;                           /* the uninstaller (file type 1)       */
} pf_file;

typedef struct { const u8 *name; u32 n, attr; } pf_dir;

typedef struct {
    u64 chunk_off, chunk_size, file_off, size, mtime;
    u32 slice, last_slice;
    u8 comp, enc, filter, ck_type;
    u8 ck[32];
} pf_data;

typedef struct {
    ino_hdr h;
    pf_file *f; u32 nf;
    pf_dir *d; u32 nd;
    pf_data *dt; u32 ndt;
    u32 lang_cp; int lang_cp_mixed;      /* ANSI installers: code page of the languages */
    int soft;
} ino_parse;

/* MinVersion + OnlyBelowVersion: each Windows 9x and NT version, NT service pack */
static INO_COLD void winver(ird *r)
{
    for (int k = 0; k < 2; k++) {
        for (int i = 0; i < 2; i++) {
            if (r->v >= V(1, 3, 19)) g16(r);    /* build */
            g8(r); g8(r);                       /* minor, major */
        }
        if (r->v >= V(1, 3, 19)) { g8(r); g8(r); }
    }
}

static INO_COLD void cond_data(ird *r, const u8 **lang, u32 *ln, const u8 **comp, u32 *cn)
{
    u32 v = r->v, n;
    const u8 *q;
    *ln = *cn = 0;
    *lang = *comp = 0;
    if (v >= V(2, 0, 0) || (r->isx && v >= V(1, 3, 8))) { q = gs(r, &n); *comp = q; *cn = n; }
    if (v >= V(2, 0, 0) || (r->isx && v >= V(1, 3, 17))) S(r);       /* tasks */
    if (v >= V(4, 0, 1)) { q = gs(r, &n); *lang = q; *ln = n; }
    if (v >= V(4, 0, 0) || (r->isx && v >= V(1, 3, 24))) S(r);       /* check */
    if (v >= V(4, 1, 0)) { S(r); S(r); }                             /* after / before install */
}

static INO_COLD void parse_header(ird *r, ino_hdr *h)
{
    const u32 v = r->v;
    const int isx = r->isx;
    u32 n;
    __builtin_memset(h, 0, sizeof *h);
    if (v < V(1, 3, 0)) g32(r);                                       /* uncompressed size */
    S(r); S(r);                                                       /* AppName, AppVerName */
    if (v >= V(1, 3, 0)) S(r);                                        /* AppId */
    S(r);                                                             /* AppCopyright */
    if (v >= V(1, 3, 0)) { S(r); S(r); }                              /* publisher, URL */
    if (v >= V(5, 1, 13)) S(r);                                       /* support phone */
    if (v >= V(1, 3, 0)) { S(r); S(r); S(r); }                        /* support/updates URL, version */
    S(r); S(r);                                                       /* DefaultDirName, GroupName */
    if (v < V(3, 0, 0)) S(r);                                         /* uninstall icon name */
    h->base = gs(r, &h->base_n);                                      /* OutputBaseFilename */
    if (v >= V(1, 3, 0) && v < V(5, 2, 5)) { S(r); S(r); S(r); }      /* license, info before/after */
    if (v >= V(1, 3, 3)) S(r);                                        /* UninstallFilesDir */
    if (v >= V(1, 3, 6)) { S(r); S(r); }                              /* uninstall name, icon */
    if (v >= V(1, 3, 14)) S(r);                                       /* AppMutex */
    if (v >= V(3, 0, 0)) { S(r); S(r); }                              /* default user name, org */
    if (v >= V(4, 0, 0) || (isx && v >= IV(3, 0, 6, 1))) S(r);        /* default serial */
    if ((v >= V(4, 0, 0) && v < V(5, 2, 5)) || (isx && v >= V(1, 3, 24))) S(r);   /* compiled code */
    if (v >= V(4, 2, 4)) { S(r); S(r); S(r); S(r); }                  /* readme, contact, comments, modify path */
    if (v >= V(5, 3, 8)) S(r);                                        /* CreateUninstallRegKey */
    if (v >= V(5, 3, 10)) S(r);                                       /* Uninstallable */
    if (v >= V(5, 5, 0)) S(r);                                        /* CloseApplicationsFilter */
    if (v >= V(5, 5, 6)) S(r);                                        /* SetupMutex */
    if (v >= V(5, 6, 1)) { S(r); S(r); }                              /* ChangesEnvironment / Associations */
    if (v >= V(6, 3, 0)) { S(r); S(r); }                              /* architecture expressions */
    if (v >= V(6, 4, 2)) S(r);                                        /* CloseApplicationsFilterExcludes */
    if (v >= V(6, 5, 0)) { gs(r, &n); h->sevenzip_lib = n != 0; }     /* SevenZipLibraryName */
    if (v >= V(6, 7, 0)) { S(r); S(r); S(r); S(r); S(r); }            /* UsePrevious* expressions */
    if (v >= V(5, 2, 5)) { S(r); S(r); S(r); }                        /* license, info before/after */
    if (v >= V(5, 2, 1) && v < V(5, 3, 10)) S(r);                     /* uninstaller signature */
    if (v >= V(5, 2, 5)) S(r);                                        /* compiled code */
    if (v >= V(2, 0, 6) && !r->uni) {                                 /* DBCS lead bytes */
        h->at_lead = (u32)(r->p - r->b);
        const u8 *q = rget(r, 32);
        if (q) { __builtin_memcpy(h->lead, q, 32); h->has_lead = 1; }
    }
    if (v >= V(4, 0, 0)) h->n_lang = g32(r);
    else if (v >= V(2, 0, 1)) h->n_lang = 1;
    if (v >= V(4, 2, 1)) h->n_msg = g32(r);
    if (v >= V(4, 1, 0)) h->n_perm = g32(r);
    if (v >= V(2, 0, 0) || isx) { h->n_type = g32(r); h->n_comp = g32(r); }
    if (v >= V(2, 0, 0) || (isx && v >= V(1, 3, 17))) h->n_task = g32(r);
    h->n_dir = g32(r);
    if (v >= V(6, 5, 0)) h->n_issig = g32(r);
    h->n_file = g32(r);
    h->n_data = g32(r);
    h->n_icon = g32(r);
    h->n_ini = g32(r);
    h->n_reg = g32(r);
    h->n_del = g32(r);
    h->n_udel = g32(r);
    h->n_run = g32(r);
    h->n_urun = g32(r);
    u32 lic = 0, ib = 0, ia = 0;
    if (v < V(1, 3, 0)) { lic = g32(r); ib = g32(r); ia = g32(r); }
    if (v >= IV(7, 0, 0, 3)) g32(r);                                  /* CompiledCodeVersion */
    winver(r);
    if (v < IV(6, 4, 0, 1)) g32(r);                                   /* BackColor */
    if (v >= V(1, 3, 3) && v < IV(6, 4, 0, 1)) g32(r);                /* BackColor2 */
    if (v < V(5, 5, 7)) g32(r);                                       /* WizardImageBackColor */
    if ((v >= V(2, 0, 0) && v < V(5, 0, 4)) || isx) g32(r);           /* WizardSmallImageBackColor */
    if (v >= V(6, 6, 0)) { g32(r); g32(r); E(r, 3); }                 /* size percents, dark style */
    else if (v >= V(6, 0, 0)) { E(r, 2); g32(r); g32(r); }            /* WizardStyle, size percents */
    if (v >= V(5, 5, 7)) E(r, 3);                                     /* image alpha format */
    if (v >= V(6, 5, 2)) { g32(r); g32(r); }                          /* image back colors */
    if (v >= V(6, 7, 0)) g32(r);                                      /* WizardBackColor */
    if (v >= V(6, 6, 0)) { g32(r); g32(r); }                          /* dynamic dark colors */
    if (v >= V(6, 7, 0)) g32(r);
    if (v >= V(6, 6, 1)) g8(r);                                       /* WizardImageOpacity */
    if (v >= V(6, 7, 0)) { g8(r); E(r, 3); }                          /* back image opacity, light styling */
    /* password test */
    const u8 *q;
    h->at_pw = (u32)(r->p - r->b);
    if (v >= V(6, 5, 0)) {
        /* in the encryption header */
    } else if (v >= V(6, 4, 0)) {
        if ((q = rget(r, 4))) { __builtin_memcpy(h->pw_hash, q, 4); h->pw_type = PW_XCHACHA; }
    } else if (v >= V(5, 3, 9)) {
        if ((q = rget(r, 20))) { __builtin_memcpy(h->pw_hash, q, 20); h->pw_type = PW_SHA1; }
    } else if (v >= V(4, 2, 0)) {
        if ((q = rget(r, 16))) { __builtin_memcpy(h->pw_hash, q, 16); h->pw_type = PW_MD5; }
    } else {
        wr32(h->pw_hash, g32(r));
        h->pw_type = PW_CRC;
    }
    if (v >= V(6, 5, 0)) {
    } else if (v >= V(6, 4, 0)) {
        if ((q = rget(r, 44))) { __builtin_memcpy(h->salt, q, 44); h->salt_len = 44; }
    } else if (v >= V(4, 2, 2)) {
        if ((q = rget(r, 8))) { __builtin_memcpy(h->salt, q, 8); h->salt_len = 8; }
    }
    if (v >= V(4, 0, 0)) { g64(r); h->slices_per_disk = g32(r); }     /* extra disk space, slices */
    else { g32(r); h->slices_per_disk = 1; }
    if ((v >= V(2, 0, 0) && v < V(5, 0, 0)) || (isx && v >= V(1, 3, 4))) E(r, 3);   /* install mode */
    if (v >= V(1, 3, 0)) E(r, 3);                                     /* uninstall log mode */
    if (v < V(5, 0, 0) && (v >= V(2, 0, 0) || (isx && v >= V(1, 3, 13)))) E(r, 2);  /* uninstall style */
    if (v >= V(1, 3, 6)) E(r, 3);                                     /* DirExistsWarning */
    if (isx && v >= V(2, 0, 10) && v < V(3, 0, 0)) g32(r);            /* code line offset */
    if (v >= V(3, 0, 0) && v < V(3, 0, 3)) E(r, 3);                   /* restart */
    if (v >= V(5, 3, 7)) E(r, 4);                                     /* PrivilegesRequired */
    else if (v >= V(3, 0, 4) || (isx && v >= V(3, 0, 3))) E(r, 3);
    if (v >= V(5, 7, 0)) g8(r);                                       /* privileges override set */
    if (v >= V(4, 0, 10)) { E(r, 3); E(r, 3); }                       /* language dialog, detection */
    u8 cm = C_ZLIB;
    h->at_comp = (u32)(r->p - r->b);
    if (v >= V(5, 3, 9)) {
        static const u8 m3[5] = { C_STORED, C_ZLIB, C_BZIP2, C_LZMA1, C_LZMA2 };
        u8 x = E(r, 5);
        cm = x < 5 ? m3[x] : C_BAD;
    } else if (v >= V(4, 2, 6)) {
        static const u8 m2[4] = { C_STORED, C_ZLIB, C_BZIP2, C_LZMA1 };
        u8 x = E(r, 4);
        cm = x < 4 ? m2[x] : C_BAD;
    } else if (v >= V(4, 2, 5)) {
        static const u8 m1[3] = { C_STORED, C_BZIP2, C_LZMA1 };
        u8 x = E(r, 3);
        cm = x < 3 ? m1[x] : C_BAD;
    } else if (v >= V(4, 1, 5)) {
        static const u8 m0[3] = { C_ZLIB, C_BZIP2, C_LZMA1 };
        u8 x = E(r, 3);
        cm = x < 3 ? m0[x] : C_BAD;
    }
    if (v < V(6, 3, 0) && v >= V(5, 1, 0)) { g8(r); g8(r); }          /* architecture sets */
    if (v >= V(5, 2, 1) && v < V(5, 3, 10)) { g32(r); g32(r); }       /* signed uninstaller size/CRC */
    if (v >= V(5, 3, 3)) { E(r, 3); E(r, 3); }                        /* DisableDirPage, ProgramGroupPage */
    if (v >= V(5, 5, 0)) g64(r);                                      /* UninstallDisplaySize */
    else if (v >= V(5, 3, 6)) g32(r);
    if (v == IV(5, 3, 10, 1) || v == IV(5, 4, 2, 1) || v == IV(5, 5, 0, 1)) g8(r);   /* modified variants */

    ifl f = { r, 0, 0, 0, 0 };
    h->at_flags = (u32)(r->p - r->b);
    F(&f, 1);                                           /* DisableStartupPrompt */
    F(&f, v < V(5, 3, 10));                             /* Uninstallable */
    F(&f, 1);                                           /* CreateAppDir */
    F(&f, v < V(5, 3, 3));                              /* DisableDirPage */
    F(&f, v < V(1, 3, 6));                              /* DisableDirExistsWarning */
    F(&f, v < V(5, 3, 3));                              /* DisableProgramGroupPage */
    F(&f, 1);                                           /* AllowNoIcons */
    F(&f, v < V(3, 0, 0) || v >= V(3, 0, 3));           /* AlwaysRestart */
    F(&f, v < V(1, 3, 3));                              /* BackSolid */
    F(&f, 1);                                           /* AlwaysUsePersonalGroup */
    for (int i = 0; i < 4; i++) F(&f, v < IV(6, 4, 0, 1));   /* Window* */
    F(&f, 1);                                           /* EnableDirDoesntExistWarning */
    F(&f, v < V(4, 1, 2));                              /* DisableAppendDir */
    F(&f, 1);                                           /* Password */
    F(&f, v >= V(1, 2, 6));                             /* AllowRootDirectory */
    F(&f, v >= V(1, 2, 14));                            /* DisableFinishedPage */
    F(&f, v < V(3, 0, 4));                              /* AdminPrivilegesRequired */
    F(&f, v < V(3, 0, 0));                              /* AlwaysCreateUninstallIcon */
    F(&f, v < V(1, 3, 6));                              /* OverwriteUninstRegEntries */
    F(&f, v < V(5, 6, 1));                              /* ChangesAssociations */
    F(&f, v >= V(1, 3, 0) && v < V(5, 3, 8));           /* CreateUninstallRegKey */
    F(&f, v >= V(1, 3, 1) && v < V(6, 7, 0));           /* UsePreviousAppDir */
    F(&f, v >= V(1, 3, 3) && v < IV(6, 4, 0, 1));       /* BackColorHorizontal */
    F(&f, v >= V(1, 3, 10) && v < V(6, 7, 0));          /* UsePreviousGroup */
    F(&f, v >= V(1, 3, 20));                            /* UpdateUninstallLogAppName */
    F(&f, (v >= V(2, 0, 0) || (isx && v >= V(1, 3, 10))) && v < V(6, 7, 0));   /* UsePreviousSetupType */
    if (v >= V(2, 0, 0)) {
        for (int i = 0; i < 4; i++) F(&f, 1);           /* ReadyMemo, components list flags */
        F(&f, v < V(6, 7, 0));                          /* UsePreviousTasks */
        F(&f, 1);                                       /* DisableReadyPage */
    }
    F(&f, v >= V(2, 0, 7)); F(&f, v >= V(2, 0, 7));     /* AlwaysShowDir/GroupOnReadyPage */
    int bzip = F(&f, v >= V(2, 0, 17) && v < V(4, 1, 5));   /* BzipUsed */
    F(&f, v >= V(2, 0, 18));                            /* AllowUNCPath */
    if (v >= V(3, 0, 0)) { F(&f, 1); F(&f, v < V(6, 7, 0)); }   /* UserInfoPage, UsePreviousUserInfo */
    F(&f, v >= V(3, 0, 1));                             /* UninstallRestartComputer */
    F(&f, v >= V(3, 0, 3));                             /* RestartIfNeededByRun */
    F(&f, v >= V(4, 0, 0) || (isx && v >= V(3, 0, 3))); /* ShowTasksTreeLines */
    F(&f, v >= V(4, 0, 0) && v < V(4, 0, 10));          /* ShowLanguageDialog */
    F(&f, v >= V(4, 0, 1) && v < V(4, 0, 10));          /* DetectLanguageUsingLocale */
    F(&f, v >= V(4, 0, 9));                             /* AllowCancelDuringInstall */
    F(&f, v >= V(4, 1, 3));                             /* WizardImageStretch */
    F(&f, v >= V(4, 1, 8)); F(&f, v >= V(4, 1, 8));     /* AppendDefaultDir/GroupName */
    h->enc_bit = f.nbits;
    h->enc_used = (u8)F(&f, v >= V(4, 2, 2) && v < V(6, 5, 0));   /* EncryptionUsed */
    F(&f, v >= V(5, 0, 4) && v < V(5, 6, 1));           /* ChangesEnvironment */
    F(&f, v >= V(5, 1, 7) && !r->uni);                  /* ShowUndisplayableLanguages */
    F(&f, v >= V(5, 1, 13));                            /* SetupLogging */
    F(&f, v >= V(5, 2, 1));                             /* SignedUninstaller */
    F(&f, v >= V(5, 3, 8));                             /* UsePreviousLanguage */
    F(&f, v >= V(5, 3, 9));                             /* DisableWelcomePage */
    for (int i = 0; i < 3; i++) F(&f, v >= V(5, 5, 0)); /* Close/RestartApplications, AllowNetworkDrive */
    F(&f, v >= V(5, 5, 7));                             /* ForceCloseApplications */
    F(&f, v >= V(6, 0, 0)); F(&f, v >= V(6, 0, 0));     /* AppNameHasConsts, UsePreviousPrivileges */
    F(&f, v >= V(6, 0, 0) && v < V(6, 6, 0));           /* WizardResizable */
    F(&f, v >= V(6, 3, 0));                             /* UninstallLogging */
    for (int i = 0; i < 3; i++) F(&f, v >= V(6, 6, 0)); /* WizardModern, BorderStyled, KeepAspectRatio */
    F(&f, v >= V(6, 6, 0) && v < V(6, 7, 0));           /* WizardLightButtonsUnstyled */
    F(&f, v >= V(6, 7, 0)); F(&f, v >= V(6, 7, 0));     /* RedirectionGuard, WizardBevelsHidden */
    F_end(&f, v >= V(6, 7, 0) ? 8 : 0);
    if (v < V(4, 1, 5)) cm = bzip ? C_BZIP2 : C_ZLIB;
    h->comp = cm;
    if (cm == C_BAD) r->soft = 1;
    if (v < V(1, 3, 0)) {
        if ((i32)lic > 0) gskip(r, lic);
        if ((i32)ib > 0) gskip(r, ib);
        if ((i32)ia > 0) gskip(r, ia);
    }
}

/* default ANSI code pages of Windows languages (data versions before 4.2.2) */
static INO_COLD u32 lang_cp(u32 id)
{
    static const u16 tab[][2] = {
        { 0x0401, 1256 }, { 0x0402, 1251 }, { 0x0404, 950 }, { 0x0405, 1250 }, { 0x0408, 1253 },
        { 0x040d, 1255 }, { 0x040e, 1250 }, { 0x0411, 932 }, { 0x0412, 949 }, { 0x0415, 1250 },
        { 0x0418, 1250 }, { 0x0419, 1251 }, { 0x041a, 1250 }, { 0x041b, 1250 }, { 0x041c, 1250 },
        { 0x041e, 874 }, { 0x041f, 1254 }, { 0x0420, 1256 }, { 0x0422, 1251 }, { 0x0423, 1251 },
        { 0x0424, 1250 }, { 0x0425, 1257 }, { 0x0426, 1257 }, { 0x0427, 1257 }, { 0x0429, 1256 },
        { 0x042a, 1258 }, { 0x042c, 1254 }, { 0x042f, 1251 }, { 0x043f, 1251 }, { 0x0440, 1251 },
        { 0x0443, 1254 }, { 0x0444, 1251 }, { 0x0450, 1251 }, { 0x0801, 1256 }, { 0x0804, 936 },
        { 0x081a, 1250 }, { 0x082c, 1251 }, { 0x0843, 1251 }, { 0x0c04, 950 }, { 0x0c1a, 1251 },
        { 0x1004, 936 }, { 0x1404, 950 } };
    for (u32 i = 0; i < GZ_COUNTOF(tab); i++) if (tab[i][0] == id) return tab[i][1];
    if ((id & 0x3FF) == 0x01) return 1256;          /* Arabic variants */
    return 1252;
}

static INO_COLD void parse_language(ird *r, ino_parse *P)
{
    const u32 v = r->v;
    if (v >= V(4, 0, 0)) S(r);                       /* internal name */
    S(r);                                            /* LanguageName */
    if (v == IV(5, 5, 7, 1)) S(r);
    S(r);                                            /* DialogFontName */
    if (v < V(6, 6, 0)) S(r);                        /* TitleFontName */
    S(r);                                            /* WelcomeFontName */
    if (v < V(6, 6, 0)) S(r);                        /* CopyrightFontName */
    if (v >= V(4, 0, 0)) S(r);                       /* messages data */
    if (v >= V(4, 0, 1)) { S(r); S(r); S(r); }       /* license, info before/after */
    u32 id = v >= V(6, 6, 0) ? g16(r) : g32(r);
    u32 cp = 0;
    if (v < V(4, 2, 2)) cp = lang_cp(id);
    else if (!r->uni) cp = g32(r);
    else if (v < V(5, 3, 0)) g32(r);
    g32(r);                                          /* DialogFontSize */
    if (v < V(4, 1, 0)) g32(r);                      /* DialogFontStandardHeight */
    if (v >= V(6, 6, 0)) { g32(r); g32(r); } else g32(r);   /* base scale / TitleFontSize */
    g32(r);                                          /* WelcomeFontSize */
    if (v < V(6, 6, 0)) g32(r);                      /* CopyrightFontSize */
    if (v == IV(5, 5, 7, 1)) g32(r);
    if (v >= V(5, 2, 3)) g8(r);                      /* RightToLeft */
    /* ANSI strings: a code page shared by every language other than Western */
    if (!r->uni) {
        if (cp == 1252 || cp == 0) P->lang_cp_mixed = 1;
        else if (!P->lang_cp) P->lang_cp = cp;
        else if (P->lang_cp != cp) P->lang_cp_mixed = 1;
    }
}

static INO_COLD void parse_wizard_images(ird *r)
{
    u32 n = r->v >= V(5, 6, 0) ? g32(r) : 1;
    for (u32 i = 0; i < n && !r->bad; i++) S(r);
}

static INO_COLD void parse_wizard_dlls(ird *r, const ino_hdr *h)
{
    const u32 v = r->v;
    parse_wizard_images(r);                          /* wizard images */
    if (v >= V(2, 0, 0) || r->isx) parse_wizard_images(r);   /* small images */
    if (v >= V(6, 7, 0)) parse_wizard_images(r);     /* back images */
    if (v >= V(6, 6, 0)) {                           /* dynamic dark copies */
        parse_wizard_images(r);
        parse_wizard_images(r);
        if (v >= V(6, 7, 0)) parse_wizard_images(r);
    }
    if (h->comp == C_BZIP2 || (h->comp == C_LZMA1 && v == V(4, 1, 5)) ||
        (h->comp == C_ZLIB && v >= V(4, 2, 6)))
        S(r);                                        /* decompressor DLL */
    if (v >= V(6, 5, 0) && h->sevenzip_lib) S(r);    /* 7-Zip decoder DLL */
    if (h->enc_used && v < V(6, 4, 0)) S(r);         /* decryption DLL */
}

static INO_COLD void parse_type(ird *r)
{
    const u32 v = r->v;
    S(r); S(r);
    if (v >= V(4, 0, 1)) S(r);
    if (v >= V(4, 0, 0) || (r->isx && v >= V(1, 3, 24))) S(r);
    winver(r);
    g8(r);                                           /* options */
    if (v >= V(4, 0, 3)) E(r, 4);                    /* type */
    if (v >= V(4, 0, 0)) g64(r); else g32(r);        /* size */
}

static INO_COLD void parse_component(ird *r)
{
    const u32 v = r->v;
    S(r); S(r); S(r);                                /* name, description, types */
    if (v >= V(4, 0, 1)) S(r);
    if (v >= V(4, 0, 0) || (r->isx && v >= V(1, 3, 24))) S(r);
    if (v >= V(4, 0, 0)) g64(r); else g32(r);        /* extra disk space */
    if (v >= V(6, 7, 0)) g8(r);                      /* level */
    else if (v >= V(4, 0, 0) || (r->isx && v >= V(3, 0, 3))) g32(r);
    if (v >= V(4, 0, 0) || (r->isx && v >= V(3, 0, 4))) g8(r);   /* used */
    winver(r);
    g8(r);                                           /* options */
    if (v >= V(4, 0, 0)) g64(r);                     /* size */
    else if (v >= V(2, 0, 0) || (r->isx && v >= V(1, 3, 24))) g32(r);
}

static INO_COLD void parse_task(ird *r)
{
    const u32 v = r->v;
    S(r); S(r); S(r); S(r);                          /* name, description, group, components */
    if (v >= V(4, 0, 1)) S(r);
    if (v >= V(4, 0, 0) || (r->isx && v >= V(1, 3, 24))) S(r);
    if (v >= V(6, 7, 0)) g8(r);
    else if (v >= V(4, 0, 0) || (r->isx && v >= V(3, 0, 3))) g32(r);
    if (v >= V(4, 0, 0) || (r->isx && v >= V(3, 0, 4))) g8(r);
    winver(r);
    ifl f = { r, 0, 0, 0, 0 };
    F(&f, 1); F(&f, 1); F(&f, v >= V(2, 0, 5)); F(&f, v >= V(2, 0, 6)); F(&f, v >= V(4, 2, 3));
    F_end(&f, 0);
}

static INO_COLD void parse_dir(ird *r, pf_dir *d)
{
    const u32 v = r->v;
    const u8 *l, *c;
    u32 ln, cn;
    if (v < V(1, 3, 0)) g32(r);
    d->name = gs(r, &d->n);
    cond_data(r, &l, &ln, &c, &cn);
    if (v >= V(4, 0, 11) && v < V(4, 1, 0)) S(r);    /* permissions */
    d->attr = v >= V(2, 0, 11) ? g32(r) : 0;
    winver(r);
    if (v >= V(4, 1, 0)) g16(r);                     /* permission index */
    g8(r);                                           /* options */
}

static INO_COLD void parse_file(ird *r, pf_file *fe)
{
    const u32 v = r->v;
    const int isx = r->isx;
    if (v < V(1, 3, 0)) g32(r);
    S(r);                                            /* source */
    fe->dst = gs(r, &fe->dn);
    S(r);                                            /* font name */
    if (v >= V(5, 2, 5)) S(r);                       /* strong assembly name */
    cond_data(r, &fe->lang, &fe->ln, &fe->comp, &fe->cn);
    if (v >= V(6, 5, 0)) {
        for (int i = 0; i < 6; i++) S(r);            /* excludes, download*, archive password, ISSig keys */
        gskip(r, 32);                                /* SHA-256 */
        E(r, 3);                                     /* verification */
    }
    winver(r);
    fe->loc = g32(r);
    fe->attr = g32(r);
    if (v >= V(4, 0, 0)) g64(r); else g32(r);        /* external size */
    if (v < V(3, 0, 5)) E(r, 4);                     /* copy mode */
    if (v >= V(4, 1, 0)) g16(r);                     /* permission */
    fe->arch = 0;
    if (v >= IV(7, 0, 0, 3)) {
        u8 b = g8(r);                                /* bitness */
        fe->arch = b == 1 ? 1 : b == 2 ? 2 : 0;
    }
    ifl f = { r, 0, 0, 0, 0 };
    for (int i = 0; i < 7; i++) F(&f, 1);            /* ConfirmOverwrite .. SharedFile */
    F(&f, v < V(2, 0, 0) && !isx);                   /* IsReadmeFile */
    F(&f, 1); F(&f, 1);                              /* CompareTimeStamp, FontIsNotTrueType */
    F(&f, v >= V(1, 2, 5));
    F(&f, v >= V(1, 2, 6));
    F(&f, v >= V(1, 3, 21)); F(&f, v >= V(1, 3, 21));
    F(&f, v >= V(1, 3, 25));
    F(&f, v >= V(2, 0, 5));
    F(&f, v >= V(3, 0, 1));
    for (int i = 0; i < 3; i++) F(&f, v >= V(3, 0, 5));
    F(&f, v >= V(4, 0, 0) || (isx && v >= IV(3, 0, 6, 1)));   /* DontCopy */
    F(&f, v >= V(4, 0, 5));
    F(&f, v >= V(4, 1, 8));
    F(&f, v >= V(4, 2, 1));
    F(&f, v >= V(4, 2, 5));
    F(&f, v >= V(5, 0, 3));
    F(&f, v >= V(5, 1, 0));
    int b32 = F(&f, v >= V(5, 1, 2) && v < IV(7, 0, 0, 3));
    int b64 = F(&f, v >= V(5, 1, 2) && v < IV(7, 0, 0, 3));
    for (int i = 0; i < 3; i++) F(&f, v >= V(5, 2, 0));
    F(&f, v >= V(5, 2, 5));                          /* GacInstall */
    F(&f, v >= V(6, 5, 0)); F(&f, v >= V(6, 5, 0));  /* Download, ExtractArchive */
    F_end(&f, v >= V(6, 7, 0) ? 8 : 0);
    if (b32 != b64) fe->arch = b32 ? 1 : 2;
    fe->uninst = E(r, v >= V(5, 0, 0) ? 2 : 3) == 1;  /* file type: user / uninstaller / regsvr */
}

static INO_COLD void parse_icon(ird *r)
{
    const u32 v = r->v;
    const u8 *l, *c;
    u32 ln, cn;
    if (v < V(1, 3, 0)) g32(r);
    for (int i = 0; i < 6; i++) S(r);                /* name, file, parameters, dir, icon, comment */
    cond_data(r, &l, &ln, &c, &cn);
    if (v >= V(5, 3, 5)) S(r);                       /* AppUserModelID */
    if (v >= V(6, 1, 0)) gskip(r, 16);               /* toast activator CLSID */
    winver(r);
    g32(r);                                          /* icon index */
    if (v >= V(1, 3, 24)) g32(r);                    /* show command */
    if (v >= V(1, 3, 15)) E(r, 3);                   /* close on exit */
    if (v >= V(2, 0, 7)) g16(r);                     /* hot key */
    ifl f = { r, 0, 0, 0, 0 };
    F(&f, 1); F(&f, v < V(1, 3, 26)); F(&f, 1); F(&f, 1);
    F(&f, v >= V(5, 0, 3) && v < V(6, 3, 0));
    F(&f, v >= V(5, 4, 2));
    F(&f, v >= V(5, 5, 0));
    F(&f, v >= V(6, 1, 0));
    F_end(&f, 0);
}

static INO_COLD void parse_ini(ird *r)
{
    const u8 *l, *c;
    u32 ln, cn;
    if (r->v < V(1, 3, 0)) g32(r);
    S(r); S(r); S(r); S(r);
    cond_data(r, &l, &ln, &c, &cn);
    winver(r);
    g8(r);
}

static INO_COLD void parse_registry(ird *r)
{
    const u32 v = r->v;
    const u8 *l, *c;
    u32 ln, cn;
    if (v < V(1, 3, 0)) g32(r);
    S(r); S(r); S(r);                                /* key, name, value */
    cond_data(r, &l, &ln, &c, &cn);
    if (v >= V(4, 0, 11) && v < V(4, 1, 0)) S(r);
    winver(r);
    g32(r);                                          /* root key */
    if (v >= V(4, 1, 0)) g16(r);
    E(r, v >= V(5, 2, 5) ? 7 : 6);                   /* value type */
    if (v >= IV(7, 0, 0, 3)) g8(r);                  /* bitness */
    ifl f = { r, 0, 0, 0, 0 };
    for (int i = 0; i < 5; i++) F(&f, 1);
    F(&f, v >= V(1, 2, 6));
    F(&f, v >= V(1, 3, 9)); F(&f, v >= V(1, 3, 9));
    F(&f, v >= V(1, 3, 12));
    F(&f, v >= V(1, 3, 16));
    F(&f, v >= V(5, 1, 0) && v < IV(7, 0, 0, 3)); F(&f, v >= V(5, 1, 0) && v < IV(7, 0, 0, 3));
    F_end(&f, 0);
}

static INO_COLD void parse_delete(ird *r)
{
    const u8 *l, *c;
    u32 ln, cn;
    if (r->v < V(1, 3, 0)) g32(r);
    S(r);
    cond_data(r, &l, &ln, &c, &cn);
    winver(r);
    E(r, 3);
}

static INO_COLD void parse_run(ird *r)
{
    const u32 v = r->v;
    const u8 *l, *c;
    u32 ln, cn;
    if (v < V(1, 3, 0)) g32(r);
    S(r); S(r); S(r);                                /* file, parameters, working dir */
    if (v >= V(1, 3, 9)) S(r);                       /* RunOnceId */
    if (v >= V(2, 0, 2)) S(r);                       /* status message */
    if (v >= V(5, 1, 13)) S(r);                      /* verb */
    if (v >= V(2, 0, 0) || r->isx) S(r);             /* description */
    cond_data(r, &l, &ln, &c, &cn);
    if (v >= IV(7, 0, 0, 1)) S(r);                   /* OnLog */
    winver(r);
    if (v >= V(1, 3, 24)) g32(r);                    /* show command */
    E(r, 3);                                         /* wait */
    if (v >= IV(7, 0, 0, 3)) g8(r);                  /* bitness */
    ifl f = { r, 0, 0, 0, 0 };
    F(&f, v >= V(1, 2, 3));
    F(&f, v >= V(1, 3, 9) || (r->isx && v >= V(1, 3, 8)));
    for (int i = 0; i < 4; i++) F(&f, v >= V(2, 0, 0));
    F(&f, v >= V(2, 0, 8));
    F(&f, v >= V(5, 1, 10) && v < IV(7, 0, 0, 3)); F(&f, v >= V(5, 1, 10) && v < IV(7, 0, 0, 3));
    F(&f, v >= V(5, 2, 0));
    F(&f, v >= V(6, 1, 0));
    F(&f, v >= V(6, 3, 0));
    F_end(&f, 0);
}

static INO_COLD void parse_data(ird *r, const ino_hdr *h, pf_data *d)
{
    const u32 v = r->v;
    __builtin_memset(d, 0, sizeof *d);
    d->slice = g32(r);
    d->last_slice = g32(r);
    if (v < V(4, 0, 0)) {
        if (d->slice < 1 || d->last_slice < 1) r->soft = 1;
        else { d->slice--; d->last_slice--; }
    }
    d->chunk_off = v >= V(6, 5, 2) ? g64(r) : g32(r);
    d->file_off = v >= V(4, 0, 1) ? g64(r) : 0;
    if (v >= V(4, 0, 0)) { d->size = g64(r); d->chunk_size = g64(r); }
    else { d->size = g32(r); d->chunk_size = g32(r); }
    const u8 *q;
    if (v >= V(6, 4, 0)) { if ((q = rget(r, 32))) __builtin_memcpy(d->ck, q, 32); d->ck_type = CK_SHA256; }
    else if (v >= V(5, 3, 9)) { if ((q = rget(r, 20))) __builtin_memcpy(d->ck, q, 20); d->ck_type = CK_SHA1; }
    else if (v >= V(4, 2, 0)) { if ((q = rget(r, 16))) __builtin_memcpy(d->ck, q, 16); d->ck_type = CK_MD5; }
    else { wr32(d->ck, g32(r)); d->ck_type = v >= V(4, 0, 1) ? CK_CRC : CK_ADLER; }
    d->mtime = g64(r);                               /* FILETIME */
    g32(r); g32(r);                                  /* file version */
    ifl f = { r, 0, 0, 0, 0 };
    F(&f, 1);                                        /* VersionInfoValid */
    F(&f, v < V(6, 4, 3));                           /* VersionInfoNotValid */
    int bz = F(&f, v >= V(2, 0, 17) && v < V(4, 0, 1));   /* BZipped */
    F(&f, v >= V(4, 0, 10));                         /* TimeStampInUTC */
    F(&f, v >= V(4, 1, 0) && v < V(6, 4, 3));        /* IsUninstallerExe */
    int call = F(&f, v >= V(4, 1, 8));               /* CallInstructionOptimized */
    F(&f, v >= V(4, 2, 0) && v < V(6, 4, 3));        /* Touch */
    int enc = F(&f, v >= V(4, 2, 2));                /* ChunkEncrypted */
    int comp = v >= V(4, 2, 5) ? F(&f, 1) : 1;       /* ChunkCompressed */
    F(&f, v >= V(5, 1, 13) && v < V(6, 4, 3));       /* SolidBreak */
    F(&f, v >= V(5, 5, 7) && v < V(6, 3, 0)); F(&f, v >= V(5, 5, 7) && v < V(6, 3, 0));   /* Sign */
    F_end(&f, 0);
    if (v >= V(6, 3, 0) && v < V(6, 4, 3)) E(r, 4);  /* sign mode */
    d->comp = comp ? h->comp : C_STORED;
    if (bz) d->comp = C_BZIP2;
    d->enc = !enc ? EN_NONE : v >= V(6, 4, 0) ? EN_XCHACHA : v >= V(5, 3, 9) ? EN_ARC4_SHA1 : EN_ARC4_MD5;
    d->filter = !call ? FI_NONE : v < V(5, 2, 0) ? FI_4108 : v < V(5, 3, 9) ? FI_5200 : FI_5309;
}

static void parse_free(ino_parse *P)
{
    gz_free(P->f);
    gz_free(P->d);
    gz_free(P->dt);
    P->f = 0; P->d = 0; P->dt = 0;
    P->nf = P->nd = P->ndt = 0;
}

/* Parse both header blocks with data version v. Returns 0 (clean), 1 (unexpected
 * values, usable), -1 (layout does not fit) or GZ_E_NOMEM. */
static INO_COLD int parse_all(ino_parse *P, const u8 *b0, size_t n0, const u8 *b1, size_t n1,
                     u32 v, u8 uni, u8 isx)
{
    parse_free(P);
    P->lang_cp = 0;
    P->lang_cp_mixed = 0;
    ird r = { b0, b0 + n0, b0, v, uni, isx, 0, 0 };
    ino_hdr *h = &P->h;
    parse_header(&r, h);
    if (r.bad) return -1;
    /* every entry takes at least 4 bytes: absurd counts cannot fit */
    u64 tot = (u64)h->n_lang + h->n_msg + h->n_perm + h->n_type + h->n_comp + h->n_task + h->n_dir +
              h->n_issig + h->n_file + h->n_icon + h->n_ini + h->n_reg + h->n_del + h->n_udel +
              h->n_run + h->n_urun;
    u64 rest = (u64)(r.end - r.p);
    if (tot > rest / 4 || h->n_file > rest / 32 || h->n_dir > rest / 13 || h->n_data > n1 / 40) return -1;
    for (u32 i = 0; i < h->n_lang && !r.bad; i++) parse_language(&r, P);
    if (v < V(4, 0, 0)) parse_wizard_dlls(&r, h);
    for (u32 i = 0; i < h->n_msg && !r.bad; i++) {
        S(&r); S(&r);
        i32 lang = (i32)g32(&r);
        if (lang >= 0 && (u32)lang >= h->n_lang && h->n_lang) r.soft = 1;
    }
    for (u32 i = 0; i < h->n_perm && !r.bad; i++) S(&r);
    for (u32 i = 0; i < h->n_type && !r.bad; i++) parse_type(&r);
    for (u32 i = 0; i < h->n_comp && !r.bad; i++) parse_component(&r);
    for (u32 i = 0; i < h->n_task && !r.bad; i++) parse_task(&r);
    if (r.bad) return -1;
    P->d = (pf_dir *)gz_alloc((size_t)h->n_dir * sizeof(pf_dir) + 1);
    P->f = (pf_file *)gz_alloc((size_t)h->n_file * sizeof(pf_file) + 1);
    if (!P->d || !P->f) return GZ_E_NOMEM;
    for (u32 i = 0; i < h->n_dir && !r.bad; i++) parse_dir(&r, &P->d[i]);
    P->nd = h->n_dir;
    for (u32 i = 0; i < h->n_issig && !r.bad; i++) { S(&r); S(&r); S(&r); }
    for (u32 i = 0; i < h->n_file && !r.bad; i++) parse_file(&r, &P->f[i]);
    P->nf = h->n_file;
    for (u32 i = 0; i < h->n_icon && !r.bad; i++) parse_icon(&r);
    for (u32 i = 0; i < h->n_ini && !r.bad; i++) parse_ini(&r);
    for (u32 i = 0; i < h->n_reg && !r.bad; i++) parse_registry(&r);
    for (u32 i = 0; i < h->n_del && !r.bad; i++) parse_delete(&r);
    for (u32 i = 0; i < h->n_udel && !r.bad; i++) parse_delete(&r);
    for (u32 i = 0; i < h->n_run && !r.bad; i++) parse_run(&r);
    for (u32 i = 0; i < h->n_urun && !r.bad; i++) parse_run(&r);
    if (v >= V(4, 0, 0)) parse_wizard_dlls(&r, h);
    if (r.bad || r.p != r.end) return -1;            /* the block must be used up exactly */
    int soft = r.soft;

    ird r1 = { b1, b1 + n1, b1, v, uni, isx, 0, 0 };
    P->dt = (pf_data *)gz_alloc((size_t)h->n_data * sizeof(pf_data) + 1);
    if (!P->dt) return GZ_E_NOMEM;
    for (u32 i = 0; i < h->n_data && !r1.bad; i++) parse_data(&r1, h, &P->dt[i]);
    P->ndt = h->n_data;
    if (r1.bad || r1.p != r1.end) return -1;
    soft |= r1.soft;
    for (u32 i = 0; i < P->nf; i++)
        if (P->f[i].loc >= P->ndt && P->f[i].loc != 0xFFFFFFFFu) soft = 1;
    return soft ? 1 : 0;
}

/* ---------------- version string ---------------- */

/* Known data versions: value << 2 | variant (1 = Unicode, 2 = ISX). The layout
 * of the next known versions is tried when the stated one does not fit. */
static const u32 known_versions[] = {
#define K(a, b, c, d, f) (IV(a, b, c, d) << 2 | (f))
    K(1,3,3,0,0), K(1,3,9,0,0), K(1,3,10,0,0), K(1,3,10,0,2), K(1,3,12,1,2), K(1,3,21,0,0),
    K(1,3,21,0,2), K(1,3,24,0,0), K(1,3,24,0,2), K(1,3,25,0,0), K(1,3,25,0,2), K(2,0,0,0,0),
    K(2,0,1,0,0), K(2,0,2,0,0), K(2,0,5,0,0), K(2,0,6,0,0), K(2,0,6,0,2), K(2,0,7,0,0),
    K(2,0,8,0,0), K(2,0,8,0,2), K(2,0,10,0,2), K(2,0,11,0,0), K(2,0,11,0,2), K(2,0,17,0,0),
    K(2,0,17,0,2), K(2,0,18,0,0), K(2,0,18,0,2), K(3,0,0,0,0), K(3,0,1,0,0), K(3,0,1,0,2),
    K(3,0,3,0,0), K(3,0,3,0,2), K(3,0,4,0,0), K(3,0,4,0,2), K(3,0,5,0,0), K(3,0,6,1,2),
    K(4,0,0,0,0), K(4,0,1,0,0), K(4,0,3,0,0), K(4,0,5,0,0), K(4,0,9,0,0), K(4,0,10,0,0),
    K(4,0,11,0,0), K(4,1,0,0,0), K(4,1,2,0,0), K(4,1,3,0,0), K(4,1,4,0,0), K(4,1,5,0,0),
    K(4,1,6,0,0), K(4,1,8,0,0), K(4,2,0,0,0), K(4,2,1,0,0), K(4,2,2,0,0), K(4,2,3,0,0),
    K(4,2,4,0,0), K(4,2,5,0,0), K(4,2,6,0,0), K(5,0,0,0,0), K(5,0,1,0,0), K(5,0,3,0,0),
    K(5,0,4,0,0), K(5,1,0,0,0), K(5,1,2,0,0), K(5,1,7,0,0), K(5,1,10,0,0), K(5,1,13,0,0),
    K(5,2,0,0,0), K(5,2,1,0,0), K(5,2,3,0,0), K(5,2,5,0,0), K(5,2,5,0,1), K(5,3,0,0,0),
    K(5,3,0,0,1), K(5,3,3,0,0), K(5,3,3,0,1), K(5,3,5,0,0), K(5,3,5,0,1), K(5,3,6,0,0),
    K(5,3,6,0,1), K(5,3,7,0,0), K(5,3,7,0,1), K(5,3,8,0,0), K(5,3,8,0,1), K(5,3,9,0,0),
    K(5,3,9,0,1), K(5,3,10,0,0), K(5,3,10,0,1), K(5,3,10,1,0), K(5,3,10,1,1), K(5,4,2,0,0),
    K(5,4,2,0,1), K(5,4,2,1,0), K(5,4,2,1,1), K(5,5,0,0,0), K(5,5,0,0,1), K(5,5,0,1,0),
    K(5,5,0,1,1), K(5,5,6,0,0), K(5,5,6,0,1), K(5,5,7,0,0), K(5,5,7,0,1), K(5,5,7,1,0),
    K(5,5,7,1,1), K(5,6,0,0,0), K(5,6,0,0,1), K(5,6,2,0,0), K(5,6,2,0,1), K(6,0,0,0,1),
    K(6,1,0,0,1), K(6,3,0,0,1), K(6,4,0,0,1), K(6,4,0,1,1), K(6,4,2,0,1), K(6,4,3,0,1),
    K(6,5,0,0,1), K(6,5,2,0,1), K(6,6,0,0,1), K(6,6,1,0,1), K(6,7,0,0,1), K(7,0,0,1,1),
    K(7,0,0,3,1)
#undef K
};

static u32 next_version(u32 v, u32 variant)
{
    for (u32 i = 0; i < GZ_COUNTOF(known_versions); i++) {
        u32 k = known_versions[i];
        if ((k & 3) == variant && (k >> 2) > v) return k >> 2;
    }
    return 0;
}

static int contains(const u8 *s, u32 n, const char *lit)
{
    u32 m = 0;
    while (lit[m]) m++;
    for (u32 i = 0; i + m <= n; i++)
        if (!__builtin_memcmp(s + i, lit, m)) return 1;
    return 0;
}

static u32 num(const u8 *s, u32 n, u32 *i)
{
    u32 x = 0, st = *i;
    while (*i < n && s[*i] >= '0' && s[*i] <= '9' && *i - st < 6) x = x * 10 + (s[(*i)++] - '0');
    return *i > st ? x : 0xFFFFFFFFu;
}

/* Parse the 64-byte data version field. *hl: header length (12 or 64).
 * Returns GZ_OK, GZ_E_FORMAT or GZ_E_METHOD (16-bit installers). */
static INO_COLD int parse_version(const u8 *s, u32 *v, u8 *uni, u8 *isx, u32 *hl)
{
    *uni = *isx = 0;
    if (s[0] == 'i' && s[11] == 0x1a) {               /* "i1.2.10--32\x1a" */
        if (s[2] != '.' || s[4] != '.' || s[7] != '-' || s[8] != '-') return GZ_E_FORMAT;
        if (s[1] < '0' || s[1] > '9' || s[3] < '0' || s[3] > '9' ||
            s[5] < '0' || s[5] > '9' || s[6] < '0' || s[6] > '9') return GZ_E_FORMAT;
        if (s[9] == '1' && s[10] == '6') return GZ_E_METHOD;
        if (s[9] != '3' || s[10] != '2') return GZ_E_FORMAT;
        *v = V(s[1] - '0', s[3] - '0', (s[5] - '0') * 10 + (s[6] - '0'));
        *hl = 12;
        return GZ_OK;
    }
    u32 n = 0;
    while (n < 64 && s[n]) n++;
    if (!contains(s, n, "Inno Setup")) return GZ_E_FORMAT;
    u32 best = 0;
    for (u32 b = 0; b < n; b++) {
        if (s[b] != '(') continue;
        u32 i = b + 1;
        u32 a = num(s, n, &i);
        if (a > 255 || i >= n || s[i] != '.') continue;
        i++;
        u32 bb = num(s, n, &i);
        if (bb > 255 || i >= n || s[i] != '.') continue;
        i++;
        u32 c = num(s, n, &i);
        if (c > 255 || i >= n) continue;
        if (s[i] == 'a') i++;
        u32 d = 0;
        if (i < n && s[i] == '.') {
            i++;
            d = num(s, n, &i);
            if (d > 255) d = 0;
        }
        u32 x = IV(a, bb, c, d);
        if (x > best) best = x;
    }
    if (!best) return GZ_E_FORMAT;
    *v = best;
    *uni = best >= V(6, 3, 0) || contains(s, n, "(u)") || contains(s, n, "(U)");
    *isx = contains(s, n, "My Inno Setup Extensions") || contains(s, n, "with ISX");
    *hl = 64;
    return GZ_OK;
}

/* ---------------- locating the loader table ---------------- */

static const u8 ldr_magic[7][12] = {
    { 'r', 'D', 'l', 'P', 't', 'S', '0', '2', 0x87, 'e', 'V', 'x' },
    { 'r', 'D', 'l', 'P', 't', 'S', '0', '4', 0x87, 'e', 'V', 'x' },
    { 'r', 'D', 'l', 'P', 't', 'S', '0', '5', 0x87, 'e', 'V', 'x' },
    { 'r', 'D', 'l', 'P', 't', 'S', '0', '6', 0x87, 'e', 'V', 'x' },
    { 'r', 'D', 'l', 'P', 't', 'S', '0', '7', 0x87, 'e', 'V', 'x' },
    { 'r', 'D', 'l', 'P', 't', 'S', 0xcd, 0xe6, 0xd7, '{', 0x0b, '*' },
    { 'n', 'S', '5', 'W', '7', 'd', 'T', 0x83, 0xaa, 0x1b, 0x0f, 'j' },   /* modified loaders */
};
static const u32 ldr_ver[7] = { V(1, 2, 10), V(4, 0, 0), V(4, 0, 3), V(4, 0, 10), V(4, 1, 6), V(5, 1, 5), V(5, 1, 5) };

/* Offset table at pos: setup-0 and setup-1 offsets. */
static INO_COLD int read_table(gz_src *s, u64 pos, u64 *o0, u64 *o1)
{
    u8 b[64];
    if (pos >= s->size) return GZ_E_FORMAT;
    u32 n = (u32)GZ_MIN((u64)sizeof b, s->size - pos);
    if (n < 40 || gz_src_read_exact(s, pos, b, n)) return GZ_E_FORMAT;
    u32 lv = 0;
    for (u32 i = 0; i < 7; i++)
        if (!__builtin_memcmp(b, ldr_magic[i], 12)) lv = ldr_ver[i];
    if (!lv) return GZ_E_FORMAT;
    u32 p = 12, crc_end;
    if (lv >= V(5, 1, 5)) {
        u32 rev = rd32(b + 12);
        if (rev == 2) {                  /* 6.5.0+: 64-bit TotalSize, OffsetEXE, Offset0, Offset1 */
            if (n < 64) return GZ_E_FORMAT;
            *o0 = rd64(b + 40);
            *o1 = rd64(b + 48);
            crc_end = 60;
            if (gz_crc32(0, b, crc_end) != rd32(b + crc_end)) return GZ_E_FORMAT;
            return (*o0 >> 62) || (*o1 >> 62) ? GZ_E_FORMAT : GZ_OK;
        }
        if (rev != 1) return GZ_E_FORMAT;
        p = 16;
    }
    p += 8;                              /* TotalSize, OffsetEXE */
    if (lv < V(4, 1, 6)) p += 4;         /* CompressedSizeEXE */
    p += 8;                              /* UncompressedSizeEXE, CRC/Adler of the EXE */
    if (lv < V(4, 0, 0)) p += 4;         /* message offset */
    if (p + 8 > n) return GZ_E_FORMAT;
    *o0 = rd32(b + p);
    *o1 = rd32(b + p + 4);
    crc_end = p + 8;
    if (lv >= V(4, 0, 10) && (crc_end + 4 > n || gz_crc32(0, b, crc_end) != rd32(b + crc_end)))
        return GZ_E_FORMAT;
    return GZ_OK;
}

/* RCDATA resource 11111 of a PE file: file offset of its data. */
static INO_COLD int find_rcdata(gz_src *s, u64 *off)
{
    u8 b[512];
    if (s->size < 0x40 || gz_src_read_exact(s, 0, b, 0x40) || b[0] != 'M' || b[1] != 'Z') return 0;
    u32 pe = rd32(b + 0x3C);
    if (pe < 0x40 || pe > (1u << 20) || (u64)pe + 24 + 240 > s->size) return 0;
    if (gz_src_read_exact(s, pe, b, 24 + 240)) return 0;
    if (rd32(b) != 0x00004550u) return 0;
    u32 nsec = rd16(b + 6), optsz = rd16(b + 20), magic = rd16(b + 24);
    u32 dd = magic == 0x20b ? 24 + 112 : 24 + 96, nrva = rd32(b + dd - 4);
    if ((magic != 0x10b && magic != 0x20b) || nrva < 3 || dd + 24 > 24u + optsz || nsec > 96) return 0;
    u32 rva = rd32(b + dd + 16);
    if (!rva) return 0;
    u64 sec = (u64)pe + 24 + optsz;
    u64 base = 0;
    int found = 0;
    u32 sva = 0, svs = 0, sraw = 0;
    for (u32 i = 0; i < nsec; i++) {
        u8 h[40];
        if (gz_src_read_exact(s, sec + 40 * i, h, 40)) return 0;
        u32 vs = rd32(h + 8), va = rd32(h + 12), rs = rd32(h + 16), ra = rd32(h + 20);
        u32 span = vs > rs ? vs : rs;
        if (rva >= va && rva - va < span) { base = (u64)ra + (rva - va); sva = va; svs = span; sraw = ra; found = 1; break; }
    }
    if (!found) return 0;
    /* three levels: type 10 (RT_RCDATA) -> name 11111 -> first language */
    u64 dir = base;
    const u32 want[3] = { 10, 11111, 0xFFFFFFFFu };
    for (int lev = 0; lev < 3; lev++) {
        u8 dh[16];
        if (gz_src_read_exact(s, dir, dh, 16)) return 0;
        u32 nn = rd16(dh + 12), ni = rd16(dh + 14), tot = nn + ni;
        if (tot > 4096) return 0;
        u32 ent = 0;
        int hit = 0;
        for (u32 k = 0; k < tot; k++) {
            u8 e[8];
            if (gz_src_read_exact(s, dir + 16 + 8 * (u64)k, e, 8)) return 0;
            if (want[lev] == 0xFFFFFFFFu || (k >= nn && rd32(e) == want[lev])) { ent = rd32(e + 4); hit = 1; break; }
        }
        if (!hit) return 0;
        int sub = (ent >> 31) != 0;
        if (sub != (lev < 2)) return 0;
        dir = base + (ent & 0x7FFFFFFFu);
    }
    u8 de[8];
    if (gz_src_read_exact(s, dir, de, 8)) return 0;
    u32 drva = rd32(de);
    if (drva < sva || drva - sva >= svs) return 0;   /* data is in the resource section */
    *off = (u64)sraw + (drva - sva);
    return 1;
}

/* Setup-0 / setup-1 offsets of an installer. Raw "setup-0.bin" files start
 * with the version string. */
static INO_COLD int ino_locate(gz_src *s, u64 *o0, u64 *o1)
{
    u8 b[12];
    if (s->size < 64 || gz_src_read_exact(s, 0, b, 12)) return GZ_E_FORMAT;
    if (b[0] == 'M' && b[1] == 'Z') {
        if (s->size >= 0x3C && !gz_src_read_exact(s, 0x30, b, 12) && rd32(b) == 0x6f6e6e49u &&
            rd32(b + 4) == ~rd32(b + 8) && !read_table(s, rd32(b + 4), o0, o1))
            return GZ_OK;
        u64 t;
        if (find_rcdata(s, &t) && !read_table(s, t, o0, o1)) return GZ_OK;
        return GZ_E_FORMAT;
    }
    if (!__builtin_memcmp(b, "Inno Setup S", 12) || !__builtin_memcmp(b, "My Inno Setu", 12) ||
        (b[0] == 'i' && b[11] == 0x1a)) {
        *o0 = 0;
        *o1 = 0;
        return GZ_OK;
    }
    return GZ_E_FORMAT;
}

static int ino_probe(gz_src *s, const u8 *head, u32 n)
{
    u64 o0, o1;
    if (n < 64 || (head[0] != 'M' && head[0] != 'I' && head[0] != 'i')) return 0;
    if (ino_locate(s, &o0, &o1)) return 0;
    u8 vs[64];
    u32 v, hl;
    u8 uni, isx;
    if (o0 >= s->size || s->size - o0 < 64 || gz_src_read_exact(s, o0, vs, 64)) return 0;
    int r = parse_version(vs, &v, &uni, &isx, &hl);
    if (r == GZ_E_FORMAT) return 0;
    return o0 ? 90 : 60;
}

/* ---------------- header blocks ---------------- */

typedef struct { const u8 *p; size_t n; } mem_rd;

static int mem_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    mem_rd *m = (mem_rd *)ctx;
    u32 k = m->n < cap ? (u32)m->n : cap;
    __builtin_memcpy(buf, m->p, k);
    m->p += k;
    m->n -= k;
    *got = k;
    return GZ_OK;
}

typedef struct { mem_rd rd; gz_mem_sink *ms; } mem_io;
static int mem_io_read(void *ctx, u8 *buf, u32 cap, u32 *got) { return mem_read(&((mem_io *)ctx)->rd, buf, cap, got); }
static int mem_io_write(void *ctx, const u8 *p, size_t n) { return gz_mem_write(((mem_io *)ctx)->ms, p, n); }

static void *lz_new(void) { return gz_lzma_dec_new(); }
static void lz_free(void *p) { gz_lzma_dec_free((gz_lzma_dec *)p); }
static void *bz_new(void) { return gz_bzip2_dec_new(); }
static void bz_free(void *p) { gz_bzip2_dec_free((gz_bzip2_dec *)p); }

/* zlib stream header (CMF, FLG): Deflate, no preset dictionary */
static int zlib_hdr(const u8 *p) { return (p[0] & 0x0F) == 8 && (p[0] >> 4) <= 7 && !(p[1] & 0x20) && (p[0] * 256u + p[1]) % 31 == 0; }

/* Read the compressed block at *pos (advanced past it) into a new buffer. */
static INO_COLD int read_block(gz_src *s, u64 *pos, u32 v, gz_ctx *c, u8 **out, size_t *outn)
{
    u8 h[13];
    u32 hl = v >= V(4, 0, 9) ? (v >= V(6, 7, 0) ? 13 : 9) : 12;
    *out = 0;
    *outn = 0;
    if (*pos >= s->size || s->size - *pos < hl) return GZ_E_TRUNC;
    int r = gz_src_read_exact(s, *pos, h, hl);
    if (r) return r;
    if (gz_crc32(0, h + 4, hl - 4) != rd32(h)) return GZ_E_CRC;
    u64 stored;
    int comp;
    if (v >= V(4, 0, 9)) {
        stored = hl == 13 ? rd64(h + 4) : rd32(h + 4);
        comp = !h[hl - 1] ? C_STORED : v >= V(4, 1, 6) ? C_LZMA1 : C_ZLIB;
    } else {
        u32 cs = rd32(h + 4), us = rd32(h + 8);
        if (cs == 0xFFFFFFFFu) { stored = us; comp = C_STORED; }
        else { stored = cs; comp = C_ZLIB; }
        stored += (stored + 4095) / 4096 * 4;
    }
    u64 at = *pos + hl;
    if (stored > s->size - at) return GZ_E_TRUNC;
    if (stored > HDR_MAX) return GZ_E_LIMIT;
    u8 *raw = (u8 *)gz_alloc((size_t)stored + 1);
    if (!raw) return GZ_E_NOMEM;
    r = gz_src_read_exact(s, at, raw, (u32)stored);
    if (r) { gz_free(raw); return r; }
    *pos = at + stored;
    /* 4 KiB pieces, each after the CRC-32 of its bytes: compact in place */
    size_t o = 0, i = 0;
    while (i < stored) {
        if (stored - i < 5) { gz_free(raw); return GZ_E_DATA; }
        size_t k = GZ_MIN((size_t)stored - i - 4, (size_t)4096);
        if (gz_crc32(0, raw + i + 4, k) != rd32(raw + i)) { gz_free(raw); return GZ_E_CRC; }
        __builtin_memmove(raw + o, raw + i + 4, k);
        o += k;
        i += 4 + k;
    }
    if (comp == C_STORED) { *out = raw; *outn = o; return GZ_OK; }
    gz_mem_sink ms = { 0, 0, 0, HDR_MAX };
    if (comp == C_ZLIB) {
        if (o < 2 || !zlib_hdr(raw)) { gz_free(raw); return GZ_E_DATA; }
        gz_inflater *z = gz_ctx_inflater(c);
        if (!z) { gz_free(raw); return GZ_E_NOMEM; }
        mem_io mi = { { raw + 2, o - 2 }, &ms };
        gz_stream_io io = { mem_io_read, mem_io_write, &mi };
        r = gz_inflate_run(z, &io, 0);
    } else {
        gz_lzma_dec *d = (gz_lzma_dec *)gz_ctx_slot(c, GZ_SLOT_LZMA, lz_new, lz_free);
        if (!d) { gz_free(raw); return GZ_E_NOMEM; }
        if (o < 5) r = GZ_E_DATA;
        else {
            gz_lzma_dec_set_limit(d, HDR_DICT_MAX);
            r = gz_lzma_decode_mem(d, raw, raw + 5, o - 5, GZ_SIZE_UNKNOWN, gz_mem_write, &ms, 0);
            gz_lzma_dec_set_limit(d, 0);
        }
    }
    gz_free(raw);
    if (r) { gz_mem_sink_free(&ms); return r == GZ_E_LIMIT || r == GZ_E_NOMEM ? r : GZ_E_DATA; }
    *out = ms.p;
    *outn = ms.n;
    if (!ms.p) { *out = (u8 *)gz_alloc(1); if (!*out) return GZ_E_NOMEM; }
    return GZ_OK;
}

/* ---------------- archive state ---------------- */

typedef struct {
    u64 off, size;            /* slice offset of the "zlb\x1a" magic, compressed size */
    u64 need;                 /* decompressed bytes used by its files                 */
    u32 slice, nloc;
    u8 comp, enc;
} ino_chunk;

typedef struct {
    u64 file_off, size;
    u32 chunk;
    u8 filter, ck_type;
    u8 ck[32];
} ino_loc;

typedef struct {
    u32 ver;
    u8 uni, pw_type;
    u64 data_off;             /* setup-1 in the installer; 0 = external slices        */
    ino_chunk *ch; u32 nch;
    ino_loc *loc; u32 nloc;
    u32 dict;                 /* LZMA dictionary (method text)                        */
    u32 cp;                   /* code page of ANSI strings (passwords)                */
    u8 pw_hash[20];
    u8 salt[44]; u32 salt_len;
    u32 kdf_iter;             /* XChaCha20: PBKDF2 iterations                         */
    u8 kdf_salt[16];
    u8 nonce[24];
    /* disk spanning: slice sources (a->vols index + 1, 0 = not found) */
    u32 nslices;
    u32 *slice_vol;
    u64 *slice_size;
} ino_priv;

static void ino_close(gz_archive *a)
{
    ino_priv *p = (ino_priv *)a->priv;
    if (!p) return;
    gz_free(p->ch);
    gz_free(p->loc);
    gz_free(p->slice_vol);
    gz_free(p->slice_size);
    gz_free(p);
    a->priv = 0;
}

/* ---------------- names ---------------- */

typedef struct { u8 *p; size_t n, cap; } pool;

static int pool_put(pool *b, const void *s, size_t n)
{
    if (b->n + n > b->cap) {
        size_t nc = b->cap ? b->cap : 4096;
        while (nc < b->n + n) nc *= 2;
        if (nc > ((size_t)1 << 30)) return GZ_E_LIMIT;
        u8 *q = (u8 *)gz_realloc(b->p, nc);
        if (!q) return GZ_E_NOMEM;
        b->p = q;
        b->cap = nc;
    }
    __builtin_memcpy(b->p + b->n, s, n);
    b->n += n;
    return GZ_OK;
}

/* character i of a name in either encoding */
static u32 nch(const u8 *s, u32 i, int uni) { return uni ? rd16(s + 2 * (size_t)i) : s[i]; }

/* Destination -> entry name: "{{" -> "{", path separators inside constants
 * ("{code:Dir|{pf}\x}") -> '_'. DBCS lead bytes keep their trail byte. */
static INO_COLD int conv_name(pool *b, const u8 *s, u32 bytes, int uni, const u8 *lead)
{
    u32 n = uni ? bytes / 2 : bytes, depth = 0;
    for (u32 i = 0; i < n; i++) {
        u32 ch = nch(s, i, uni);
        u8 two[4];
        if (!uni && lead && (lead[ch >> 3] >> (ch & 7) & 1) && i + 1 < n) {
            two[0] = (u8)ch;
            two[1] = s[++i];
            if (pool_put(b, two, 2)) return GZ_E_NOMEM;
            continue;
        }
        if (ch == '{') {
            if (!depth && i + 1 < n && nch(s, i + 1, uni) == '{') i++;
            else depth++;
        } else if (ch == '}') {
            if (depth) depth--;
        } else if (depth && (ch == '\\' || ch == '/')) {
            ch = '_';
        }
        if (uni) wr16(two, (u16)ch); else two[0] = (u8)ch;
        if (pool_put(b, two, uni ? 2 : 1)) return GZ_E_NOMEM;
    }
    return GZ_OK;
}

static u32 name_hash(const u8 *s, u32 bytes, int uni)
{
    u32 n = uni ? bytes / 2 : bytes, h = 2166136261u;
    for (u32 i = 0; i < n; i++) {
        u32 ch = nch(s, i, uni);
        if (ch >= 'A' && ch <= 'Z') ch += 32;
        if (ch == '/') ch = '\\';
        h = (h ^ ch) * 16777619u;
    }
    return h;
}

static int name_eq(const u8 *x, u32 xn, const u8 *y, u32 yn, int uni)
{
    if (xn != yn) return 0;
    u32 n = uni ? xn / 2 : xn;
    for (u32 i = 0; i < n; i++) {
        u32 p = nch(x, i, uni), q = nch(y, i, uni);
        if (p >= 'A' && p <= 'Z') p += 32;
        if (q >= 'A' && q <= 'Z') q += 32;
        if (p == '/') p = '\\';
        if (q == '/') q = '\\';
        if (p != q) return 0;
    }
    return 1;
}

static int str_same(const u8 *x, u32 xn, const u8 *y, u32 yn)
{
    return xn == yn && (!xn || !__builtin_memcmp(x, y, xn));
}

/* innoextract's "simple expression": an identifier, used as the suffix as is */
static int simple_expr(const u8 *s, u32 bytes, int uni)
{
    u32 n = uni ? bytes / 2 : bytes;
    if (!n) return 0;
    for (u32 i = 0; i < n; i++) {
        u32 ch = nch(s, i, uni);
        int id = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' || ch == '-';
        if (!id && (!i || !((ch >= '0' && ch <= '9') || ch == '\\'))) return 0;
    }
    return 1;
}

/* Name with an ASCII suffix inserted before the extension of the last component. */
static INO_COLD int name_with_suffix(pool *b, const u8 *s, u32 bytes, int uni, const char *suf)
{
    u32 n = uni ? bytes / 2 : bytes, cut = n, start = 0;
    for (u32 i = 0; i < n; i++) {
        u32 ch = nch(s, i, uni);
        if (ch == '\\' || ch == '/') { start = i + 1; cut = n; }
        else if (ch == '.' && i > start) cut = i;
    }
    u32 cb = uni ? cut * 2 : cut;
    if (pool_put(b, s, cb)) return GZ_E_NOMEM;
    for (const char *q = suf; *q; q++) {
        u8 two[2];
        if (uni) wr16(two, (u8)*q); else two[0] = (u8)*q;
        if (pool_put(b, two, uni ? 2 : 1)) return GZ_E_NOMEM;
    }
    return pool_put(b, s + cb, bytes - cb);
}

/* ---------------- open ---------------- */

static int load_headers(gz_src *s, u64 pos0, u32 v, gz_ctx *c, u8 **b0, size_t *n0, u8 **b1, size_t *n1)
{
    u64 pos = pos0;
    int r = read_block(s, &pos, v, c, b0, n0);
    if (r) return r;
    r = read_block(s, &pos, v, c, b1, n1);
    if (r) { gz_free(*b0); *b0 = 0; }
    return r;
}

static u32 block_class(u32 v)
{
    return (v >= V(4, 0, 9)) | (v >= V(4, 1, 6)) << 1 | (v >= V(6, 5, 0)) << 2 | (v >= V(6, 7, 0)) << 3;
}

/* data area of slice k: source and offset */
static gz_src *slice_src(gz_archive *a, gz_src *s, u32 k, u64 *base, u64 *size)
{
    ino_priv *p = (ino_priv *)a->priv;
    if (p->data_off) {
        if (k) return 0;
        *base = p->data_off;
        *size = s->size - p->data_off;
        return s;
    }
    if (k >= p->nslices || !p->slice_vol[k]) return 0;
    gz_src *v = a->vols[p->slice_vol[k] - 1];
    *base = 0;
    *size = p->slice_size[k];
    return v;
}

/* Open the external slices "<base>-1.bin" (or "-1a.bin" with several per disk). */
static INO_COLD void open_slices(gz_archive *a, const gz_open_opts *o, const ino_hdr *h, u32 nslices)
{
    ino_priv *p = (ino_priv *)a->priv;
    if (!o->open_volume || !o->file_name || !nslices || nslices > MAX_SLICES) return;
    p->slice_vol = (u32 *)gz_alloc((size_t)nslices * sizeof(u32));
    p->slice_size = (u64 *)gz_alloc((size_t)nslices * sizeof(u64));
    a->vols = (gz_src **)gz_alloc((size_t)nslices * sizeof(gz_src *));
    if (!p->slice_vol || !p->slice_size || !a->vols) return;
    p->nslices = nslices;
    /* directory of the installer */
    size_t fl = gz_wcslen(o->file_name), dl = fl;
    while (dl && o->file_name[dl - 1] != '/' && o->file_name[dl - 1] != '\\') dl--;
    gzch *nm = (gzch *)gz_alloc((dl + 300) * sizeof(gzch));
    if (!nm) return;
    u32 spd = h->slices_per_disk ? h->slices_per_disk : 1;
    for (u32 k = 0; k < nslices; k++) {
        for (int pass = 0; pass < 2; pass++) {
            /* base name from the header, else the installer's own name */
            size_t m = dl;
            __builtin_memcpy(nm, o->file_name, dl * sizeof(gzch));
            if (pass == 0) {
                if (!h->base_n || h->base_n > 200) continue;
                u32 cnt = p->uni ? h->base_n / 2 : h->base_n;
                for (u32 i = 0; i < cnt; i++) {
                    gzch ch = (gzch)nch(h->base, i, p->uni);
                    nm[m++] = ch == '/' || ch == '\\' || ch == ':' || ch < 0x20 ? '_' : ch;   /* stay in the directory */
                }
            } else {
                size_t st = dl, en = fl;
                for (size_t i = fl; i > dl; i--) if (o->file_name[i - 1] == '.') { en = i - 1; break; }
                if (en - st > 200) continue;
                for (size_t i = st; i < en; i++) nm[m++] = o->file_name[i];
            }
            char t[24];
            u32 tn = 0, disk = spd == 1 ? k + 1 : k / spd + 1;
            char dg[12];
            int dn = 0;
            do { dg[dn++] = (char)('0' + disk % 10); disk /= 10; } while (disk);
            t[tn++] = '-';
            while (dn) t[tn++] = dg[--dn];
            if (spd > 1) t[tn++] = (char)('a' + k % spd);
            t[tn++] = '.'; t[tn++] = 'b'; t[tn++] = 'i'; t[tn++] = 'n';
            for (u32 i = 0; i < tn; i++) nm[m++] = (gzch)t[i];
            nm[m] = 0;
            gz_src *v = 0;
            if (o->open_volume(o->user, nm, &v) || !v) continue;
            u8 sh[12];
            if (v->size < 12 || gz_src_read_exact(v, 0, sh, 12) ||
                (__builtin_memcmp(sh, "idska32\x1a", 8) && __builtin_memcmp(sh, "idska16\x1a", 8)) ||
                rd32(sh + 8) > v->size || rd32(sh + 8) < 12) {
                gz_src_free(v);
                continue;
            }
            a->vols[a->nvols++] = v;
            p->slice_vol[k] = a->nvols;
            p->slice_size[k] = rd32(sh + 8);
            break;
        }
    }
    gz_free(nm);
}

static int loc_cmp(const ino_parse *P, u32 x, u32 y)
{
    const pf_data *a = &P->dt[x], *b = &P->dt[y];
    if (a->slice != b->slice) return a->slice < b->slice ? -1 : 1;
    if (a->chunk_off != b->chunk_off) return a->chunk_off < b->chunk_off ? -1 : 1;
    return x < y ? -1 : x > y;
}

/* heap sort of location indices by (slice, chunk offset) */
static INO_COLD void sort_locs(const ino_parse *P, u32 *ix, u32 n)
{
    for (u32 st = n / 2; st-- > 0;) {
        for (u32 r = st;;) {
            u32 ch = 2 * r + 1;
            if (ch >= n) break;
            if (ch + 1 < n && loc_cmp(P, ix[ch], ix[ch + 1]) < 0) ch++;
            if (loc_cmp(P, ix[r], ix[ch]) >= 0) break;
            u32 t = ix[r]; ix[r] = ix[ch]; ix[ch] = t;
            r = ch;
        }
    }
    for (u32 e = n; e-- > 1;) {
        u32 t = ix[0]; ix[0] = ix[e]; ix[e] = t;
        for (u32 r = 0;;) {
            u32 ch = 2 * r + 1;
            if (ch >= e) break;
            if (ch + 1 < e && loc_cmp(P, ix[ch], ix[ch + 1]) < 0) ch++;
            if (loc_cmp(P, ix[r], ix[ch]) >= 0) break;
            u32 t2 = ix[r]; ix[r] = ix[ch]; ix[ch] = t2;
            r = ch;
        }
    }
}

/* Group locations into chunks. */
static INO_COLD int build_chunks(ino_priv *p, const ino_parse *P)
{
    u32 n = P->ndt;
    p->loc = (ino_loc *)gz_alloc((size_t)n * sizeof(ino_loc) + 1);
    p->ch = (ino_chunk *)gz_alloc((size_t)n * sizeof(ino_chunk) + 1);
    u32 *ix = (u32 *)gz_alloc((size_t)n * sizeof(u32) + 1);
    if (!p->loc || !p->ch || !ix) { gz_free(ix); return GZ_E_NOMEM; }
    for (u32 i = 0; i < n; i++) ix[i] = i;
    sort_locs(P, ix, n);
    p->nloc = n;
    for (u32 k = 0; k < n; k++) {
        const pf_data *d = &P->dt[ix[k]];
        ino_chunk *c = p->nch ? &p->ch[p->nch - 1] : 0;
        if (!c || c->slice != d->slice || c->off != d->chunk_off || c->size != d->chunk_size ||
            c->comp != d->comp || c->enc != d->enc) {
            c = &p->ch[p->nch++];
            c->off = d->chunk_off;
            c->size = d->chunk_size;
            c->slice = d->slice;
            c->comp = d->comp;
            c->enc = d->enc;
            c->need = 0;
            c->nloc = 0;
        }
        ino_loc *l = &p->loc[ix[k]];
        l->file_off = d->file_off;
        l->size = d->size;
        l->chunk = p->nch - 1;
        l->filter = d->filter;
        l->ck_type = d->ck_type;
        __builtin_memcpy(l->ck, d->ck, 32);
        u64 end = d->file_off + d->size;
        if (end < d->file_off) end = ~(u64)0;
        if (end > c->need) c->need = end;
        c->nloc++;
    }
    gz_free(ix);
    return GZ_OK;
}

/* dictionary size of the first LZMA chunk (method text) */
static INO_COLD void read_dict(gz_archive *a, gz_src *s)
{
    ino_priv *p = (ino_priv *)a->priv;
    for (u32 i = 0; i < p->nch; i++) {
        ino_chunk *c = &p->ch[i];
        if ((c->comp != C_LZMA1 && c->comp != C_LZMA2) || c->enc) continue;
        u64 base, size;
        gz_src *v = slice_src(a, s, c->slice, &base, &size);
        u8 b[9];
        if (!v || c->off > size || size - c->off < 9 || gz_src_read_exact(v, base + c->off, b, 9) ||
            __builtin_memcmp(b, chunk_magic, 4))
            return;
        p->dict = c->comp == C_LZMA1 ? rd32(b + 5) : gz_lzma2_dict_size(b[4]);
        return;
    }
}

/* case-insensitive name set (open addressing over pool offsets) */
typedef struct { u32 *slot; u32 cap; } nset;   /* slot: index + 1, 0 = empty */

static int nset_init(nset *t, u32 n)
{
    t->cap = 64;
    while (t->cap < n * 2) t->cap *= 2;
    t->slot = (u32 *)gz_alloc((size_t)t->cap * sizeof(u32));
    return t->slot ? GZ_OK : GZ_E_NOMEM;
}

/* Find name (bytes in pool b at off/len, listed in offs[2*i]) or insert index idx. */
static INO_COLD int nset_find_add(nset *t, const pool *b, const u32 *offs, u32 off, u32 len, int uni, u32 idx, int add)
{
    u32 h = name_hash(b->p + off, len, uni) & (t->cap - 1);
    while (t->slot[h]) {
        u32 j = t->slot[h] - 1;
        if (name_eq(b->p + offs[2 * j], offs[2 * j + 1], b->p + off, len, uni)) return (int)j;
        h = (h + 1) & (t->cap - 1);
    }
    if (add) t->slot[h] = idx + 1;
    return -1;
}

static int pool_ascii(pool *b, const char *q, int uni)
{
    for (; *q; q++) {
        u8 two[2];
        if (uni) wr16(two, (u8)*q); else two[0] = (u8)*q;
        if (pool_put(b, two, uni ? 2 : 1)) return GZ_E_NOMEM;
    }
    return GZ_OK;
}

static INO_COLD int add_entries(gz_archive *a, ino_parse *P, gz_ctx *c)
{
    ino_priv *p = (ino_priv *)a->priv;
    const int uni = p->uni;
    const int ne_kind = uni ? GZ_NE_UTF16LE : GZ_NE_LEGACY;
    const u8 *lead = !uni && P->h.has_lead ? P->h.lead : 0;
    const u32 nf = P->nf;
    pool b = { 0, 0, 0 }, fin = { 0, 0, 0 };
    nset names = { 0, 0 }, finals = { 0, 0 };
    u32 *offs = (u32 *)gz_alloc((size_t)nf * 2 * sizeof(u32) + 8);      /* converted names    */
    u32 *foffs = (u32 *)gz_alloc((size_t)nf * 2 * sizeof(u32) + 8);     /* final names        */
    u32 *file = (u32 *)gz_alloc((size_t)nf * sizeof(u32) + 4);          /* parse index        */
    u32 *group = (u32 *)gz_alloc((size_t)nf * sizeof(u32) + 4);         /* first same name    */
    u32 *gnext = (u32 *)gz_alloc((size_t)nf * sizeof(u32) + 4);         /* next "$n" of group */
    u8 *gfl = (u8 *)gz_alloc((size_t)nf + 1);                           /* group: 1 several, 2 languages differ, 4 architectures differ */
    u8 *first_in_chunk = (u8 *)gz_alloc((size_t)p->nch + 1);
    int r = GZ_OK;
    if (!offs || !foffs || !file || !group || !gnext || !gfl || !first_in_chunk) { r = GZ_E_NOMEM; goto out; }
    if ((r = nset_init(&names, nf)) || (r = nset_init(&finals, nf + P->nd))) goto out;

    /* converted names; the same name with the same data is listed once */
    u32 cnt = 0;
    for (u32 i = 0; i < nf && !r; i++) {
        const pf_file *f = &P->f[i];
        if (f->loc >= P->ndt) continue;                  /* external file: nothing stored */
        if (!(i & 1023) && gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        u32 off = (u32)b.n;
        r = conv_name(&b, f->dst, f->dn & (uni ? ~1u : ~0u), uni, lead);
        /* no destination: the uninstaller of old versions (installed as unins000.exe),
         * else an internal file */
        if (!r && b.n == off) {
            if (!f->uninst) continue;
            r = pool_ascii(&b, "{app}\\unins000.exe", uni);
        }
        if (r) break;
        u32 len = (u32)(b.n - off);
        offs[2 * cnt] = off;
        offs[2 * cnt + 1] = len;
        int j = nset_find_add(&names, &b, offs, off, len, uni, cnt, 1);
        if (j >= 0 && P->f[file[j]].loc == f->loc) { b.n = off; continue; }
        file[cnt] = i;
        group[cnt] = j >= 0 ? group[j] : cnt;
        gnext[cnt] = 1;
        if (j >= 0) {
            const pf_file *g = &P->f[file[group[cnt]]];
            gfl[group[cnt]] |= 1;
            if (!str_same(g->lang, g->ln, f->lang, f->ln)) gfl[group[cnt]] |= 2;
            if (g->arch != f->arch) gfl[group[cnt]] |= 4;
        }
        cnt++;
    }
    if (r) goto out;

    /* final names: variants of a name get "@lang" / "@32bit" / "@64bit", then "$n" */
    for (u32 i = 0; i < cnt && !r; i++) {
        const pf_file *f = &P->f[file[i]];
        u8 gf = gfl[group[i]];
        char suf[96];
        u32 sn = 0;
        if ((gf & 2) && simple_expr(f->lang, f->ln, uni)) {
            u32 m = uni ? f->ln / 2 : f->ln;
            suf[sn++] = '@';
            for (u32 k = 0; k < m && sn < 60; k++) {
                u32 ch = nch(f->lang, k, uni);
                suf[sn++] = (char)(ch == '\\' ? '$' : ch);
            }
        }
        if ((gf & 4) && f->arch) {
            for (const char *t = f->arch == 1 ? "@32bit" : "@64bit"; *t; t++) suf[sn++] = *t;
        }
        for (u32 k = 0;;) {
            u32 tn = sn;
            if (k) {                                     /* "$<k-1>" */
                u32 x = k - 1, dn = 0;
                char dg[12];
                do { dg[dn++] = (char)('0' + x % 10); x /= 10; } while (x);
                suf[tn++] = '$';
                while (dn) suf[tn++] = dg[--dn];
            }
            suf[tn] = 0;
            u32 st = (u32)fin.n;
            r = tn ? name_with_suffix(&fin, b.p + offs[2 * i], offs[2 * i + 1], uni, suf)
                   : pool_put(&fin, b.p + offs[2 * i], offs[2 * i + 1]);
            if (r) break;
            foffs[2 * i] = st;
            foffs[2 * i + 1] = (u32)fin.n - st;
            if (nset_find_add(&finals, &fin, foffs, st, foffs[2 * i + 1], uni, i, 1) < 0) {
                if (k) gnext[group[i]] = k + 1;
                break;
            }
            fin.n = st;
            k = k ? k + 1 : gnext[group[i]];
            if (k > cnt + 2) { r = GZ_E_FORMAT; break; }   /* cannot happen: a free number exists */
        }
    }

    /* entries */
    for (u32 i = 0; i < cnt && !r; i++) {
        const pf_file *f = &P->f[file[i]];
        const pf_data *d = &P->dt[f->loc];
        const ino_loc *l = &p->loc[f->loc];
        const ino_chunk *ch = &p->ch[l->chunk];
        gz_entry *e;
        r = gz_arc_add_named(a, fin.p + foffs[2 * i], foffs[2 * i + 1], ne_kind, &e);
        if (r) break;
        e->usize = d->size;
        e->csize = 0;
        if (!first_in_chunk[l->chunk]) { first_in_chunk[l->chunk] = 1; e->csize = ch->size; }
        e->aux32 = f->loc;
        e->mtime = d->mtime;
        e->mtime_kind = d->mtime ? GZ_MT_FILETIME : GZ_MT_NONE;
        e->attr = f->attr == 0xFFFFFFFFu ? 0 : (f->attr & 0x27u);
        e->method = ch->comp;
        e->flags = (u16)((ch->nloc > 1 ? IF_SOLID : 0) | (ch->enc ? IF_ENC : 0));
        e->aux = l->filter;
        e->enc = ch->enc ? GZ_ENC_OTHER : GZ_ENC_NONE;
        if (d->ck_type == CK_CRC) { e->crc = rd32(d->ck); e->has_crc = 1; }
    }

    /* [Dirs] entries, each name once */
    gz_free(names.slot);
    names.slot = 0;
    gz_free(offs);
    offs = (u32 *)gz_alloc((size_t)P->nd * 2 * sizeof(u32) + 8);
    if (!r && (!offs || nset_init(&names, P->nd))) r = GZ_E_NOMEM;
    b.n = 0;
    for (u32 i = 0; i < P->nd && !r; i++) {
        const pf_dir *dd = &P->d[i];
        u32 st = (u32)b.n;
        r = conv_name(&b, dd->name, dd->n & (uni ? ~1u : ~0u), uni, lead);
        if (r) break;
        offs[2 * i] = st;
        offs[2 * i + 1] = (u32)b.n - st;
        if (!offs[2 * i + 1] || nset_find_add(&names, &b, offs, st, offs[2 * i + 1], uni, i, 1) >= 0) continue;
        gz_entry *e;
        r = gz_arc_add_named(a, b.p + st, offs[2 * i + 1], ne_kind, &e);
        if (r) break;
        e->is_dir = 1;
        e->usize = e->csize = 0;
        e->attr = 0x10 | (dd->attr & 0x07u);
        e->aux32 = 0xFFFFFFFFu;
    }
out:
    gz_free(b.p);
    gz_free(fin.p);
    gz_free(names.slot);
    gz_free(finals.slot);
    gz_free(offs);
    gz_free(foffs);
    gz_free(file);
    gz_free(group);
    gz_free(gnext);
    gz_free(gfl);
    gz_free(first_in_chunk);
    return r;
}

static INO_COLD int ino_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    u64 o0, o1;
    int r = ino_locate(s, &o0, &o1);
    if (r) return r;
    if (o0 >= s->size || s->size - o0 < 64 || o1 > s->size) return GZ_E_FORMAT;
    u8 vs[64];
    r = gz_src_read_exact(s, o0, vs, 64);
    if (r) return r;
    u32 v, hl;
    u8 uni, isx;
    r = parse_version(vs, &v, &uni, &isx, &hl);
    if (r) return r;
    ino_priv *p = (ino_priv *)gz_alloc(sizeof(ino_priv));
    if (!p) return GZ_E_NOMEM;
    a->priv = p;
    p->data_off = o1;
    u64 pos = o0 + hl;
    if (v >= V(6, 5, 0)) {
        /* TSetupEncryptionHeader: CRC, use (none / files / full), KDF salt and
         * iterations, base nonce, password test */
        u8 eh[53];
        if (s->size - pos < 53) return GZ_E_TRUNC;
        r = gz_src_read_exact(s, pos, eh, 53);
        if (r) return r;
        if (gz_crc32(0, eh + 4, 49) != rd32(eh)) return GZ_E_CRC;
        if (eh[4] > 1) return GZ_E_METHOD;               /* encrypted headers */
        if (eh[4]) {
            __builtin_memcpy(p->kdf_salt, eh + 5, 16);
            p->kdf_iter = rd32(eh + 21);
            __builtin_memcpy(p->nonce, eh + 25, 24);
            __builtin_memcpy(p->pw_hash, eh + 49, 4);
            p->pw_type = PW_XCHACHA;
        }
        pos += 53;
    }

    /* headers: the stated version first, then the next known layouts */
    ino_parse P;
    __builtin_memset(&P, 0, sizeof P);
    u8 *b0 = 0, *b1 = 0;
    size_t n0 = 0, n1 = 0;
    u32 bclass = 0xFFFFFFFFu, variant = (u32)(uni ? 1 : 0) | (u32)(isx ? 2 : 0);
    u32 tv = v, soft_v = 0;
    int got = -1, first_err = 0;
    for (int t = 0; t < MAX_TRIES && tv; t++, tv = next_version(tv, variant)) {
        if (block_class(tv) != bclass) {
            if (block_class(tv) & 4 && !(block_class(v) & 4)) break;   /* would need the encryption header */
            if (!(block_class(tv) & 4) && (block_class(v) & 4)) break;
            gz_free(b0); gz_free(b1);
            b0 = b1 = 0;
            r = load_headers(s, pos, tv, c, &b0, &n0, &b1, &n1);
            if (r) {
                if (!first_err) first_err = r;
                if (r == GZ_E_NOMEM || r == GZ_E_LIMIT) break;
                bclass = 0xFFFFFFFFu;
                continue;
            }
            bclass = block_class(tv);
        }
        int pr = parse_all(&P, b0, n0, b1, n1, tv, uni, isx);
        if (pr == GZ_E_NOMEM) { r = pr; break; }
        if (pr == 0) { got = 0; v = tv; break; }
        if (pr == 1 && !soft_v) soft_v = tv;
    }
    if (got && soft_v) {
        /* nothing parsed cleanly: take the first layout with unexpected values */
        if (block_class(soft_v) != bclass) {
            gz_free(b0); gz_free(b1);
            b0 = b1 = 0;
            r = load_headers(s, pos, soft_v, c, &b0, &n0, &b1, &n1);
        } else r = GZ_OK;
        if (!r && parse_all(&P, b0, n0, b1, n1, soft_v, uni, isx) >= 0) { got = 0; v = soft_v; }
    }
    if (got) {
        parse_free(&P);
        gz_free(b0); gz_free(b1);
        return r == GZ_E_NOMEM ? r : first_err ? first_err : GZ_E_FORMAT;
    }
    p->ver = v;
    p->uni = uni;
    if (v < V(6, 5, 0)) {                                 /* else from the encryption header */
        p->pw_type = P.h.pw_type;
        __builtin_memcpy(p->pw_hash, P.h.pw_hash, 20);
        __builtin_memcpy(p->salt, P.h.salt, 44);
        p->salt_len = P.h.salt_len;
        if (p->pw_type == PW_XCHACHA && P.h.salt_len == 44) {
            __builtin_memcpy(p->kdf_salt, P.h.salt, 16);
            p->kdf_iter = rd32(P.h.salt + 16);
            __builtin_memcpy(p->nonce, P.h.salt + 20, 24);
        }
    }
    p->cp = !uni && P.lang_cp && !P.lang_cp_mixed ? P.lang_cp : 0;
    r = build_chunks(p, &P);
    if (!r && !p->data_off) {
        u32 ns = 0;
        for (u32 i = 0; i < P.ndt; i++) {
            u32 k = P.dt[i].last_slice > P.dt[i].slice ? P.dt[i].last_slice : P.dt[i].slice;
            if (k < MAX_SLICES && k + 1 > ns) ns = k + 1;
        }
        open_slices(a, o, &P.h, ns);
    }
    if (!r) read_dict(a, s);
    if (!r) r = add_entries(a, &P, c);
    parse_free(&P);
    gz_free(b0);
    gz_free(b1);
    if (r) return r;
    a->win_names = 1;
    for (u32 i = 0; i < p->nch; i++) if (p->ch[i].nloc > 1) a->solid = 1;
    if (p->cp && a->codepage == GZ_CP_AUTO && gz_plat_cp_valid((int)p->cp)) a->codepage = (int)p->cp;
    gz_arc_set_type(a, "Inno Setup");
    return GZ_OK;
}

/* ---------------- passwords ---------------- */

/* Password bytes as the installer hashed them: UTF-16LE (Unicode builds) or the
 * code page of the installer. */
static u32 pw_bytes(const ino_priv *p, const gzch *pw, u8 *out, u32 cap)
{
    u32 n = (u32)gz_wcslen(pw);
    if (p->uni) {
        if (n > cap / 2) n = cap / 2;
        for (u32 i = 0; i < n; i++) wr16(out + 2 * i, pw[i]);
        return n * 2;
    }
    int k = gz_plat_wc2mb(p->cp ? (int)p->cp : gz_plat_acp(), pw, (int)n, out, (int)cap);
    if (k <= 0) {
        k = 0;
        for (u32 i = 0; i < n && (u32)k < cap; i++) out[k++] = (u8)pw[i];
    }
    return (u32)k;
}

/* XChaCha20 key = PBKDF2-SHA256(password, salt, ~200000 iterations): the last
 * derivation is kept per thread (every chunk of a non-solid installer needs it) */
#define KC_PW 512u
typedef struct { u8 salt[16]; u32 iter, pn; u8 pw[KC_PW]; u8 key[32]; int valid; } ino_kc;
static void *kc_new(void) { return gz_alloc(sizeof(ino_kc)); }
static void kc_free(void *p) { if (p) __builtin_memset(p, 0, sizeof(ino_kc)); gz_free(p); }

static void xc_key(const ino_priv *p, gz_ctx *c, const u8 *pw, u32 pn, u8 key[32])
{
    u32 it = p->kdf_iter ? p->kdf_iter : 1;
    ino_kc *k = c && pn <= KC_PW ? (ino_kc *)gz_ctx_slot(c, GZ_SLOT_MISC4, kc_new, kc_free) : 0;
    if (k && k->valid && k->iter == it && k->pn == pn && !__builtin_memcmp(k->salt, p->kdf_salt, 16) &&
        (!pn || !__builtin_memcmp(k->pw, pw, pn))) {
        __builtin_memcpy(key, k->key, 32);
        return;
    }
    gz_pbkdf2_sha256(pw, pn, p->kdf_salt, 16, it, key, 32);
    if (k) {
        __builtin_memcpy(k->salt, p->kdf_salt, 16);
        k->iter = it;
        k->pn = pn;
        if (pn) __builtin_memcpy(k->pw, pw, pn);
        __builtin_memcpy(k->key, key, 32);
        k->valid = 1;
    }
}

static int pw_check(const ino_priv *p, gz_ctx *c, const u8 *pw, u32 pn)
{
    switch (p->pw_type) {
    case PW_SHA1: {
        gz_sha1 h;
        u8 d[20];
        gz_sha1_init(&h);
        gz_sha1_update(&h, "PasswordCheckHash", 17);
        gz_sha1_update(&h, p->salt, p->salt_len);
        gz_sha1_update(&h, pw, pn);
        gz_sha1_final(&h, d);
        return !__builtin_memcmp(d, p->pw_hash, 20);
    }
    case PW_MD5: {
        ino_md5 h;
        u8 d[16];
        md5_init(&h);
        if (p->salt_len) {
            md5_update(&h, (const u8 *)"PasswordCheckHash", 17);
            md5_update(&h, p->salt, p->salt_len);
        }
        md5_update(&h, pw, pn);
        md5_final(&h, d);
        return !__builtin_memcmp(d, p->pw_hash, 16);
    }
    case PW_CRC:
        return gz_crc32(0, pw, pn) == rd32(p->pw_hash);
    case PW_XCHACHA: {
        u8 key[32], nonce[24], t[4] = { 0, 0, 0, 0 };
        ino_xc x;
        xc_key(p, c, pw, pn, key);
        __builtin_memcpy(nonce, p->nonce, 24);
        wr32(nonce + 8, ~rd32(nonce + 8));
        xc_init(&x, key, nonce);
        xc_crypt(&x, t, 4);
        return !__builtin_memcmp(t, p->pw_hash, 4);
    }
    }
    return 1;
}

/* Cipher state of a chunk: key from the password (checked), salt / nonce. */
typedef struct { int kind; ino_rc4 rc4; ino_xc xc; } ino_cipher;

/* ---------------- chunk input: slices, decryption ---------------- */

typedef struct {
    gz_archive *a;
    gz_src *s;                /* the installer                         */
    gz_src *v;                /* current slice source                  */
    u64 pos, end;             /* within v                              */
    u32 slice;
    u64 left;                 /* chunk bytes still to deliver          */
    ino_cipher *ci;
    volatile long *cancel;
    int (*sink)(void *, const u8 *, size_t);
    void *user;
} ino_in;

static int in_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    ino_in *x = (ino_in *)ctx;
    *got = 0;
    if (x->cancel && *x->cancel) return GZ_E_CANCEL;
    if (!x->left) return GZ_OK;
    if (x->pos >= x->end) {
        /* chunk continues in the next slice, after its 12-byte header */
        u64 base, size;
        gz_src *nv = slice_src(x->a, x->s, x->slice + 1, &base, &size);
        if (!nv || size < 12) return GZ_E_VOLUME;
        x->slice++;
        x->v = nv;
        x->pos = base + 12;
        x->end = base + size;
        if (x->pos >= x->end) return GZ_E_TRUNC;
    }
    u64 k = GZ_MIN(x->end - x->pos, x->left);
    if (k > cap) k = cap;
    u32 g = 0;
    int r = x->v->read_at(x->v, x->pos, buf, (u32)k, &g);
    if (r) return r;
    if (!g) return GZ_E_TRUNC;
    x->pos += g;
    x->left -= g;
    if (x->ci && x->ci->kind == EN_XCHACHA) xc_crypt(&x->ci->xc, buf, g);
    else if (x->ci && x->ci->kind) rc4_crypt(&x->ci->rc4, buf, g);
    *got = g;
    return GZ_OK;
}

static int in_exact(ino_in *x, u8 *b, u32 n)
{
    while (n) {
        u32 g;
        int r = in_read(x, b, n, &g);
        if (r) return r;
        if (!g) return GZ_E_TRUNC;
        b += g;
        n -= g;
    }
    return GZ_OK;
}

static int in_write(void *ctx, const u8 *p, size_t n)
{
    ino_in *x = (ino_in *)ctx;
    return x->sink(x->user, p, n);
}

/* Key the cipher of chunk ch (ARC4: reads the salt from in). */
static int cipher_init(const ino_priv *p, const ino_chunk *ch, ino_in *in, gz_ctx *c, ino_cipher *ci)
{
    u8 pw[1024];
    ci->kind = ch->enc;
    if (ch->enc == EN_NONE) return GZ_OK;
    if (!c->password || !c->password[0]) return GZ_E_PASSWORD;
    u32 pn = pw_bytes(p, c->password, pw, sizeof pw);
    if (!pw_check(p, c, pw, pn)) return GZ_E_PASSWORD;
    if (ch->enc == EN_XCHACHA) {
        u8 key[32], nonce[24];
        xc_key(p, c, pw, pn, key);
        __builtin_memcpy(nonce, p->nonce, 24);
        wr64(nonce, rd64(nonce) ^ ch->off);
        wr32(nonce + 8, rd32(nonce + 8) ^ ch->slice);
        xc_init(&ci->xc, key, nonce);
        return GZ_OK;
    }
    u8 salt[8], d[20];
    int r = in_exact(in, salt, 8);
    if (r) return r;
    if (ch->enc == EN_ARC4_SHA1) {
        gz_sha1 h;
        gz_sha1_init(&h);
        gz_sha1_update(&h, salt, 8);
        gz_sha1_update(&h, pw, pn);
        gz_sha1_final(&h, d);
        rc4_init(&ci->rc4, d, 20);
    } else {
        ino_md5 h;
        md5_init(&h);
        md5_update(&h, salt, 8);
        md5_update(&h, pw, pn);
        md5_final(&h, d);
        rc4_init(&ci->rc4, d, 16);
    }
    return GZ_OK;
}

static int ino_check_password(gz_archive *a, gz_src *s, u32 idx, gz_ctx *c)
{
    const ino_priv *p = (const ino_priv *)a->priv;
    const gz_entry *e = &a->e[idx];
    if (!e->enc) return GZ_OK;
    if (!c->password || !c->password[0]) return GZ_E_PASSWORD;
    u8 pw[1024];
    u32 pn = pw_bytes(p, c->password, pw, sizeof pw);
    (void)s;
    return pw_check(p, c, pw, pn) ? GZ_OK : GZ_E_PASSWORD;
}

/* Decode chunk ch, pushing at least `need` bytes (or all of it) into sink.
 * A sink returning GZ_E_SKIP stops decoding (returned as is). */
static int run_chunk(gz_archive *a, gz_src *s, const ino_chunk *ch, u64 need, gz_ctx *c,
                     int (*sink)(void *, const u8 *, size_t), void *user)
{
    const ino_priv *p = (const ino_priv *)a->priv;
    u64 base, size;
    gz_src *v = slice_src(a, s, ch->slice, &base, &size);
    if (!v) return GZ_E_VOLUME;
    if (ch->off >= size) return GZ_E_TRUNC;
    /* magic, ARC4 salt and data may continue in the next slices */
    u32 pre = 4 + (ch->enc == EN_ARC4_MD5 || ch->enc == EN_ARC4_SHA1 ? 8 : 0);
    ino_in in = { a, s, v, base + ch->off, base + size, ch->slice, ch->size + pre, 0, c->cancel, sink, user };
    if (in.left < pre) return GZ_E_LIMIT;
    u8 m[4];
    int r = in_exact(&in, m, 4);
    if (r) return r;
    if (__builtin_memcmp(m, chunk_magic, 4)) return GZ_E_DATA;
    ino_cipher *ci = 0;
    if (ch->enc) {
        ci = (ino_cipher *)gz_alloc(sizeof *ci);
        if (!ci) return GZ_E_NOMEM;
        r = cipher_init(p, ch, &in, c, ci);
        if (r) { gz_free(ci); return r; }
        in.ci = ci;
    }
    gz_stream_io io = { in_read, in_write, &in };
    switch (ch->comp) {
    case C_STORED: {
        u8 *buf = gz_ctx_buffer(c, 256u << 10);
        if (!buf) { r = GZ_E_NOMEM; break; }
        for (;;) {
            u32 g;
            r = in_read(&in, buf, 256u << 10, &g);
            if (r || !g) break;
            if ((r = sink(user, buf, g))) break;
        }
        break;
    }
    case C_ZLIB: {
        u8 zh[2];
        u32 g = 0, g2 = 0;
        r = in_read(&in, zh, 1, &g);
        if (!r && g) r = in_read(&in, zh + 1, 1, &g2);
        if (!r && (g + g2 != 2 || !zlib_hdr(zh))) r = GZ_E_DATA;
        gz_inflater *z = r ? 0 : gz_ctx_inflater(c);
        if (!r && !z) r = GZ_E_NOMEM;
        if (!r) r = gz_inflate_run(z, &io, 0);
        break;
    }
    case C_BZIP2: {
        gz_bzip2_dec *d = (gz_bzip2_dec *)gz_ctx_slot(c, GZ_SLOT_BZIP2, bz_new, bz_free);
        r = d ? gz_bzip2_decode(d, &io, need, 0, 0) : GZ_E_NOMEM;
        break;
    }
    case C_LZMA1:
    case C_LZMA2: {
        u8 pr[5];
        u32 pn = ch->comp == C_LZMA1 ? 5 : 1, g = 0, t = 0;
        while (t < pn && !(r = in_read(&in, pr + t, pn - t, &g)) && g) t += g;
        if (!r && t < pn) r = GZ_E_DATA;
        gz_lzma_dec *d = r ? 0 : (gz_lzma_dec *)gz_ctx_slot(c, GZ_SLOT_LZMA, lz_new, lz_free);
        if (!r && !d) r = GZ_E_NOMEM;
        if (r) break;
        gz_lzma_dec_set_flags(d, GZ_LZMA_LENIENT_END);
        r = ch->comp == C_LZMA1 ? gz_lzma_decode(d, pr, &io, need, 0) : gz_lzma2_decode(d, pr[0], &io, need, 0);
        gz_lzma_dec_set_flags(d, 0);       /* the decoder is shared through the ctx slot */
        break;
    }
    default:
        r = GZ_E_METHOD;
    }
    gz_free(ci);
    return r;
}

/* ---------------- per-file output: call filter, checksum ---------------- */

#define FBUF 65536u

typedef struct {
    gz_out *out;
    u32 idx;
    int opened, st;
    u8 filter, ck_type;
    u64 left;                 /* bytes of this file still to come                */
    /* call filter */
    u32 f_off, f_addr, f_left;
    u32 f_hold;               /* bytes held in fbuf (5200: lookahead)            */
    u8 *fbuf;
    /* checksum */
    union { u32 crc; ino_md5 md5; gz_sha1 sha1; gz_sha256 sha256; } h;
    /* data shared with the following files */
    gz_mem_sink *dup;
} ino_fo;

static void fo_hash_init(ino_fo *f)
{
    switch (f->ck_type) {
    case CK_ADLER: f->h.crc = 1; break;
    case CK_CRC: f->h.crc = 0; break;
    case CK_MD5: md5_init(&f->h.md5); break;
    case CK_SHA1: gz_sha1_init(&f->h.sha1); break;
    case CK_SHA256: gz_sha256_init(&f->h.sha256); break;
    }
}

static int fo_emit(ino_fo *f, const u8 *p, size_t n)
{
    switch (f->ck_type) {
    case CK_ADLER: f->h.crc = adler32(f->h.crc, p, n); break;
    case CK_CRC: f->h.crc = gz_crc32(f->h.crc, p, n); break;
    case CK_MD5: md5_update(&f->h.md5, p, n); break;
    case CK_SHA1: gz_sha1_update(&f->h.sha1, p, n); break;
    case CK_SHA256: gz_sha256_update(&f->h.sha256, p, n); break;
    }
    if (f->dup && gz_mem_write(f->dup, p, n)) f->dup = 0;     /* too big: next pass */
    if (!f->opened || f->st) return GZ_OK;
    int r = f->out->write(f->out, p, n);
    if (r == GZ_E_CANCEL) return r;
    if (r) f->st = r;
    return GZ_OK;
}

/* Inno Setup 4.1.8 - 5.1.x: E8/E9 targets made absolute byte by byte */
static void filt_4108(ino_fo *f, u8 *p, size_t n)
{
    size_t i = 0;
    while (i < n) {
        if (!f->f_left) {
            size_t st = i;
            while (i < n && (p[i] & 0xFE) != 0xE8) i++;
            f->f_off += (u32)(i - st);
            if (i >= n) break;
            f->f_addr = ~f->f_off + 1;
            f->f_left = 4;
        } else {
            f->f_addr += p[i];
            p[i] = (u8)f->f_addr;
            f->f_addr >>= 8;
            f->f_left--;
        }
        f->f_off++;
        i++;
    }
}

/* Inno Setup 5.2.0+: 24-bit targets of E8/E9 not crossing a 64 KiB block, high
 * byte 00/FF (5.3.9+: flipped with bit 23). Converts p[0..n), returns the number
 * of final bytes; the rest (< 5) must be presented again (unless final). */
static size_t filt_5200(ino_fo *f, u8 *p, size_t n, int final)
{
    const u32 base = f->f_off;              /* stream offset of p[0] */
    const int flip = f->filter == FI_5309;
    size_t i = 0;
    for (;;) {
        while (i < n && (p[i] & 0xFE) != 0xE8) i++;      /* next E8 / E9 */
        if (i >= n) break;
        u32 pos = base + (u32)i;
        if (0x10000u - (pos & 0xFFFFu) < 5) { i++; continue; }
        if (n - i < 5) {
            if (final) break;
            f->f_off = pos;
            return i;
        }
        u8 *q = p + i + 1;
        if (q[3] == 0x00 || q[3] == 0xFF) {
            u32 rel = (q[0] | (u32)q[1] << 8 | (u32)q[2] << 16) - ((pos + 5) & 0xFFFFFF);
            q[0] = (u8)rel; q[1] = (u8)(rel >> 8); q[2] = (u8)(rel >> 16);
            if (flip && (rel & 0x800000)) q[3] = (u8)~q[3];
        }
        i += 5;
    }
    f->f_off = base + (u32)n;
    return n;
}

static int fo_write(ino_fo *f, const u8 *p, size_t n)
{
    if (f->filter == FI_NONE) return fo_emit(f, p, n);
    while (n) {
        size_t k = GZ_MIN(n, (size_t)FBUF - f->f_hold);
        __builtin_memcpy(f->fbuf + f->f_hold, p, k);
        p += k;
        n -= k;
        size_t tot = f->f_hold + k, done;
        if (f->filter == FI_4108) { filt_4108(f, f->fbuf, tot); done = tot; }
        else done = filt_5200(f, f->fbuf, tot, 0);
        int r = fo_emit(f, f->fbuf, done);
        if (r) return r;
        f->f_hold = (u32)(tot - done);
        if (f->f_hold) __builtin_memmove(f->fbuf, f->fbuf + done, f->f_hold);
    }
    return GZ_OK;
}

static int fo_finish(ino_fo *f, const ino_loc *l)
{
    if (f->f_hold) {
        size_t done = filt_5200(f, f->fbuf, f->f_hold, 1);
        int r = fo_emit(f, f->fbuf, done);
        if (r) return r;
        f->f_hold = 0;
    }
    u8 d[32];
    int ok = 1;
    switch (f->ck_type) {
    case CK_ADLER: case CK_CRC: ok = f->h.crc == rd32(l->ck); break;
    case CK_MD5: md5_final(&f->h.md5, d); ok = !__builtin_memcmp(d, l->ck, 16); break;
    case CK_SHA1: gz_sha1_final(&f->h.sha1, d); ok = !__builtin_memcmp(d, l->ck, 20); break;
    case CK_SHA256: gz_sha256_final(&f->h.sha256, d); ok = !__builtin_memcmp(d, l->ck, 32); break;
    }
    return ok ? GZ_OK : GZ_E_CRC;
}

/* ---------------- chunk passes ---------------- */

typedef struct {
    gz_archive *a;
    gz_out *out;
    gz_ctx *c;
    const u32 *job; u32 nj;   /* entries of the chunk, by (file offset, location)   */
    u8 *done;                 /* per job                                            */
    int *res;                 /* optional: status per job                           */
    u32 cur;                  /* job being written, or the next one                 */
    u64 pos;                  /* decompressed position                              */
    int active;
    ino_fo fo;
    gz_mem_sink dup;
    u8 *fbuf;
} ino_cx;

static const ino_loc *job_loc(const ino_cx *x, u32 j)
{
    const ino_priv *p = (const ino_priv *)x->a->priv;
    return &p->loc[x->a->e[x->job[j]].aux32];
}

static void set_res(ino_cx *x, int st)
{
    if (x->res) x->res[x->cur] = st;
}

/* open the current job's entry: GZ_OK (fo.opened tells), or a fatal error */
static int cx_open(ino_cx *x, u32 idx)
{
    int r = x->out->open(x->out, idx);
    x->fo.opened = !r;
    x->fo.st = GZ_OK;
    if (r == GZ_E_SKIP) { set_res(x, GZ_E_SKIP); return GZ_OK; }
    return r;
}

static int cx_close(ino_cx *x, u32 idx, int st)
{
    if (st == GZ_E_SKIP) st = GZ_OK;
    int r = x->out->close(x->out, idx, st);
    set_res(x, st);
    return r == GZ_E_CANCEL || st == GZ_E_CANCEL ? GZ_E_CANCEL : GZ_OK;
}

static int cx_start(ino_cx *x)
{
    u32 idx = x->job[x->cur];
    const ino_loc *l = job_loc(x, x->cur);
    ino_fo *f = &x->fo;
    __builtin_memset(f, 0, sizeof *f);
    f->out = x->out;
    f->idx = idx;
    f->filter = l->filter;
    f->ck_type = l->ck_type;
    f->f_off = 5;
    if (f->filter >= FI_5200) f->f_off = 0;
    f->left = l->size;
    f->fbuf = x->fbuf;
    fo_hash_init(f);
    x->dup.n = 0;
    /* the next job uses the same data: keep a copy */
    if (x->cur + 1 < x->nj && x->a->e[x->job[x->cur + 1]].aux32 == x->a->e[idx].aux32 && l->size <= DUP_MAX)
        f->dup = &x->dup;
    x->active = 1;
    return cx_open(x, idx);
}

static int cx_end(ino_cx *x)
{
    ino_fo *f = &x->fo;
    u32 idx = x->job[x->cur];
    const ino_loc *l = job_loc(x, x->cur);
    int st = fo_finish(f, l);
    if (st == GZ_E_CANCEL) return st;
    x->done[x->cur] = 1;
    x->active = 0;
    if (f->opened) {
        int r = cx_close(x, idx, f->st ? f->st : st);
        if (r) return r;
    }
    /* following jobs with the same data: replay the copy */
    u32 loc = x->a->e[idx].aux32;
    gz_mem_sink *dup = f->dup;
    while (x->cur + 1 < x->nj && x->a->e[x->job[x->cur + 1]].aux32 == loc) {
        if (!dup) { x->cur++; break; }               /* not buffered: next pass */
        x->cur++;
        u32 di = x->job[x->cur];
        x->done[x->cur] = 1;
        int r = x->out->open(x->out, di);
        if (r == GZ_E_SKIP) { set_res(x, GZ_E_SKIP); continue; }
        if (r) return r;
        int ws = dup->n ? x->out->write(x->out, dup->p, dup->n) : GZ_OK;
        r = cx_close(x, di, ws ? ws : st);
        if (r) return r;
    }
    x->cur++;
    return GZ_OK;
}

static int cx_write(void *u, const u8 *q, size_t n)
{
    ino_cx *x = (ino_cx *)u;
    if (gz_cancelled(x->c)) return GZ_E_CANCEL;
    while (n || (!x->active && x->cur < x->nj)) {
        int r;
        if (x->active) {
            size_t k = x->fo.left < n ? (size_t)x->fo.left : n;
            if ((r = fo_write(&x->fo, q, k))) return r;
            q += k; n -= k; x->pos += k; x->fo.left -= k;
            if (!x->fo.left && (r = cx_end(x))) return r;
            continue;
        }
        /* next job not done yet whose data lies ahead */
        while (x->cur < x->nj && (x->done[x->cur] || job_loc(x, x->cur)->file_off < x->pos)) x->cur++;
        if (x->cur >= x->nj) return GZ_E_SKIP;
        u64 t = job_loc(x, x->cur)->file_off;
        if (x->pos < t) {
            if (!n) return GZ_OK;
            u64 d = t - x->pos;
            if (d >= n) { x->pos += n; return GZ_OK; }
            q += d; n -= (size_t)d; x->pos = t;
        }
        if ((r = cx_start(x))) return r;
        if (!x->fo.left && (r = cx_end(x))) return r;
    }
    return GZ_OK;
}

/* open + close an entry with an error status (*res: what the entry got) */
static int fail_entry(gz_out *out, u32 idx, int st, int *res)
{
    int r = out->open(out, idx);
    if (r) {
        if (res) *res = GZ_E_SKIP;
        return r == GZ_E_SKIP ? GZ_OK : r;
    }
    if (res) *res = st;
    r = out->close(out, idx, st);
    return r == GZ_E_CANCEL ? r : GZ_OK;
}

static int fatal(int r) { return r == GZ_E_CANCEL || r == GZ_E_IO || r == GZ_E_CREATE || r == GZ_E_DISK; }

/* Extract entries job[0..nj) of chunk k (sorted by file offset); res: optional
 * status per job. */
static int extract_chunk(gz_archive *a, gz_src *s, u32 k, const u32 *job, u32 nj, gz_out *out,
                         gz_ctx *c, int *res)
{
    const ino_priv *p = (const ino_priv *)a->priv;
    const ino_chunk *ch = &p->ch[k];
    u8 one = 0;
    u8 *done = nj > 1 ? (u8 *)gz_alloc(nj) : &one;
    /* the call filter's buffer sits behind the stored-chunk read buffer of run_chunk */
    u8 *fbuf = gz_ctx_buffer(c, (256u << 10) + FBUF + 8);
    if (!done || !fbuf) { if (nj > 1) gz_free(done); return GZ_E_NOMEM; }
    fbuf += 256u << 10;
    int ret = GZ_OK;
    /* password problems before any output */
    if (ch->enc) {
        int pr = GZ_OK;
        if (!c->password || !c->password[0]) pr = GZ_E_PASSWORD;
        else {
            u8 pw[1024];
            u32 pn = pw_bytes(p, c->password, pw, sizeof pw);
            if (!pw_check(p, c, pw, pn)) pr = GZ_E_PASSWORD;
        }
        if (pr) {
            for (u32 j = 0; j < nj && !ret; j++) ret = fail_entry(out, job[j], pr, res ? res + j : 0);
            if (nj > 1) gz_free(done);
            return ret;
        }
    }
    u32 prev_left = 0xFFFFFFFFu;
    for (int pass = 0; pass < MAX_PASSES && !ret; pass++) {
        u64 need = 0;
        u32 left = 0;
        for (u32 j = 0; j < nj; j++) {
            if (done[j]) continue;
            const ino_loc *l = &p->loc[a->e[job[j]].aux32];
            u64 e = l->file_off + l->size;
            if (e < l->file_off) e = ~(u64)0;
            if (e > need) need = e;
            left++;
        }
        if (!left || left == prev_left) break;   /* done, or the last pass got nowhere */
        prev_left = left;
        ino_cx x;
        __builtin_memset(&x, 0, sizeof x);
        x.a = a; x.out = out; x.c = c; x.job = job; x.nj = nj; x.done = done; x.res = res; x.fbuf = fbuf;
        x.dup.limit = DUP_MAX;
        int r;
        if (!need) r = cx_write(&x, 0, 0);           /* only empty files */
        else r = run_chunk(a, s, ch, need, c, cx_write, &x);
        if (r == GZ_E_SKIP) r = GZ_OK;
        if (!r) r = cx_write(&x, 0, 0);              /* empty files at the very end */
        if (r == GZ_E_SKIP) r = GZ_OK;
        if (x.active) {
            /* stream ended inside the file */
            int st = r ? r : GZ_E_DATA;
            done[x.cur] = 1;
            if (x.fo.opened && cx_close(&x, x.job[x.cur], st) == GZ_E_CANCEL) r = GZ_E_CANCEL;
            if (!r) r = GZ_E_DATA;
        }
        gz_mem_sink_free(&x.dup);
        if (fatal(r)) { ret = r; break; }
        if (r) {
            for (u32 j = 0; j < nj && !ret; j++)
                if (!done[j]) { done[j] = 1; ret = fail_entry(out, job[j], r, res ? res + j : 0); }
            break;
        }
    }
    for (u32 j = 0; j < nj && !ret; j++)
        if (!done[j]) ret = fail_entry(out, job[j], GZ_E_DATA, res ? res + j : 0);
    if (nj > 1) gz_free(done);
    return ret;
}

static int dir_entry(gz_out *out, u32 idx)
{
    int r = out->open(out, idx);
    if (r) return r == GZ_E_SKIP ? GZ_OK : r;
    return out->close(out, idx, GZ_OK);
}

/* sort key of an entry inside its chunk */
static int job_less(const gz_archive *a, u32 x, u32 y)
{
    const ino_priv *p = (const ino_priv *)a->priv;
    const ino_loc *lx = &p->loc[a->e[x].aux32], *ly = &p->loc[a->e[y].aux32];
    if (lx->chunk != ly->chunk) return lx->chunk < ly->chunk;
    if (lx->file_off != ly->file_off) return lx->file_off < ly->file_off;
    if (a->e[x].aux32 != a->e[y].aux32) return a->e[x].aux32 < a->e[y].aux32;
    return x < y;
}

static void sort_jobs(const gz_archive *a, u32 *v, u32 n)
{
    /* merge sort with a scratch half (n entries, bottom-up), falls back to insertion */
    for (u32 i = 1; i < n && i < 32; i++) {
        u32 t = v[i], j = i;
        while (j && job_less(a, t, v[j - 1])) { v[j] = v[j - 1]; j--; }
        v[j] = t;
    }
    if (n <= 32) return;
    u32 *tmp = (u32 *)gz_alloc((size_t)n * sizeof(u32));
    if (!tmp) {
        for (u32 i = 32; i < n; i++) {
            u32 t = v[i], j = i;
            while (j && job_less(a, t, v[j - 1])) { v[j] = v[j - 1]; j--; }
            v[j] = t;
        }
        return;
    }
    /* runs of 32 by insertion, then merges */
    for (u32 st = 32; st < n; st += 32) {
        u32 en = GZ_MIN(st + 32, n);
        for (u32 i = st + 1; i < en; i++) {
            u32 t = v[i], j = i;
            while (j > st && job_less(a, t, v[j - 1])) { v[j] = v[j - 1]; j--; }
            v[j] = t;
        }
    }
    for (u32 w = 32; w < n; w *= 2) {
        for (u32 lo = 0; lo < n; lo += 2 * w) {
            u32 mid = GZ_MIN(lo + w, n), hi = GZ_MIN(lo + 2 * w, n), i = lo, j = mid, k = lo;
            while (i < mid && j < hi) tmp[k++] = job_less(a, v[j], v[i]) ? v[j++] : v[i++];
            while (i < mid) tmp[k++] = v[i++];
            while (j < hi) tmp[k++] = v[j++];
        }
        __builtin_memcpy(v, tmp, (size_t)n * sizeof(u32));
        if (w > n / 2) break;
    }
    gz_free(tmp);
}

static int extract_sel(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_ctx *c, int *res)
{
    const ino_priv *p = (const ino_priv *)a->priv;
    u32 *job = (u32 *)gz_alloc((size_t)a->n * sizeof(u32) + 4);
    if (!job) return GZ_E_NOMEM;
    u32 nj = 0;
    int ret = GZ_OK;
    for (u32 i = 0; i < a->n && !ret; i++) {
        if (!sel[i]) continue;
        if (a->e[i].is_dir) ret = dir_entry(out, i);
        else if (a->e[i].aux32 < p->nloc) job[nj++] = i;
    }
    if (!ret) sort_jobs(a, job, nj);
    for (u32 i = 0; i < nj && !ret;) {
        if (gz_cancelled(c)) { ret = GZ_E_CANCEL; break; }
        u32 k = p->loc[a->e[job[i]].aux32].chunk, j = i + 1;
        while (j < nj && p->loc[a->e[job[j]].aux32].chunk == k) j++;
        ret = extract_chunk(a, s, k, job + i, j - i, out, c, res);
        i = j;
    }
    gz_free(job);
    return ret;
}

static int ino_extract_solid(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_ctx *c)
{
    return extract_sel(a, s, sel, out, c, 0);
}

static int ino_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    const ino_priv *p = (const ino_priv *)a->priv;
    gz_entry *e = &a->e[idx];
    if (e->is_dir) return dir_entry(out, idx);
    if (e->aux32 >= p->nloc) return GZ_E_FORMAT;
    int st = -1;
    int r = extract_chunk(a, s, p->loc[e->aux32].chunk, &idx, 1, out, c, &st);
    if (r) return r;
    return st == GZ_E_SKIP || st < 0 ? GZ_OK : st;
}

static gz_src *ino_view(gz_archive *a, gz_src *s, u32 idx)
{
    const ino_priv *p = (const ino_priv *)a->priv;
    const gz_entry *e = &a->e[idx];
    if (e->is_dir || e->aux32 >= p->nloc) return 0;
    const ino_loc *l = &p->loc[e->aux32];
    const ino_chunk *ch = &p->ch[l->chunk];
    if (ch->comp != C_STORED || ch->enc || l->filter || !p->data_off) return 0;
    if (ch->off > s->size || l->file_off > ch->size || l->size > ch->size - l->file_off) return 0;
    u64 st = p->data_off + ch->off + 4 + l->file_off;
    if (st > s->size || l->size > s->size - st) return 0;
    return gz_src_sub(s, st, l->size);
}

static INO_COLD void ino_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    const ino_priv *p = (const ino_priv *)a->priv;
    char t[64];
    u32 n = 0;
    static const char *const names[] = { "Store", "zlib", "BZip2", "LZMA", "LZMA2" };
    const char *m = e->method < 5 ? names[e->method] : "?";
    while (*m) t[n++] = *m++;
    if ((e->method == C_LZMA1 || e->method == C_LZMA2) && p->dict) {
        u32 d = p->dict;
        char suf = 0;
        if (!(d & ((1u << 20) - 1))) { d >>= 20; suf = 'M'; }
        else if (!(d & ((1u << 10) - 1))) { d >>= 10; suf = 'K'; }
        char dg[12];
        int k = 0;
        do { dg[k++] = (char)('0' + d % 10); d /= 10; } while (d);
        t[n++] = ':';
        while (k) t[n++] = dg[--k];
        if (suf) t[n++] = suf;
    }
    const char *x[3] = { e->flags & IF_SOLID ? " solid" : "", e->aux ? " x86" : "",
                         e->flags & IF_ENC ? (p->ver >= V(6, 4, 0) ? " XChaCha20" : " ARC4") : "" };
    for (int i = 0; i < 3; i++) for (const char *q = x[i]; *q && n < sizeof t - 1; q++) t[n++] = *q;
    u32 i = 0;
    for (; i < n && i + 1 < cap; i++) buf[i] = t[i];
    if (cap) buf[i] = 0;
}

GZ_FORMAT(gz_fmt_inno)
const gz_format gz_fmt_inno = {
    "Inno Setup", "exe bin",
    0, ino_probe, ino_open, ino_close, ino_extract, ino_extract_solid, ino_check_password,
    ino_method, ino_view, 0
};
