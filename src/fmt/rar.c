/*
 * 고깃ZIP - RAR 1.5 - 4.x archive reader (and RAR 1.4 "RE~^" archives)
 *
 *   Headers: marker 52 61 72 21 1A 07 00, main header (volume, solid, lock,
 *   encrypted headers, recovery record, new volume naming, first volume),
 *   file headers (HIGH_PACK/HIGH_UNP sizes, salt, extended times, Unicode
 *   names in RAR 3's "legacy name + encoded UTF-16" form or UTF-8, directory
 *   flag, host OS attributes, split before / after), service headers (CMT is
 *   the archive comment, STM NTFS streams become aux entries "file:stream",
 *   ACL / AV / RR / UOW ... are skipped), old sub-blocks (RAR 2.x NTFS streams
 *   as aux entries), old comments (RAR 1.5 / 2.x inside the main header,
 *   RAR 1.4), end-of-archive header. Header CRC16s are checked.
 *   Data: rar3dec.h (unpack 1.5 / 2.0 / 2.9 incl. PPMd and VM filters),
 *   CRC32 (RAR 1.4: its 16-bit checksum).
 *   Encryption: RAR 3.x AES-128-CBC (gz_rar3_kdf: key + IV from the UTF-16LE
 *   password and the salt), encrypted headers (-hp: every header after the
 *   main one has a salt and is AES encrypted; password asked at open, a wrong
 *   one shows as a header CRC mismatch), RAR 2.0, 1.5 and 1.3 ciphers
 *   (password in the ANSI code page, as unrar). Without check values a wrong
 *   password is found by the data CRC and reported as GZ_E_PASSWORD.
 *   Volumes: name.partN.rar or name.rar, name.r00, ... (o->open_volume);
 *   files split across volumes are read as one stream; opening a later
 *   volume starts from the first one when it can be found.
 *   Solid archives: files with the solid flag (RAR 1.5: every file after the
 *   first) continue the previous compressed file's decoder state.
 *   SFX: the marker is searched in the first 4 MiB of executables.
 */
#include "arc.h"
#include "crc32.h"
#include "rar3dec.h"

GZ_FORMAT(gz_fmt_rar)

static const u8 sig4[7] = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 };
static const u8 sig14[4] = { 0x52, 0x45, 0x7E, 0x5E };

enum { HT_MAIN = 0x73, HT_FILE = 0x74, HT_CMT = 0x75, HT_AV = 0x76, HT_SUB = 0x77, HT_PROTECT = 0x78,
       HT_SIGN = 0x79, HT_SERVICE = 0x7A, HT_END = 0x7B };
#define MHD_VOLUME     0x0001u
#define MHD_COMMENT    0x0002u
#define MHD_SOLID      0x0008u
#define MHD_NEWNUMBER  0x0010u
#define MHD_PACKCMT14  0x0010u
#define MHD_PASSWORD   0x0080u
#define MHD_FIRSTVOL   0x0100u
#define LHD_SPLIT_BEFORE 0x0001u
#define LHD_SPLIT_AFTER  0x0002u
#define LHD_PASSWORD   0x0004u
#define LHD_COMMENT    0x0008u
#define LHD_SOLID      0x0010u
#define LHD_LARGE      0x0100u
#define LHD_UNICODE    0x0200u
#define LHD_SALT       0x0400u
#define LHD_EXTTIME    0x1000u
#define LONG_BLOCK     0x8000u
#define EARC_NEXT_VOL  0x0001u
#define EARC_VOLNUM    0x0008u
#define STREAM_HEAD    0x0105u

#define MAX_VOLS   9999u
#define SFX_SCAN   (4u << 20)
#define CMT_MAX    (1u << 20)
#define KEEP_WIN   ((u64)64 << 20)
#define PW_MAX     127
#define RA_CAP     (80u << 10)       /* header read-ahead (a header is < 64 KiB) */
#define RA_STEP    (16u << 10)

enum { C_NONE = 0, C_13 = 13, C_15 = 15, C_20 = 20, C_AES = 30 };
enum { K_FILE = 0, K_STREAM = 1 };

typedef struct { u32 vol, pad_; u64 off, len; } r4_seg;

typedef struct {
    u32 seg0, nseg;
    u32 crc;             /* CRC32 of the whole file (RAR 1.4: 16-bit checksum) */
    u64 dict;
    u64 gwin;            /* first entry of a solid run: window for the run      */
    i32 group;           /* solid run (index of its first entry), -1: none      */
    u8 ver, method, crypt, has_salt;
    u8 salt[8];
    u8 has_crc, crc14, incomplete, solid, kind, ppmd, pad_[2];
} r4_item;

typedef struct {
    r4_item *it;   u32 nit, capit;
    r4_seg *seg;   u32 nseg, capseg;
    i32 *vsrc;     u32 nvol, capvol;    /* volume -> -1 (archive source) or a->vols index */
} r4_priv;

/* per-thread state: decoder + recent RAR 3.x key derivations */
typedef struct {
    u8 salt[8], has_salt, used, pad_[2];
    u32 pwlen;
    u8 pw[2 * PW_MAX];
    u8 key[16], iv[16];
} r4_kdf;

typedef struct {
    gz_rar3_dec *dec;
    r4_kdf kdf[4];
    u32 knext;
} r4_tls;

static void *tls_new(void)
{
    r4_tls *t = (r4_tls *)gz_alloc(sizeof(r4_tls));
    if (t && !(t->dec = gz_rar3_dec_new())) { gz_free(t); t = 0; }
    return t;
}

static void tls_free(void *p)
{
    r4_tls *t = (r4_tls *)p;
    gz_rar3_dec_free(t->dec);
    __builtin_memset(t->kdf, 0, sizeof t->kdf);
    gz_free(t);
}

static r4_tls *get_tls(gz_ctx *c)
{
    return (r4_tls *)gz_ctx_slot(c, GZ_SLOT_RAR, tls_new, tls_free);
}

/* ---------------- small helpers ---------------- */

static int grow_arr(void **p, u32 *cap, u32 need, size_t elem)
{
    if (need <= *cap) return GZ_OK;
    u32 nc = *cap ? *cap : 64;
    while (nc < need) {
        if (nc > (1u << 28)) return GZ_E_LIMIT;
        nc *= 2;
    }
    void *np = gz_realloc(*p, (size_t)nc * elem);
    if (!np) return GZ_E_NOMEM;
    *p = np;
    *cap = nc;
    return GZ_OK;
}

static u32 crc16(const u8 *p, u32 n)
{
    return gz_crc32(0, p, n) & 0xFFFF;
}

/* UTF-16 password -> UTF-16LE bytes (at most PW_MAX characters, like RAR) */
static u32 pw_utf16(const gzch *w, u8 *out)
{
    if (!w) return 0;
    size_t n = gz_wcslen(w);
    if (n > PW_MAX) n = PW_MAX;
    for (size_t i = 0; i < n; i++) wr16(out + 2 * i, w[i]);
    return (u32)n * 2;
}

/* password bytes for the RAR 1.3 - 2.0 ciphers: ANSI code page (unrar), else UTF-8 */
static u32 pw_ansi(const gzch *w, u8 *out, u32 cap)
{
    if (!w) return 0;
    size_t n = gz_wcslen(w);
    if (n > PW_MAX) n = PW_MAX;
    int k = n ? gz_plat_wc2mb(gz_plat_acp(), w, (int)n, out, (int)cap) : 0;
    if (k <= 0 && n) k = gz_utf16_to_utf8(w, n, out);
    return k > 0 ? (u32)k : 0;
}

static const r4_kdf *kdf_get(r4_tls *t, const u8 *pw, u32 pwlen, const u8 *salt)
{
    for (u32 i = 0; i < 4; i++) {
        r4_kdf *k = &t->kdf[i];
        if (k->used && k->pwlen == pwlen && k->has_salt == (salt != 0) &&
            (!salt || !__builtin_memcmp(k->salt, salt, 8)) && !__builtin_memcmp(k->pw, pw, pwlen))
            return k;
    }
    r4_kdf *k = &t->kdf[t->knext++ & 3];
    gz_rar3_kdf(pw, pwlen, salt, k->key, k->iv);
    k->has_salt = salt != 0;
    if (salt) __builtin_memcpy(k->salt, salt, 8);
    __builtin_memcpy(k->pw, pw, pwlen);
    k->pwlen = pwlen;
    k->used = 1;
    return k;
}

/* ---------------- RAR 1.3 / 1.5 / 2.0 ciphers (unrar crypt1.cpp / crypt2.cpp) ---------------- */

static const u8 subst20_init[256] = {
    215, 19, 149, 35, 73, 197, 192, 205, 249, 28, 16, 119, 48, 221, 2, 42,
    232, 1, 177, 233, 14, 88, 219, 25, 223, 195, 244, 90, 87, 239, 153, 137,
    255, 199, 147, 70, 92, 66, 246, 13, 216, 40, 62, 29, 217, 230, 86, 6,
    71, 24, 171, 196, 101, 113, 218, 123, 93, 91, 163, 178, 202, 67, 44, 235,
    107, 250, 75, 234, 49, 167, 125, 211, 83, 114, 157, 144, 32, 193, 143, 36,
    158, 124, 247, 187, 89, 214, 141, 47, 121, 228, 61, 130, 213, 194, 174, 251,
    97, 110, 54, 229, 115, 57, 152, 94, 105, 243, 212, 55, 209, 245, 63, 11,
    164, 200, 31, 156, 81, 176, 227, 21, 76, 99, 139, 188, 127, 17, 248, 51,
    207, 120, 189, 210, 8, 226, 41, 72, 183, 203, 135, 165, 166, 60, 98, 7,
    122, 38, 155, 170, 69, 172, 252, 238, 39, 134, 59, 128, 236, 27, 240, 80,
    131, 3, 85, 206, 145, 79, 154, 142, 159, 220, 201, 133, 74, 64, 20, 129,
    224, 185, 138, 103, 173, 182, 43, 34, 254, 82, 198, 151, 231, 180, 58, 10,
    118, 26, 102, 12, 50, 132, 22, 191, 136, 111, 162, 179, 45, 4, 148, 108,
    161, 56, 78, 126, 242, 222, 15, 175, 146, 23, 33, 241, 181, 190, 77, 225,
    0, 46, 169, 186, 68, 95, 237, 65, 53, 208, 253, 168, 9, 18, 100, 52,
    116, 184, 160, 96, 109, 37, 30, 106, 140, 104, 150, 5, 204, 117, 112, 84 };

typedef struct {
    u32 k20[4];
    u8 sub[256];
    u16 k15[4];
    u8 k13[3];
} r4_old_crypt;

GZ_INLINE u32 rol32(u32 x, u32 n) { return (x << n) | (x >> (32 - n)); }

static u32 subst_long(const r4_old_crypt *c, u32 t)
{
    return (u32)c->sub[t & 255] | (u32)c->sub[(t >> 8) & 255] << 8 |
           (u32)c->sub[(t >> 16) & 255] << 16 | (u32)c->sub[t >> 24] << 24;
}

static void upd_keys20(r4_old_crypt *c, const u8 *b)
{
    for (u32 i = 0; i < 16; i += 4) {
        c->k20[0] ^= gz_crc_table[0][b[i]];
        c->k20[1] ^= gz_crc_table[0][b[i + 1]];
        c->k20[2] ^= gz_crc_table[0][b[i + 2]];
        c->k20[3] ^= gz_crc_table[0][b[i + 3]];
    }
}

static void block20(r4_old_crypt *c, u8 *b, int dec)
{
    u8 in[16];
    __builtin_memcpy(in, b, 16);
    u32 A = rd32(b) ^ c->k20[0], B = rd32(b + 4) ^ c->k20[1];
    u32 C = rd32(b + 8) ^ c->k20[2], D = rd32(b + 12) ^ c->k20[3];
    for (int r = 0; r < 32; r++) {
        int i = dec ? 31 - r : r;
        u32 t = (C + rol32(D, 11)) ^ c->k20[i & 3];
        u32 ta = A ^ subst_long(c, t);
        t = (D ^ rol32(C, 17)) + c->k20[i & 3];
        u32 tb = B ^ subst_long(c, t);
        A = C;
        B = D;
        C = ta;
        D = tb;
    }
    wr32(b, C ^ c->k20[0]);
    wr32(b + 4, D ^ c->k20[1]);
    wr32(b + 8, A ^ c->k20[2]);
    wr32(b + 12, B ^ c->k20[3]);
    upd_keys20(c, dec ? in : b);
}

static void setkey20(r4_old_crypt *c, const u8 *pw, u32 n)
{
    u8 psw[4 * PW_MAX + 40];
    if (n > 4 * PW_MAX + 4) n = 4 * PW_MAX + 4;
    c->k20[0] = 0xD3A3B879u;
    c->k20[1] = 0x3F6D12F7u;
    c->k20[2] = 0x7515A235u;
    c->k20[3] = 0xA4E7F123u;
    __builtin_memcpy(c->sub, subst20_init, 256);
    __builtin_memset(psw, 0, sizeof psw);
    __builtin_memcpy(psw, pw, n);
    for (u32 j = 0; j < 256; j++)
        for (u32 i = 0; i < n; i += 2) {
            u32 n1 = (u8)gz_crc_table[0][(psw[i] - j) & 0xFF];
            u32 n2 = (u8)gz_crc_table[0][(psw[i + 1] + j) & 0xFF];
            for (u32 k = 1; n1 != n2; n1 = (n1 + 1) & 0xFF, k++) {
                u8 *x = &c->sub[n1], *y = &c->sub[(n1 + i + k) & 0xFF], t = *x;
                *x = *y;
                *y = t;
            }
        }
    for (u32 i = 0; i < n; i += 16) block20(c, psw + i, 0);
    __builtin_memset(psw, 0, sizeof psw);
}

GZ_INLINE u16 ror16(u32 x, u32 n) { x &= 0xFFFF; return (u16)((x >> n) | (x << (16 - n))); }

static void setkey15(r4_old_crypt *c, const u8 *pw, u32 n)
{
    u32 crc = ~gz_crc32(0, pw, n);          /* unrar's CRC32(0xffffffff, ...): raw register */
    c->k15[0] = (u16)crc;
    c->k15[1] = (u16)(crc >> 16);
    c->k15[2] = c->k15[3] = 0;
    for (u32 i = 0; i < n; i++) {
        u8 p = pw[i];
        c->k15[2] = (u16)(c->k15[2] ^ p ^ gz_crc_table[0][p]);
        c->k15[3] = (u16)(c->k15[3] + p + (gz_crc_table[0][p] >> 16));
    }
}

static void crypt15(r4_old_crypt *c, u8 *b, size_t n)
{
    u16 *k = c->k15;
    while (n--) {
        k[0] = (u16)(k[0] + 0x1234);
        u32 t = gz_crc_table[0][(k[0] & 0x1FE) >> 1];
        k[1] = (u16)(k[1] ^ t);
        k[2] = (u16)(k[2] - (t >> 16));
        k[0] ^= k[2];
        k[3] = (u16)(ror16(k[3], 1) ^ k[1]);
        k[3] = ror16(k[3], 1);
        k[0] ^= k[3];
        *b++ ^= (u8)(k[0] >> 8);
    }
}

static void setkey13(r4_old_crypt *c, const u8 *pw, u32 n)
{
    c->k13[0] = c->k13[1] = c->k13[2] = 0;
    for (u32 i = 0; i < n; i++) {
        u8 p = pw[i];
        c->k13[0] = (u8)(c->k13[0] + p);
        c->k13[1] ^= p;
        c->k13[2] = (u8)(c->k13[2] + p);
        c->k13[2] = (u8)((c->k13[2] << 1) | (c->k13[2] >> 7));
    }
}

static void decrypt13(r4_old_crypt *c, u8 *b, size_t n)
{
    while (n--) {
        c->k13[1] = (u8)(c->k13[1] + c->k13[2]);
        c->k13[0] = (u8)(c->k13[0] + c->k13[1]);
        *b = (u8)(*b - c->k13[0]);
        b++;
    }
}

/* RAR 1.4 file checksum */
static u32 sum14(u32 s, const u8 *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        s = (s + p[i]) & 0xFFFF;
        s = ((s << 1) | (s >> 15)) & 0xFFFF;
    }
    return s;
}

/* ---------------- gzch name helpers (volume names) ---------------- */

static int wdigit(gzch c) { return c >= '0' && c <= '9'; }

static size_t wname_start(const gzch *s, size_t n)
{
    size_t b = n;
    while (b && s[b - 1] != '/' && s[b - 1] != '\\') b--;
    return b;
}

static size_t wext(const gzch *s, size_t n)
{
    size_t b = wname_start(s, n);
    for (size_t i = n; i > b; i--)
        if (s[i - 1] == '.') return i - 1;
    return n;
}

static int wext_is(const gzch *s, size_t n, size_t dot, const char *e)
{
    size_t k = 0;
    for (; e[k]; k++) {
        if (dot + 1 + k >= n) return 0;
        gzch c = s[dot + 1 + k];
        if (c >= 'A' && c <= 'Z') c += 32;
        if (c != (gzch)e[k]) return 0;
    }
    return dot + 1 + k == n;
}

static gzch *wcopy(const gzch *s, size_t n, size_t extra)
{
    gzch *w = (gzch *)gz_alloc((n + extra + 1) * sizeof(gzch));
    if (w) {
        __builtin_memcpy(w, s, n * sizeof(gzch));
        w[n] = 0;
    }
    return w;
}

/* .exe / .sfx first volumes continue as .rar */
static void wfix_sfx_ext(gzch *w, size_t *n)
{
    size_t dot = wext(w, *n);
    if (dot < *n && (wext_is(w, *n, dot, "exe") || wext_is(w, *n, dot, "sfx"))) {
        int up = w[dot + 1] >= 'A' && w[dot + 1] <= 'Z';
        w[dot + 1] = up ? 'R' : 'r';
        w[dot + 2] = up ? 'A' : 'a';
        w[dot + 3] = up ? 'R' : 'r';
    }
}

/* name.part1.rar -> name.part2.rar: increment the last digit group of the name */
static gzch *vol_next_new(const gzch *cur)
{
    size_t n = gz_wcslen(cur), b = wname_start(cur, n);
    gzch *w = wcopy(cur, n, 2);
    if (!w) return 0;
    wfix_sfx_ext(w, &n);
    size_t k = n;
    while (k > b && !wdigit(w[k - 1])) k--;
    if (k == b) { gz_free(w); return 0; }
    k--;
    for (;;) {
        if (w[k] != '9') { w[k]++; break; }
        w[k] = '0';
        if (k == b || !wdigit(w[k - 1])) {
            for (size_t j = n + 1; j > k; j--) w[j] = w[j - 1];
            w[k] = '1';
            break;
        }
        k--;
    }
    return w;
}

/* name.rar -> name.r00 -> name.r01 ... -> name.r99 -> name.s00 */
static gzch *vol_next_old(const gzch *cur)
{
    size_t n = gz_wcslen(cur);
    gzch *w = wcopy(cur, n, 4);
    if (!w) return 0;
    wfix_sfx_ext(w, &n);
    size_t dot = wext(w, n);
    if (dot == n || n - dot != 4) { gz_free(w); return 0; }
    if (!wdigit(w[dot + 2]) || !wdigit(w[dot + 3])) {
        w[dot + 2] = w[dot + 3] = '0';
        return w;
    }
    for (size_t k = dot + 3;; k--) {
        if (k == dot) { gz_free(w); return 0; }
        if (w[k] != '9' || !wdigit(w[k])) {
            if (!wdigit(w[k]) && (w[k] == 'z' || w[k] == 'Z')) { gz_free(w); return 0; }
            w[k]++;
            break;
        }
        w[k] = '0';
    }
    return w;
}

/* first volume of the set name belongs to (old style when the extension is a
 * letter and two digits, else the last digit group becomes 1) */
static gzch *vol_first(const gzch *cur)
{
    size_t n = gz_wcslen(cur), b = wname_start(cur, n);
    size_t dot = wext(cur, n);
    gzch *w = wcopy(cur, n, 0);
    if (!w) return 0;
    if (dot < n && n - dot == 4 && wdigit(cur[dot + 2]) && wdigit(cur[dot + 3])) {
        int up = cur[dot + 1] >= 'A' && cur[dot + 1] <= 'Z';
        w[dot + 1] = up ? 'R' : 'r';
        w[dot + 2] = up ? 'A' : 'a';
        w[dot + 3] = up ? 'R' : 'r';
        return w;
    }
    size_t k = dot;
    while (k > b && !wdigit(w[k - 1])) k--;
    if (k == b) { gz_free(w); return 0; }
    size_t e = k;
    while (k > b && wdigit(w[k - 1])) k--;
    for (size_t i = k; i < e; i++) w[i] = (gzch)(i + 1 == e ? '1' : '0');
    return w;
}

/* ---------------- header reading ---------------- */

typedef struct {
    u32 type, flags, hs;
    u64 off;                 /* header start (its salt when headers are encrypted) */
    u64 data_off, data_len;
    u64 next;
    const u8 *h;             /* hs header bytes (decrypted)                        */
    int crc_ok;              /* CRC16 over the whole header matches                */
    int nb_ok;               /* data byte after the header available in nb         */
    u8 nb;
} r4_hdr;

typedef struct {
    gz_archive *a;
    const gz_open_opts *o;
    gz_ctx *c;
    r4_priv *pv;
    r4_tls *t;
    gz_src *src;             /* current volume */
    u32 vol;
    u64 off;
    u8 *ra; u64 ra_off; u32 ra_len;
    u8 *buf; u32 cap;
    int enc;                 /* headers encrypted (current volume)          */
    u8 pw[2 * PW_MAX]; u32 pwlen; int have_pw;
    u32 arc_flags;
    int old14;               /* RAR 1.4 archive                              */
    int more;                /* another volume follows                       */
    i32 pending;             /* file continued in the next volume, -1        */
    i32 last_file;           /* parent of stream entries                     */
    u32 nfile_hdrs;          /* file headers seen (RAR 1.5 solid rule)       */
    gzch *name;              /* file name of the current volume (owned)      */
    int style;               /* volume naming: 0 unknown, 1 new, 2 old       */
    /* archive comment */
    int has_cmt; r4_item cmt; u64 cmt_usize; u32 cmt_unicode, cmt_oem;
    u64 nhdr;
} r4_ost;

static int buf_need(r4_ost *st, u32 n)
{
    if (n <= st->cap) return GZ_OK;
    u8 *b = (u8 *)gz_realloc(st->buf, n);
    if (!b) return GZ_E_NOMEM;
    st->buf = b;
    st->cap = n;
    return GZ_OK;
}

/* n (<= RA_CAP) bytes at off of the current volume through the read-ahead buffer */
static int ra_get(r4_ost *st, u64 off, u32 n, const u8 **out)
{
    gz_src *s = st->src;
    if (off >= st->ra_off && off - st->ra_off + n <= st->ra_len) {
        *out = st->ra + (off - st->ra_off);
        return GZ_OK;
    }
    if (off > s->size || s->size - off < n) return GZ_E_TRUNC;
    if (!st->ra && !(st->ra = (u8 *)gz_alloc(RA_CAP))) return GZ_E_NOMEM;
    u64 left = s->size - off;
    u32 want = n > RA_STEP ? n : RA_STEP;
    if (want > left) want = (u32)left;
    st->ra_len = 0;
    int r = gz_src_read_exact(s, off, st->ra, want);
    if (r) return r;
    st->ra_off = off;
    st->ra_len = want;
    *out = st->ra;
    return GZ_OK;
}

/* Header at st->off of a RAR 1.5 - 4.x volume. GZ_E_CRC: encrypted header
 * that does not decrypt (wrong password), GZ_E_TRUNC / GZ_E_FORMAT: broken. */
static int read_hdr(r4_ost *st, r4_hdr *h)
{
    u64 off = st->off;
    const u8 *b;
    u32 pre = 0, span;
    int r;
    __builtin_memset(h, 0, sizeof *h);
    h->off = off;
    if (!st->enc) {
        if ((r = ra_get(st, off, 7, &b))) return r;
        u32 hs = rd16(b + 5);
        if (hs < 7) return GZ_E_FORMAT;
        if ((r = ra_get(st, off, hs, &b))) return r;
        if ((r = buf_need(st, hs + 16))) return r;
        __builtin_memcpy(st->buf, b, hs);
        span = hs;
        if (off + hs < st->ra_off + st->ra_len) {
            h->nb = st->ra[off + hs - st->ra_off];
            h->nb_ok = 1;
        }
    } else {
        /* salt, then the header encrypted in 16-byte blocks */
        if ((r = ra_get(st, off, 24, &b))) return r;
        const r4_kdf *k = kdf_get(st->t, st->pw, st->pwlen, b);
        gz_aes aes;
        u8 iv[16], blk[16];
        gz_aes_set_decrypt_key(&aes, k->key, 16);
        __builtin_memcpy(iv, k->iv, 16);
        __builtin_memcpy(blk, b + 8, 16);
        gz_aes_cbc_decrypt(&aes, iv, blk, 16);
        u32 hs = rd16(blk + 5);
        if (hs < 7) return GZ_E_CRC;
        span = (hs + 15) & ~15u;
        /* a wrong key gives a random size: running past the end is a CRC error too */
        if ((r = ra_get(st, off + 8, span, &b))) return r == GZ_E_TRUNC ? GZ_E_CRC : r;
        if ((r = buf_need(st, span + 16))) return r;
        __builtin_memcpy(st->buf, b, span);
        __builtin_memcpy(iv, k->iv, 16);
        gz_aes_cbc_decrypt(&aes, iv, st->buf, span);
        pre = 8;
    }
    const u8 *p = st->buf;
    h->h = p;
    h->hs = rd16(p + 5);
    h->type = p[2];
    h->flags = rd16(p + 3);
    h->crc_ok = crc16(p + 2, h->hs - 2) == rd16(p);
    if (st->enc && !h->crc_ok) return GZ_E_CRC;
    u64 dl = 0;
    if ((h->flags & LONG_BLOCK) || h->type == HT_FILE || h->type == HT_SERVICE) {
        if (h->hs < 11) return GZ_E_FORMAT;
        dl = rd32(p + 7);
        if ((h->type == HT_FILE || h->type == HT_SERVICE) && (h->flags & LHD_LARGE)) {
            if (h->hs < 40) return GZ_E_FORMAT;
            dl |= (u64)rd32(p + 32) << 32;
        }
    }
    h->data_off = off + pre + span;
    h->data_len = dl;
    h->next = h->data_off + dl;
    if (h->next < h->data_off) return GZ_E_FORMAT;
    return GZ_OK;
}

/* ---------------- entries ---------------- */

static int add_seg(r4_priv *pv, u32 vol, u64 off, u64 len)
{
    int r = grow_arr((void **)&pv->seg, &pv->capseg, pv->nseg + 1, sizeof(r4_seg));
    if (r) return r;
    r4_seg *g = &pv->seg[pv->nseg++];
    g->vol = vol;
    g->pad_ = 0;
    g->off = off;
    g->len = len;
    return GZ_OK;
}

static int add_item(r4_ost *st, r4_item **pit)
{
    r4_priv *pv = st->pv;
    int r = grow_arr((void **)&pv->it, &pv->capit, pv->nit + 1, sizeof(r4_item));
    if (r) return r;
    r4_item *it = &pv->it[pv->nit++];
    __builtin_memset(it, 0, sizeof *it);
    it->group = -1;
    it->seg0 = pv->nseg;
    *pit = it;
    return GZ_OK;
}

/* EncodeFileName::Decode: legacy name + compressed UTF-16 -> UTF-16 (count) */
static u32 decode_unicode(const u8 *name, u32 nlen, const u8 *enc, u32 elen, gzch *out, u32 max)
{
    u32 ep = 0, dp = 0, fbits = 0, flags = 0;
    if (!elen) return 0;
    u32 high = enc[ep++];
    while (ep < elen && dp < max) {
        if (!fbits) {
            flags = enc[ep++];
            fbits = 8;
        }
        switch (flags >> 6) {
        case 0:
            if (ep >= elen) goto done;
            out[dp++] = enc[ep++];
            break;
        case 1:
            if (ep >= elen) goto done;
            out[dp++] = (gzch)(enc[ep++] + (high << 8));
            break;
        case 2:
            if (ep + 1 >= elen) goto done;
            out[dp++] = (gzch)(enc[ep] | enc[ep + 1] << 8);
            ep += 2;
            break;
        default: {
            if (ep >= elen) goto done;
            u32 len = enc[ep++];
            if (len & 0x80) {
                if (ep >= elen) goto done;
                u32 corr = enc[ep++];
                for (len = (len & 0x7F) + 2; len && dp < max && dp < nlen; len--, dp++)
                    out[dp] = (gzch)(((name[dp] + corr) & 0xFF) + (high << 8));
            } else {
                for (len += 2; len && dp < max && dp < nlen; len--, dp++) out[dp] = name[dp];
            }
            break;
        }
        }
        flags = (flags << 2) & 0xFF;
        fbits -= 2;
    }
done:
    return dp;
}

static int ascii_only(const u8 *p, u32 n)
{
    for (u32 i = 0; i < n; i++)
        if (p[i] & 0x80) return 0;
    return 1;
}

/* Add the entry for a name in the RAR 1.5 - 4.x header form */
static int add_named(r4_ost *st, const u8 *nm, u32 nl, u32 flags, gz_entry **pe)
{
    gz_archive *a = st->a;
    if (flags & LHD_UNICODE) {
        u32 z = 0;
        while (z < nl && nm[z]) z++;
        if (z < nl) {
            gzch *w = (gzch *)gz_alloc((size_t)nl * sizeof(gzch) + 2);
            if (!w) return GZ_E_NOMEM;
            u32 n = decode_unicode(nm, z, nm + z + 1, nl - z - 1, w, nl);
            int r = GZ_OK;
            if (n) {
                u8 *b = (u8 *)w;           /* UTF-16LE in place (little-endian host) */
                r = gz_arc_add_named(a, b, n * 2, GZ_NE_UTF16LE, pe);
                gz_free(w);
                return r;
            }
            gz_free(w);
            nl = z;
        } else if (gz_utf8_valid(nm, nl)) {
            return gz_arc_add_named(a, nm, nl, GZ_NE_UTF8, pe);
        }
    }
    a->win_names = 1;                  /* legacy names come from RAR (Windows code pages) */
    return gz_arc_add_named(a, nm, nl, GZ_NE_LEGACY, pe);
}

/* "parent:stream" aux entry; w/wn: stream name as UTF-16 (or legacy bytes lb/ln) */
static int add_stream_entry(r4_ost *st, const gzch *w, u32 wn, const u8 *lb, u32 ln, gz_entry **pe)
{
    gz_archive *a = st->a;
    if (st->last_file < 0) return GZ_E_SKIP;
    gz_entry pe0 = a->e[st->last_file];
    const u8 *pr = a->raw + pe0.raw_off;
    u32 pl = pe0.raw_len, sl = w ? wn : ln;
    if ((size_t)pl + 2 * (size_t)sl + 4 > 0x20000) return GZ_E_SKIP;
    u8 *tmp = (u8 *)gz_alloc(((size_t)pl + sl + 2) * 2 + 8);
    if (!tmp) return GZ_E_NOMEM;
    int sascii = 1;
    for (u32 i = 0; i < sl; i++)
        if ((w ? w[i] : lb[i]) >= 0x80) sascii = 0;
    int ne = pe0.name_enc;
    u32 n = 0;
    if (ne == GZ_NE_UTF16LE || (ascii_only(pr, pl) && !sascii && w)) {
        /* UTF-16LE: parent (UTF-16LE or ASCII) + stream */
        if (ne == GZ_NE_UTF16LE) { if (pl > 1) __builtin_memcpy(tmp, pr, pl & ~1u); n = pl & ~1u; }
        else for (u32 i = 0; i < pl; i++, n += 2) wr16(tmp + n, pr[i]);
        for (u32 i = 0; i < sl; i++, n += 2) wr16(tmp + n, w ? w[i] : (lb[i] < 0x80 ? lb[i] : '_'));
        ne = GZ_NE_UTF16LE;
    } else {
        if (pl) __builtin_memcpy(tmp, pr, pl);
        n = pl;
        if (ne == GZ_NE_UTF8 && w && !sascii) {
            n += (u32)gz_utf16_to_utf8(w, sl, tmp + n);
        } else {
            for (u32 i = 0; i < sl; i++) {
                u32 c = w ? w[i] : lb[i];
                tmp[n++] = (u8)(c < 0x80 || (!w && ne == GZ_NE_LEGACY) ? c : '_');
            }
        }
    }
    int r = gz_arc_add_named(a, tmp, n, ne, pe);
    gz_free(tmp);
    if (!r) (*pe)->is_aux = 1;
    return r;
}

/* fields common to file / service headers */
typedef struct {
    u64 pack, unp;
    u32 host, crc, ftime, ver, method, attr, flags;
    const u8 *name; u32 nl;
    const u8 *salt;
    const u8 *sub; u32 sub_len;    /* service data (stream name) */
    u32 end;                       /* processed bytes */
    int unknown_size;
} r4_fh;

static int parse_fh(const r4_hdr *h, r4_fh *f)
{
    const u8 *b = h->h;
    u32 hs = h->hs, i = 32;
    __builtin_memset(f, 0, sizeof *f);
    if (hs < 32) return GZ_E_FORMAT;
    f->flags = h->flags;
    f->pack = rd32(b + 7);
    u32 lu = rd32(b + 11), hu = 0;
    f->host = b[15];
    f->crc = rd32(b + 16);
    f->ftime = rd32(b + 20);
    f->ver = b[24];
    f->method = b[25];
    u32 nl = rd16(b + 26);
    f->attr = rd32(b + 28);
    if (h->flags & LHD_LARGE) {
        if (hs < 40) return GZ_E_FORMAT;
        f->pack |= (u64)rd32(b + 32) << 32;
        hu = rd32(b + 36);
        i = 40;
        f->unknown_size = lu == 0xFFFFFFFFu && hu == 0xFFFFFFFFu;
    } else {
        f->unknown_size = lu == 0xFFFFFFFFu;
    }
    f->unp = (u64)hu << 32 | lu;
    if (nl > hs - i) return GZ_E_FORMAT;
    f->name = b + i;
    f->nl = nl;
    i += nl;
    u32 send = hs;
    if (h->flags & LHD_SALT) {
        if (hs - i < 8) return GZ_E_FORMAT;
        send = hs - 8;
    }
    if (h->type == HT_SERVICE) {
        /* optional service data between the name and the salt (unrar's SubData) */
        u32 dsz = hs > nl + 32 + (send < hs ? 8 : 0) ? hs - nl - 32 - (send < hs ? 8 : 0) : 0;
        if (dsz > send - i) dsz = send - i;
        f->sub = b + i;
        f->sub_len = dsz;
        i += dsz;
    }
    if (h->flags & LHD_SALT) {
        f->salt = b + i;
        i += 8;
    }
    if (h->flags & LHD_EXTTIME) {
        if (hs - i < 2) return GZ_E_FORMAT;
        u32 ef = rd16(b + i);
        i += 2;
        for (int k = 0; k < 4; k++) {
            u32 rm = ef >> ((3 - k) * 4);
            if (!(rm & 8)) continue;
            u32 need = (k ? 4 : 0) + (rm & 3);
            if (hs - i < need) return GZ_E_FORMAT;
            i += need;
        }
    }
    f->end = i;
    /* old file comments: the CRC covers the fields read so far */
    if (!h->crc_ok && !((h->flags & LHD_COMMENT) && crc16(b + 2, i - 2) == rd16(b))) return GZ_E_CRC;
    return GZ_OK;
}

static void set_attrs(gz_entry *e, u32 host, u32 attr)
{
    if (host == 3 || host == 5) {            /* Unix, BeOS: st_mode */
        e->unix_mode = attr & 0xFFFF;
        if (!(attr & 0200)) e->attr |= 1;
        if ((attr & 0xF000) == 0xA000) {
            e->is_link = 1;                  /* target = the file data */
            e->is_dir = 0;
        }
    } else if (host <= 2 || host == 4) {     /* MS-DOS, OS/2, Win32, Mac */
        e->attr = attr & 0x37;
    } else {
        e->attr = e->is_dir ? 0x10 : 0x20;
    }
    if (e->is_dir) {
        e->attr |= 0x10;
        e->usize = 0;
    }
}

static u32 crypt_of(u32 ver)
{
    if (ver == 13) return C_13;
    if (ver == 15) return C_15;
    if (ver == 20 || ver == 26) return C_20;
    return C_AES;
}

static int add_file(r4_ost *st, const r4_hdr *h)
{
    gz_archive *a = st->a;
    r4_priv *pv = st->pv;
    r4_fh f;
    int r;
    if ((r = parse_fh(h, &f))) return r;
    u32 fl = f.flags;

    if (fl & LHD_SPLIT_BEFORE) {
        /* continuation of the file left open by the previous volume */
        i32 pi = st->pending;
        st->nfile_hdrs++;
        if (pi < 0) return GZ_OK;
        gz_entry *e = &a->e[pi];
        r4_item *it = &pv->it[pi];
        st->pending = -1;
        if (it->seg0 + it->nseg != pv->nseg) {
            it->incomplete = 1;
            return GZ_OK;
        }
        if ((r = add_seg(pv, st->vol, h->data_off, h->data_len))) return r;
        it = &pv->it[pi];
        it->nseg++;
        e->csize += h->data_len;
        if (fl & LHD_SPLIT_AFTER) {
            st->pending = pi;
        } else {
            it->crc = f.crc;
            it->has_crc = 1;
            e->crc = f.crc;
            e->has_crc = 1;
        }
        return GZ_OK;
    }
    if (st->pending >= 0) {
        pv->it[st->pending].incomplete = 1;
        st->pending = -1;
    }
    gz_entry *e;
    r4_item *it;
    if ((r = add_named(st, f.name, f.nl, fl, &e))) return r;
    if ((r = add_item(st, &it))) return r;
    i32 idx = (i32)(a->n - 1);
    st->last_file = idx;
    e->is_dir = f.ver < 20 ? (f.attr & 0x10) != 0 : (fl & 0xE0) == 0xE0;
    if (f.ver < 20 && (fl & 0xE0) == 0xE0) e->is_dir = 1;
    e->usize = f.unknown_size ? GZ_SIZE_UNKNOWN : f.unp;
    e->csize = h->data_len;
    e->off = h->data_off;
    e->method = (u16)(f.method - 0x30);
    e->mtime = f.ftime;
    e->mtime_kind = GZ_MT_DOS;
    set_attrs(e, f.host, f.attr);
    it->ver = (u8)f.ver;
    it->method = (u8)(f.method - 0x30);
    it->dict = (u64)0x10000 << ((fl >> 5) & 7);
    it->solid = f.ver < 20 ? (st->arc_flags & MHD_SOLID) && st->nfile_hdrs > 0 : (fl & LHD_SOLID) != 0;
    it->kind = K_FILE;
    st->nfile_hdrs++;
    if (fl & LHD_PASSWORD) {
        it->crypt = (u8)crypt_of(f.ver);
        e->enc = it->crypt == C_AES ? GZ_ENC_AES : GZ_ENC_OTHER;
    }
    if (f.salt) {
        it->has_salt = 1;
        __builtin_memcpy(it->salt, f.salt, 8);
    }
    it->crc = f.crc;
    it->has_crc = 1;
    if (e->is_dir) {
        it->nseg = 0;
    } else {
        if ((r = add_seg(pv, st->vol, h->data_off, h->data_len))) return r;
        it->nseg = 1;
        /* LZ / PPMd: a 2.9 block starts with the PPMd flag bit */
        it->ppmd = !it->crypt && !it->solid && it->method && f.ver >= 29 && h->nb_ok && h->data_len && (h->nb & 0x80);
    }
    if (fl & LHD_SPLIT_AFTER) {
        if (it->nseg) st->pending = idx;
        it->has_crc = 0;
    }
    a->e[idx].has_crc = it->has_crc;
    a->e[idx].crc = it->crc;
    return GZ_OK;
}

static int add_service(r4_ost *st, const r4_hdr *h)
{
    gz_archive *a = st->a;
    r4_priv *pv = st->pv;
    r4_fh f;
    int r = parse_fh(h, &f);
    if (r) return r == GZ_E_CRC ? GZ_E_CRC : GZ_OK;
    if (f.flags & (LHD_SPLIT_BEFORE | LHD_SPLIT_AFTER)) return GZ_OK;
    int is_cmt = f.nl == 3 && !__builtin_memcmp(f.name, "CMT", 3);
    int is_stm = f.nl == 3 && !__builtin_memcmp(f.name, "STM", 3);
    r4_item tmp, *it = &tmp;
    gz_entry *e = 0;
    if (is_cmt) {
        /* the archive comment comes before the files (file comments carry 0x10) */
        if (st->has_cmt || (f.flags & LHD_SOLID) || st->last_file >= 0) return GZ_OK;
        it = &st->cmt;
    } else if (is_stm) {
        u32 sn = f.sub_len / 2;
        if (!sn) return GZ_OK;
        gzch *w = (gzch *)gz_alloc((size_t)sn * sizeof(gzch) + 2);
        if (!w) return GZ_E_NOMEM;
        for (u32 i = 0; i < sn; i++) w[i] = rd16(f.sub + 2 * i);
        while (sn && !w[sn - 1]) sn--;
        u32 s0 = (sn && w[0] == ':') ? 0 : sn;   /* stream names start with ':' */
        r = s0 ? GZ_E_SKIP : add_stream_entry(st, w, sn, 0, 0, &e);
        gz_free(w);
        if (r == GZ_E_SKIP) return GZ_OK;
        if (r) return r;
        if ((r = add_item(st, &it))) return r;
        it->kind = K_STREAM;
    } else {
        return GZ_OK;
    }
    __builtin_memset(it, 0, sizeof *it);
    it->group = -1;
    it->seg0 = pv->nseg;
    it->ver = (u8)f.ver;
    it->method = (u8)(f.method - 0x30);
    it->dict = (u64)0x10000 << ((f.flags >> 5) & 7);
    it->kind = is_stm ? K_STREAM : K_FILE;
    it->crc = f.crc;
    it->has_crc = 1;
    if (f.flags & LHD_PASSWORD) it->crypt = (u8)crypt_of(f.ver);
    if (f.salt) {
        it->has_salt = 1;
        __builtin_memcpy(it->salt, f.salt, 8);
    }
    if ((r = add_seg(pv, st->vol, h->data_off, h->data_len))) return r;
    it->nseg = 1;
    if (is_cmt) {
        st->has_cmt = 1;
        st->cmt_usize = f.unknown_size ? GZ_SIZE_UNKNOWN : f.unp;
        st->cmt_unicode = f.attr & 1;
        return GZ_OK;
    }
    e = &a->e[a->n - 1];
    e->usize = f.unknown_size ? GZ_SIZE_UNKNOWN : f.unp;
    e->csize = h->data_len;
    e->off = h->data_off;
    e->method = (u16)it->method;
    e->mtime = a->e[st->last_file].mtime;
    e->mtime_kind = a->e[st->last_file].mtime_kind;
    e->crc = f.crc;
    e->has_crc = 1;
    if (it->crypt) e->enc = it->crypt == C_AES ? GZ_ENC_AES : GZ_ENC_OTHER;
    return GZ_OK;
}

/* RAR 2.x sub-block: NTFS streams (STREAM_HEAD) become aux entries */
static int add_oldsub(r4_ost *st, const r4_hdr *h)
{
    gz_archive *a = st->a;
    r4_priv *pv = st->pv;
    const u8 *b = h->h;
    if (!h->crc_ok || h->hs < 14 || rd16(b + 11) != STREAM_HEAD || h->hs < 26) return GZ_OK;
    u32 unp = rd32(b + 14), ver = b[18], meth = b[19], crc = rd32(b + 20), sl = rd16(b + 24);
    if (sl > h->hs - 26 || !sl || b[26] != ':' || meth < 0x31 || meth > 0x35) return GZ_OK;
    gz_entry *e;
    r4_item *it;
    int r = add_stream_entry(st, 0, 0, b + 26, sl, &e);
    if (r == GZ_E_SKIP) return GZ_OK;
    if (r || (r = add_item(st, &it))) return r;
    it->ver = (u8)ver;
    it->method = (u8)(meth - 0x30);
    it->dict = 0x10000;
    it->kind = K_STREAM;
    it->crc = crc;
    it->has_crc = 1;
    if ((r = add_seg(pv, st->vol, h->data_off, h->data_len))) return r;
    it->nseg = 1;
    e = &a->e[a->n - 1];
    e->usize = unp;
    e->csize = h->data_len;
    e->off = h->data_off;
    e->method = (u16)it->method;
    e->mtime = a->e[st->last_file].mtime;
    e->mtime_kind = a->e[st->last_file].mtime_kind;
    e->crc = crc;
    e->has_crc = 1;
    return GZ_OK;
}

/* ---------------- volumes ---------------- */

static int add_volume(r4_ost *st, gz_src *s, i32 vsrc_idx)
{
    r4_priv *pv = st->pv;
    if (pv->nvol >= MAX_VOLS) return GZ_E_LIMIT;
    int r = grow_arr((void **)&pv->vsrc, &pv->capvol, pv->nvol + 1, sizeof(i32));
    if (r) return r;
    pv->vsrc[pv->nvol] = vsrc_idx;
    st->vol = pv->nvol++;
    st->src = s;
    st->ra_len = 0;
    return GZ_OK;
}

static int keep_src(gz_archive *a, gz_src *s, i32 *idx)
{
    gz_src **nv = (gz_src **)gz_realloc(a->vols, (a->nvols + 1) * sizeof(gz_src *));
    if (!nv) return GZ_E_NOMEM;
    a->vols = nv;
    a->vols[a->nvols] = s;
    *idx = (i32)a->nvols++;
    return GZ_OK;
}

static int try_open(r4_ost *st, const gzch *name, gz_src **out)
{
    *out = 0;
    if (!name || !st->o->open_volume) return GZ_E_VOLUME;
    int r = st->o->open_volume(st->o->user, name, out);
    if (r == GZ_E_CANCEL) return r;
    if (r || !*out) { *out = 0; return GZ_E_VOLUME; }
    u8 sg[7];
    int bad = st->old14 ? gz_src_read_exact(*out, 0, sg, 4) || __builtin_memcmp(sg, sig14, 4)
                        : gz_src_read_exact(*out, 0, sg, 7) || __builtin_memcmp(sg, sig4, 7);
    if (bad) {
        gz_src_free(*out);
        *out = 0;
        return GZ_E_VOLUME;
    }
    return GZ_OK;
}

/* Open the volume after the current one; GZ_E_VOLUME when it cannot be found. */
static int open_next(r4_ost *st)
{
    gz_src *s = 0;
    gzch *cand[2] = { 0, 0 };
    int sty[2] = { 1, 2 };
    int r = GZ_E_VOLUME;
    if (!st->name) return GZ_E_VOLUME;
    if (!st->style) st->style = (st->arc_flags & MHD_NEWNUMBER) && !st->old14 ? 1 : 2;
    cand[0] = st->style == 1 ? vol_next_new(st->name) : vol_next_old(st->name);
    cand[1] = st->style == 1 ? vol_next_old(st->name) : vol_next_new(st->name);
    if (st->style == 2) { sty[0] = 2; sty[1] = 1; }
    for (int k = 0; k < 2 && !s; k++) {
        if (!cand[k]) continue;
        r = try_open(st, cand[k], &s);
        if (r == GZ_E_CANCEL) break;
        if (!r) {
            gz_free(st->name);
            st->name = cand[k];
            cand[k] = 0;
            st->style = sty[k];
        }
    }
    gz_free(cand[0]);
    gz_free(cand[1]);
    if (!s) return r == GZ_E_CANCEL ? r : GZ_E_VOLUME;
    i32 idx;
    if ((r = keep_src(st->a, s, &idx))) { gz_src_free(s); return r; }
    return add_volume(st, s, idx);
}

/* ---------------- parsing ---------------- */

enum { P_DONE = 0, P_NEXT = 1, P_REDIRECT = 2 };

/* Find the password whose key decrypts the first encrypted header. */
static int setup_password(r4_ost *st)
{
    gzch ask[PW_MAX + 2];
    const gzch *pw = st->a->password ? st->a->password : st->o->password;
    int retry = 0;
    for (int tries = 0; tries < 16; tries++) {
        if (!pw) {
            if (!st->o->ask_password) return GZ_E_PASSWORD;
            ask[0] = 0;
            int r = st->o->ask_password(st->o->user, ask, PW_MAX + 1, retry);
            if (r) return r == GZ_E_CANCEL ? r : GZ_E_PASSWORD;
            ask[PW_MAX + 1] = 0;
            pw = ask;
        }
        st->pwlen = pw_utf16(pw, st->pw);
        st->have_pw = 1;
        r4_hdr h;
        int r = read_hdr(st, &h);
        if (!r) {
            if (!st->a->password && !(st->a->password = gz_wcsdup(pw))) return GZ_E_NOMEM;
            st->a->headers_enc = 1;
            return GZ_OK;
        }
        if (r != GZ_E_CRC) return r;
        if (st->a->password) return GZ_E_PASSWORD;     /* later volume, other password */
        pw = 0;
        retry = 1;
    }
    return GZ_E_PASSWORD;
}

/* Parse the headers of the current RAR 1.5 - 4.x volume. first: 1 = first
 * opened volume (may redirect), 2 = first but no redirect, 0 = later one. */
static int parse_volume(r4_ost *st, int first, int *res)
{
    r4_hdr h;
    int r, end = 0;
    u32 nfiles_vol = 0;
    *res = P_DONE;
    st->enc = 0;
    st->more = 0;
    if ((r = read_hdr(st, &h))) return first ? GZ_E_FORMAT : GZ_E_VOLUME;
    if (h.type != HT_MAIN || h.hs < 13) return first ? GZ_E_FORMAT : GZ_E_VOLUME;
    /* RAR 1.5 / 2.x: with an embedded comment the CRC covers 13 bytes */
    if (!h.crc_ok && crc16(h.h + 2, 11) != rd16(h.h)) return first ? GZ_E_FORMAT : GZ_E_VOLUME;
    u32 af = h.flags;
    if (first) {
        st->arc_flags = af;
        if ((af & MHD_COMMENT) && h.hs >= 26 && h.h[15] == HT_CMT && !st->has_cmt) {
            /* old comment block inside the main header */
            const u8 *cb = h.h + 13;
            u32 chs = rd16(cb + 5);
            if (chs >= 13 && chs <= h.hs - 13) {
                r4_item *ci = &st->cmt;
                __builtin_memset(ci, 0, sizeof *ci);
                ci->group = -1;
                ci->seg0 = st->pv->nseg;
                ci->nseg = 1;
                ci->ver = cb[9];
                ci->method = (u8)(cb[10] - 0x30);
                ci->dict = 0x10000;
                ci->crc = rd16(cb + 11);
                ci->has_crc = 1;
                ci->crc14 = 2;            /* CRC32 & 0xFFFF */
                if ((r = add_seg(st->pv, st->vol, h.off + 13 + 13, chs - 13))) return r;
                st->cmt_usize = rd16(cb + 7);
                st->cmt_oem = 1;
                st->has_cmt = 1;
            }
        }
    } else if (!(af & MHD_VOLUME)) {
        return GZ_E_VOLUME;
    }
    st->off = h.next;
    if (af & MHD_PASSWORD) {
        st->enc = 1;
        if ((r = setup_password(st))) return r;
    }
    for (;;) {
        if (gz_cancelled(st->c)) return GZ_E_CANCEL;
        r = read_hdr(st, &h);
        if (r) break;                          /* end of data or damage: keep what was read */
        if (++st->nhdr % 4096 == 0 && st->c && st->c->progress)
            st->c->progress(st->c->progress_user, h.next, st->src->size);
        if (!h.crc_ok && h.type != HT_AV && h.type != HT_SIGN && h.type != HT_FILE && h.type != HT_SERVICE) break;
        if (h.type == HT_FILE) {
            if (first == 1 && !nfiles_vol && (af & MHD_VOLUME) && (h.flags & LHD_SPLIT_BEFORE) && !(af & MHD_FIRSTVOL)) {
                *res = P_REDIRECT;
                return GZ_OK;
            }
            nfiles_vol++;
            r = add_file(st, &h);
            if (r == GZ_E_FORMAT || r == GZ_E_CRC) break;
            if (r) return r;
        } else if (h.type == HT_SERVICE) {
            r = add_service(st, &h);
            if (r == GZ_E_CRC) break;
            if (r) return r;
        } else if (h.type == HT_SUB) {
            if ((r = add_oldsub(st, &h))) return r;
        } else if (h.type == HT_END) {
            u32 ef = h.flags;
            end = 1;
            if (ef & EARC_NEXT_VOL) st->more = 1;
            u32 vo = 7 + ((ef & 2) ? 4 : 0);
            if (first == 1 && (af & MHD_VOLUME) && !(af & MHD_FIRSTVOL) && (ef & EARC_VOLNUM) &&
                h.hs >= vo + 2 && rd16(h.h + vo) > 0) {
                *res = P_REDIRECT;
                return GZ_OK;
            }
            break;
        }
        if (h.next <= st->off) break;
        st->off = h.next;
    }
    if (!end && (af & MHD_VOLUME) && st->pending >= 0) st->more = 1;
    if (st->more && (af & MHD_VOLUME)) *res = P_NEXT;
    return GZ_OK;
}

/* RAR 1.4: "RE~^" main header (no CRCs), 21-byte file headers */
static int parse_volume14(r4_ost *st, int first, int *res)
{
    gz_archive *a = st->a;
    r4_priv *pv = st->pv;
    const u8 *b;
    int r;
    *res = P_DONE;
    st->more = 0;
    u64 base = st->off;
    if ((r = ra_get(st, base, 7, &b))) return first ? GZ_E_FORMAT : GZ_E_VOLUME;
    u32 hs = rd16(b + 4), af = b[6];
    if (hs < 7 || __builtin_memcmp(b, sig14, 4)) return first ? GZ_E_FORMAT : GZ_E_VOLUME;
    if (first) {
        st->arc_flags = af;
        if ((af & MHD_COMMENT) && hs >= 9 && !ra_get(st, base, 9, &b)) {
            u32 cl = rd16(b + 7);
            if (cl && 9 + (u64)cl <= hs) {
                r4_item *ci = &st->cmt;
                __builtin_memset(ci, 0, sizeof *ci);
                ci->group = -1;
                ci->seg0 = pv->nseg;
                ci->nseg = 1;
                ci->dict = 0x10000;
                if ((af & MHD_PACKCMT14) && cl > 2 && !ra_get(st, base, 11, &b)) {
                    ci->ver = 15;
                    ci->method = 3;
                    ci->crypt = C_13;          /* fixed comment key */
                    ci->has_salt = 1;          /* marks the comment key */
                    st->cmt_usize = rd16(b + 9);
                    if ((r = add_seg(pv, st->vol, base + 11, cl - 2))) return r;
                } else {
                    st->cmt_usize = cl;
                    if ((r = add_seg(pv, st->vol, base + 9, cl))) return r;
                }
                st->cmt_oem = 1;
                st->has_cmt = 1;
            }
        }
    } else if (!(af & MHD_VOLUME)) {
        return GZ_E_VOLUME;
    }
    st->off = base + hs;
    u32 nfiles_vol = 0;
    for (;;) {
        if (gz_cancelled(st->c)) return GZ_E_CANCEL;
        u64 off = st->off;
        if ((r = ra_get(st, off, 21, &b))) break;
        u64 pack = rd32(b), unp = rd32(b + 4);
        u32 fcrc = rd16(b + 8), fhs = rd16(b + 10), ftime = rd32(b + 12), attr = b[16], fl = b[17];
        u32 ver = b[18] == 2 ? 13 : 10, nl = b[19], meth = b[20];
        if (fhs < 21 + nl || meth > 5) break;
        if ((r = ra_get(st, off + 21, nl, &b))) break;
        u64 doff = off + fhs;
        if (doff > st->src->size) break;
        if (first == 1 && !nfiles_vol && (af & MHD_VOLUME) && (fl & LHD_SPLIT_BEFORE)) {
            *res = P_REDIRECT;
            return GZ_OK;
        }
        nfiles_vol++;
        if (fl & LHD_SPLIT_BEFORE) {
            i32 pi = st->pending;
            st->nfile_hdrs++;
            st->pending = -1;
            if (pi >= 0) {
                r4_item *it = &pv->it[pi];
                if (it->seg0 + it->nseg != pv->nseg) {
                    it->incomplete = 1;
                } else {
                    if ((r = add_seg(pv, st->vol, doff, pack))) return r;
                    pv->it[pi].nseg++;
                    a->e[pi].csize += pack;
                    if (fl & LHD_SPLIT_AFTER) st->pending = pi;
                    else {
                        pv->it[pi].crc = fcrc;
                        pv->it[pi].has_crc = 1;
                    }
                }
            }
        } else {
            if (st->pending >= 0) {
                pv->it[st->pending].incomplete = 1;
                st->pending = -1;
            }
            gz_entry *e;
            r4_item *it;
            if ((r = add_named(st, b, nl, 0, &e)) || (r = add_item(st, &it))) return r;
            i32 idx = (i32)(a->n - 1);
            st->last_file = idx;
            e->is_dir = (attr & 0x10) != 0;
            e->usize = unp;
            e->csize = pack;
            e->off = doff;
            e->method = (u16)meth;
            e->mtime = ftime;
            e->mtime_kind = GZ_MT_DOS;
            set_attrs(e, 0, attr);
            it->ver = (u8)ver;
            it->method = (u8)meth;
            it->dict = 0x10000;
            it->solid = (af & MHD_SOLID) && st->nfile_hdrs > 0;
            it->kind = K_FILE;
            it->crc = fcrc;
            it->crc14 = 1;
            it->has_crc = !(fl & LHD_SPLIT_AFTER);
            if (fl & LHD_PASSWORD) {
                it->crypt = C_13;
                e->enc = GZ_ENC_OTHER;
            }
            st->nfile_hdrs++;
            if (!e->is_dir) {
                if ((r = add_seg(pv, st->vol, doff, pack))) return r;
                pv->it[idx].nseg = 1;
                if (fl & LHD_SPLIT_AFTER) st->pending = idx;
            }
        }
        if (doff + pack > st->src->size) break;
        st->off = doff + pack;
    }
    if ((af & MHD_VOLUME) && st->pending >= 0) *res = P_NEXT;
    return GZ_OK;
}

/* first entry of each solid run and the run's window */
static void finish(r4_ost *st)
{
    gz_archive *a = st->a;
    r4_priv *pv = st->pv;
    i32 last = -1;
    u64 maxd = 0, tot = 0;
    for (u32 i = 0; i <= a->n; i++) {
        r4_item *it = i < a->n ? &pv->it[i] : 0;
        int comp = it && !a->e[i].is_dir && it->kind == K_FILE && it->nseg && it->method != 0;
        if (it && !comp) continue;
        int cont = it && it->solid && last >= 0;
        if (last >= 0 && !cont) pv->it[pv->it[last].group].gwin = gz_rar3_window_size(maxd, tot);
        if (!it) break;
        if (cont) {
            it->group = pv->it[last].group;
            a->solid = 1;
            if (it->dict > maxd) maxd = it->dict;
            if (tot != GZ_SIZE_UNKNOWN)
                tot = a->e[i].usize == GZ_SIZE_UNKNOWN ? GZ_SIZE_UNKNOWN : tot + a->e[i].usize;
        } else {
            it->group = (i32)i;
            maxd = it->dict;
            tot = a->e[i].usize;
        }
        last = (i32)i;
    }
}

/* ---------------- extraction ---------------- */

typedef struct {
    gz_archive *a;
    r4_priv *pv;
    gz_src *s;
    gz_ctx *c;
    const r4_seg *seg;
    u32 nseg, si;
    u64 done;
    u32 crypt;
    gz_aes aes;
    u8 iv[16];
    r4_old_crypt oc;
} r4_rd;

typedef struct {
    gz_out *out;
    u32 crc;
    int do_crc, crc14;
} r4_sink;

typedef struct { r4_rd rd; r4_sink sk; } r4_io;

static gz_src *vol_src(const r4_rd *r, u32 vol)
{
    if (vol >= r->pv->nvol) return 0;
    i32 k = r->pv->vsrc[vol];
    return k < 0 ? r->s : (u32)k < r->a->nvols ? r->a->vols[k] : 0;
}

static int rd_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    r4_rd *r = &((r4_io *)ctx)->rd;
    int block = r->crypt == C_AES || r->crypt == C_20;
    *got = 0;
    if (gz_cancelled(r->c)) return GZ_E_CANCEL;
    if (block) {
        cap &= ~15u;
        if (!cap) return GZ_E_IO;
    }
    u32 n = 0;
    while (n < cap && r->si < r->nseg) {
        const r4_seg *g = &r->seg[r->si];
        u64 left = g->len - r->done;
        if (!left) { r->si++; r->done = 0; continue; }
        u32 take = (u64)(cap - n) < left ? cap - n : (u32)left;
        gz_src *src = vol_src(r, g->vol);
        if (!src) return GZ_E_VOLUME;
        int e = gz_src_read_exact(src, g->off + r->done, buf + n, take);
        if (e) return e;
        n += take;
        r->done += take;
    }
    switch (r->crypt) {
    case C_AES:
        n &= ~15u;
        gz_aes_cbc_decrypt(&r->aes, r->iv, buf, n);
        break;
    case C_20:
        n &= ~15u;
        for (u32 i = 0; i < n; i += 16) block20(&r->oc, buf + i, 1);
        break;
    case C_15:
        crypt15(&r->oc, buf, n);
        break;
    case C_13:
        decrypt13(&r->oc, buf, n);
        break;
    default:
        break;
    }
    *got = n;
    return GZ_OK;
}

static int sk_write(void *ctx, const u8 *p, size_t n)
{
    r4_sink *k = &((r4_io *)ctx)->sk;
    if (k->do_crc) k->crc = k->crc14 == 1 ? sum14(k->crc, p, n) : gz_crc32(k->crc, p, n);
    return k->out ? k->out->write(k->out, p, n) : GZ_OK;
}

typedef struct {
    gz_archive *a;
    r4_priv *pv;
    gz_src *s;
    gz_ctx *c;
    r4_tls *t;
    u8 pw[2 * PW_MAX];
    u32 pwlen;
    u8 pwa[4 * PW_MAX + 4];      /* ANSI password for the old ciphers */
    u32 pwalen;
    int has_pw;
} r4_x;

static int x_init(r4_x *x, gz_archive *a, gz_src *s, gz_ctx *c, const gzch *pw)
{
    __builtin_memset(x, 0, sizeof *x);
    x->a = a;
    x->pv = (r4_priv *)a->priv;
    x->s = s;
    x->c = c;
    x->t = get_tls(c);
    if (!x->t) return GZ_E_NOMEM;
    if (!pw) pw = c->password ? c->password : a->password;
    if (pw) {
        x->pwlen = pw_utf16(pw, x->pw);
        x->pwalen = pw_ansi(pw, x->pwa, sizeof x->pwa - 1);
        x->has_pw = 1;
    }
    return GZ_OK;
}

static void x_done(r4_x *x)
{
    __builtin_memset(x->pw, 0, sizeof x->pw);
    __builtin_memset(x->pwa, 0, sizeof x->pwa);
    if (x->t) gz_rar3_dec_trim(x->t->dec, KEEP_WIN);
}

static int copy_stored(r4_x *x, r4_io *io, u64 usize)
{
    u8 *buf = gz_ctx_buffer(x->c, 256u << 10);
    if (!buf) return GZ_E_NOMEM;
    u64 left = usize;
    while (left) {
        u32 got = 0;
        int r = rd_read(io, buf, 256u << 10, &got);
        if (r) return r;
        if (!got) break;
        u32 take = (u64)got < left ? got : (u32)left;
        if ((r = sk_write(io, buf, take))) return r;
        if (left != GZ_SIZE_UNKNOWN) left -= take;
    }
    return left && usize != GZ_SIZE_UNKNOWN ? GZ_E_TRUNC : GZ_OK;
}

/* Decode (or copy) the data of an item into out (NULL: discard).
 * solid: continue the decoder's stream; verify: check the checksum. */
static int item_data(r4_x *x, const r4_item *it, u64 usize, gz_out *out, int solid, int verify)
{
    if (it->incomplete) return GZ_E_VOLUME;
    if (it->crypt && !x->has_pw && !(it->crypt == C_13 && it->has_salt)) return GZ_E_PASSWORD;
    r4_io io;
    int r;
    __builtin_memset(&io, 0, sizeof io);
    io.rd.a = x->a;
    io.rd.pv = x->pv;
    io.rd.s = x->s;
    io.rd.c = x->c;
    io.rd.seg = x->pv->seg + it->seg0;
    io.rd.nseg = it->nseg;
    io.rd.crypt = it->crypt;
    switch (it->crypt) {
    case C_AES: {
        const r4_kdf *k = kdf_get(x->t, x->pw, x->pwlen, it->has_salt ? it->salt : 0);
        gz_aes_set_decrypt_key(&io.rd.aes, k->key, 16);
        __builtin_memcpy(io.rd.iv, k->iv, 16);
        break;
    }
    case C_20: setkey20(&io.rd.oc, x->pwa, x->pwalen); break;
    case C_15: setkey15(&io.rd.oc, x->pwa, x->pwalen); break;
    case C_13:
        if (it->has_salt) {               /* RAR 1.4 packed comment key */
            io.rd.oc.k13[0] = 0;
            io.rd.oc.k13[1] = 7;
            io.rd.oc.k13[2] = 77;
        } else {
            setkey13(&io.rd.oc, x->pwa, x->pwalen);
        }
        break;
    default: break;
    }
    io.sk.out = out;
    io.sk.do_crc = verify && it->has_crc;
    io.sk.crc14 = it->crc14;
    if (!it->method) {
        r = copy_stored(x, &io, usize);
    } else if (it->method > 5) {
        r = GZ_E_METHOD;
    } else {
        const r4_item *g = it->group >= 0 ? &x->pv->it[it->group] : it;
        gz_rar3_params pp;
        pp.version = it->ver;
        pp.window = it->group >= 0 ? g->gwin : gz_rar3_window_size(it->dict, usize);
        pp.solid = solid;
        gz_stream_io sio = { rd_read, sk_write, &io };
        r = gz_rar3_decode(x->t->dec, &sio, usize, &pp);
    }
    if (!r && io.sk.do_crc) {
        u32 v = io.sk.crc, want = it->crc;
        if (it->crc14 == 2) v &= 0xFFFF;
        if (v != want) r = GZ_E_CRC;
    }
    __builtin_memset(&io.rd.oc, 0, sizeof io.rd.oc);
    if (r && it->crypt && (r == GZ_E_CRC || r == GZ_E_DATA)) r = GZ_E_PASSWORD;
    return r;
}

/* decode entry di (in a solid run: from the run's first member) */
static int data_of(r4_x *x, u32 di, gz_out *out)
{
    const r4_item *it = &x->pv->it[di];
    gz_archive *a = x->a;
    if (it->group < 0 || (u32)it->group == di) return item_data(x, it, a->e[di].usize, out, 0, 1);
    for (u32 k = (u32)it->group; k <= di; k++) {
        const r4_item *m = &x->pv->it[k];
        if (m->group != it->group) continue;
        int r = item_data(x, m, a->e[k].usize, k == di ? out : 0, k != (u32)it->group, k == di);
        if (r) return r;
    }
    return GZ_OK;
}

static int needs_pw(const r4_x *x, const r4_item *it)
{
    return it->crypt && !x->has_pw;
}

static int extract_one(r4_x *x, u32 idx, gz_out *out)
{
    gz_entry *e = &x->a->e[idx];
    const r4_item *it = &x->pv->it[idx];
    int r;
    if (e->is_dir || !it->nseg) {
        if ((r = out->open(out, idx))) return r;
        return out->close(out, idx, it->incomplete ? GZ_E_VOLUME : GZ_OK);
    }
    if (needs_pw(x, it)) return GZ_E_PASSWORD;
    if ((r = out->open(out, idx))) return r;
    int st = data_of(x, idx, out);
    r = out->close(out, idx, st);
    return st ? st : r;
}

static int r4_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    r4_x x;
    int r = x_init(&x, a, s, c, 0);
    if (r) return r;
    r = extract_one(&x, idx, out);
    x_done(&x);
    return r;
}

static int r4_extract_solid(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_ctx *c)
{
    r4_x x;
    int r = x_init(&x, a, s, c, 0);
    if (r) return r;
    r4_priv *pv = x.pv;
    /* last selected member of each run */
    i32 *upto = (i32 *)gz_alloc(((size_t)a->n + 1) * sizeof(i32));
    if (!upto) { x_done(&x); return GZ_E_NOMEM; }
    for (u32 i = 0; i < a->n; i++) upto[i] = -1;
    for (u32 i = 0; i < a->n; i++)
        if (sel[i] && pv->it[i].group >= 0) upto[pv->it[i].group] = (i32)i;
    i32 cur = -1;
    int cerr = GZ_OK, ret = GZ_OK, later = 0;
    for (u32 i = 0; i < a->n; i++) {
        if (gz_cancelled(c)) { ret = GZ_E_CANCEL; break; }
        r4_item *it = &pv->it[i];
        if (it->group < 0) {
            if (!sel[i]) continue;
            /* streams with compressed data need the decoder on their own:
             * they wait until the solid runs are done */
            if (it->kind == K_STREAM && it->method && it->nseg) { later = 1; continue; }
            r = extract_one(&x, i, out);
            if (r == GZ_E_CANCEL) { ret = r; break; }
            continue;
        }
        i32 g = it->group;
        if (upto[g] < (i32)i) continue;            /* nothing selected from here on */
        if (g != cur) { cur = g; cerr = GZ_OK; }
        int opened = 0;
        if (sel[i]) {
            if (!cerr && needs_pw(&x, it)) cerr = GZ_E_PASSWORD;
            r = out->open(out, i);
            if (r == GZ_E_CANCEL) { ret = r; break; }
            if (!r && cerr) {
                r = out->close(out, i, cerr);
                if (r == GZ_E_CANCEL) { ret = r; break; }
                continue;
            }
            opened = !r;
        }
        if (cerr) continue;
        int st = item_data(&x, it, a->e[i].usize, opened ? out : 0, (u32)g != i, opened);
        if (st == GZ_E_CANCEL) { if (opened) out->close(out, i, st); ret = st; break; }
        /* a checksum mismatch leaves the stream intact; anything else ends the run */
        if (st && st != GZ_E_CRC) cerr = st;
        if (opened) {
            r = out->close(out, i, st);
            if (r == GZ_E_CANCEL) { ret = r; break; }
        }
    }
    for (u32 i = 0; later && !ret && i < a->n; i++) {
        r4_item *it = &pv->it[i];
        if (!sel[i] || it->group >= 0 || !(it->kind == K_STREAM && it->method && it->nseg)) continue;
        if (gz_cancelled(c)) { ret = GZ_E_CANCEL; break; }
        r = extract_one(&x, i, out);
        if (r == GZ_E_CANCEL) ret = r;
    }
    gz_free(upto);
    x_done(&x);
    return ret;
}

/* discard sink for the password check: stops after 64 KiB of output */
typedef struct { gz_out o; u64 n; } chk_out;

static int chk_write(gz_out *o, const u8 *p, size_t n)
{
    chk_out *k = (chk_out *)o;
    (void)p;
    k->n += n;
    return k->n >= (64u << 10) ? GZ_E_SKIP : GZ_OK;
}

/* No check values in RAR 1.5 - 4.x: decode the entry (or its run's first
 * member) up to 64 KiB and its whole data when small; corrupt data or a CRC
 * mismatch means a wrong password. */
static int r4_check_password(gz_archive *a, gz_src *s, u32 idx, gz_ctx *c)
{
    r4_x x;
    int r = x_init(&x, a, s, c, 0);
    if (r) return r;
    const r4_item *it = &x.pv->it[idx];
    r = GZ_OK;
    if (it->crypt && it->nseg && !a->e[idx].is_dir) {
        if (!x.has_pw) {
            r = GZ_E_PASSWORD;
        } else {
            u32 k = it->group >= 0 ? (u32)it->group : idx;
            chk_out co;
            __builtin_memset(&co, 0, sizeof co);
            co.o.write = chk_write;
            r = item_data(&x, &x.pv->it[k], a->e[k].usize, &co.o, 0, 1);
            r = r == GZ_E_PASSWORD ? r : GZ_OK;
        }
    }
    x_done(&x);
    return r;
}

/* ---------------- comment ---------------- */

typedef struct { gz_out o; gz_mem_sink m; } cmt_out;

static int cmt_write(gz_out *o, const u8 *p, size_t n)
{
    return gz_mem_write(&((cmt_out *)o)->m, p, n);
}

static void load_comment(r4_ost *st, gz_src *s)
{
    gz_archive *a = st->a;
    if (!st->has_cmt || !st->cmt_usize || st->cmt_usize > CMT_MAX) return;
    r4_x x;
    if (x_init(&x, a, s, st->c, a->password ? a->password : st->o->password)) return;
    cmt_out co;
    __builtin_memset(&co, 0, sizeof co);
    co.o.write = cmt_write;
    co.m.limit = CMT_MAX;
    int r = item_data(&x, &st->cmt, st->cmt_usize, &co.o, 0, 1);
    x_done(&x);
    if (!r && co.m.n) {
        u32 n = (u32)co.m.n;
        if (st->cmt_unicode) {
            n &= ~1u;
            while (n >= 2 && !rd16(co.m.p + n - 2)) n -= 2;
        } else {
            while (n && !co.m.p[n - 1]) n--;
        }
        a->comment_raw = co.m.p;
        a->comment_len = n;
        a->comment_enc = st->cmt_unicode ? GZ_NE_UTF16LE : st->cmt_oem ? GZ_NE_OEM : GZ_NE_LEGACY;
        co.m.p = 0;
    }
    gz_mem_sink_free(&co.m);
}

/* ---------------- probe / open ---------------- */

/* A marker at off followed by a main header with a valid CRC. */
static int sig_at(gz_src *s, u64 off)
{
    u8 b[7 + 13];
    if (off + sizeof b > s->size || gz_src_read_exact(s, off, b, sizeof b)) return 0;
    if (__builtin_memcmp(b, sig4, 7) || b[9] != HT_MAIN) return 0;
    u32 hs = rd16(b + 12);
    if (hs < 13 || hs > 4096 || off + 7 + hs > s->size) return 0;
    if (crc16(b + 9, 11) == rd16(b + 7)) return 1;
    u8 big[4096];
    if (gz_src_read_exact(s, off + 7, big, hs)) return 0;
    return crc16(big + 2, hs - 2) == rd16(big);
}

/* SFX: executables (PE / ELF) with the archive appended: search the marker */
static u64 find_sfx(gz_src *s, const u8 *head, u32 n)
{
    if (n < 64 || !((head[0] == 'M' && head[1] == 'Z') ||
                    (head[0] == 0x7F && head[1] == 'E' && head[2] == 'L' && head[3] == 'F')))
        return 0;
    u8 *buf = (u8 *)gz_alloc(65536 + 8);
    if (!buf) return 0;
    u64 lim = s->size < SFX_SCAN ? s->size : SFX_SCAN, found = 0;
    for (u64 base = 0; base < lim && !found; base += 65536) {
        u64 left = s->size - base;
        u32 want = left < 65536 + 8 ? (u32)left : 65536 + 8;
        if (want < 20 || gz_src_read_exact(s, base, buf, want)) break;
        for (u32 i = 0; i + 7 <= want && i < 65536; i++) {
            if (buf[i] != 0x52 || buf[i + 1] != 0x61 || __builtin_memcmp(buf + i, sig4, 7)) continue;
            if (base + i && sig_at(s, base + i)) { found = base + i; break; }
        }
    }
    gz_free(buf);
    return found;
}

/* RAR 1.4: main header size and the first file header must be plausible */
static int is_rar14(gz_src *s, const u8 *head, u32 n)
{
    if (n < 7 || __builtin_memcmp(head, sig14, 4)) return 0;
    u32 hs = rd16(head + 4);
    if (hs < 7 || hs > s->size) return 0;
    if (hs == s->size) return 1;
    u8 f[21];
    if (hs + 21 > s->size || gz_src_read_exact(s, hs, f, 21)) return 0;
    u32 fhs = rd16(f + 10);
    return fhs >= 21 + (u32)f[19] && f[20] <= 5 && hs + (u64)fhs <= s->size;
}

static int r4_probe(gz_src *s, const u8 *head, u32 n)
{
    if (n >= 7 && !__builtin_memcmp(head, sig4, 7)) return 95;
    if (is_rar14(s, head, n)) return 90;
    return find_sfx(s, head, n) ? 80 : 0;
}

static void r4_close(gz_archive *a)
{
    r4_priv *pv = (r4_priv *)a->priv;
    if (!pv) return;
    if (pv->it) __builtin_memset(pv->it, 0, (size_t)pv->nit * sizeof(r4_item));
    gz_free(pv->it);
    gz_free(pv->seg);
    gz_free(pv->vsrc);
    gz_free(pv);
    a->priv = 0;
}

static void open_reset(r4_ost *st)
{
    gz_archive *a = st->a;
    r4_priv *pv = st->pv;
    a->n = 0;
    a->raw_len = 0;
    a->win_names = 0;
    pv->nit = pv->nseg = pv->nvol = 0;
    st->pending = st->last_file = -1;
    st->has_cmt = 0;
    st->cmt_oem = st->cmt_unicode = 0;
    st->nfile_hdrs = 0;
}

static int parse_any(r4_ost *st, int first, int *res)
{
    return st->old14 ? parse_volume14(st, first, res) : parse_volume(st, first, res);
}

static int r4_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    u8 head[64];
    u64 base = 0;
    int r, res, old14 = 0;
    if (s->size < 7) return GZ_E_FORMAT;
    u32 hn = s->size < 64 ? (u32)s->size : 64;
    if ((r = gz_src_read_exact(s, 0, head, hn))) return r;
    if (!__builtin_memcmp(head, sig4, 7)) base = 0;
    else if (is_rar14(s, head, hn)) old14 = 1;
    else if (!(base = find_sfx(s, head, hn))) return GZ_E_FORMAT;
    r4_priv *pv = (r4_priv *)gz_alloc(sizeof(r4_priv));
    if (!pv) return GZ_E_NOMEM;
    a->priv = pv;
    a->sfx_shift = base;
    r4_ost st;
    __builtin_memset(&st, 0, sizeof st);
    st.a = a;
    st.o = o;
    st.c = c;
    st.pv = pv;
    st.old14 = old14;
    st.pending = st.last_file = -1;
    if (!(st.t = get_tls(c))) { r = GZ_E_NOMEM; goto out; }
    if (o->file_name && !(st.name = gz_wcsdup(o->file_name))) { r = GZ_E_NOMEM; goto out; }
    if ((r = add_volume(&st, s, -1))) goto out;
    st.off = old14 ? 0 : base + 7;
    r = parse_any(&st, 1, &res);
    if (!r && res == P_REDIRECT) {
        /* a later volume was opened: start from the first one when it exists */
        gzch *fn = st.name ? vol_first(st.name) : 0;
        gz_src *fs = 0;
        int fr = fn ? try_open(&st, fn, &fs) : GZ_E_VOLUME;
        open_reset(&st);
        if (fr == GZ_E_CANCEL) {
            r = fr;
        } else if (!fr) {
            i32 idx;
            if ((r = keep_src(a, fs, &idx))) {
                gz_src_free(fs);
            } else {
                gz_free(st.name);
                st.name = fn;
                fn = 0;
                if (!(r = add_volume(&st, fs, idx))) {
                    st.off = old14 ? 0 : 7;
                    r = parse_any(&st, 2, &res);
                }
            }
        } else if (!(r = add_volume(&st, s, -1))) {
            /* keep this volume as the start: files continued from before are incomplete */
            st.off = old14 ? 0 : base + 7;
            r = parse_any(&st, 2, &res);
        }
        gz_free(fn);
    }
    while (!r && res == P_NEXT) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        int vr = open_next(&st);
        if (vr == GZ_E_CANCEL) { r = vr; break; }
        if (vr) break;
        st.off = old14 ? 0 : 7;
        vr = parse_any(&st, 0, &res);
        if (vr == GZ_E_CANCEL || vr == GZ_E_NOMEM || vr == GZ_E_PASSWORD) { r = vr; break; }
        if (vr) break;
    }
    if (r) goto out;
    if (st.pending >= 0) pv->it[st.pending].incomplete = 1;
    finish(&st);
    if (old14) gz_arc_set_type(a, "RAR 1.4");
    load_comment(&st, s);
out:
    gz_free(st.buf);
    gz_free(st.ra);
    gz_free(st.name);
    __builtin_memset(st.pw, 0, sizeof st.pw);
    return r;
}

static u32 put_str(char *b, u32 k, u32 cap, const char *s)
{
    while (*s && k + 1 < cap) b[k++] = *s++;
    return k;
}

static void r4_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    const r4_priv *pv = (const r4_priv *)a->priv;
    u32 idx = (u32)(e - a->e);
    if (!cap) return;
    buf[0] = 0;
    if (idx >= pv->nit || e->is_dir) return;
    const r4_item *it = &pv->it[idx];
    u32 k = 0;
    char t[24];
    if (!it->method) {
        k = put_str(buf, k, cap, "Store");
    } else {
        u32 n = 0;
        if (it->ver != 29 && it->ver != 36) {
            /* older algorithms: "v15:" / "v20:" / "v26:" */
            t[n++] = 'v';
            u32 v = it->ver < 15 ? 15 : it->ver;
            t[n++] = (char)('0' + v / 10);
            t[n++] = (char)('0' + v % 10);
            t[n++] = ':';
        }
        t[n++] = 'm';
        t[n++] = (char)('0' + (it->method > 9 ? 9 : it->method));
        t[n++] = ':';
        u64 d = it->dict >> 10;
        const char *unit = "K";
        if (d >= 1024 && !(d & 1023)) { d >>= 10; unit = "M"; }
        char nb[12];
        u32 m = 0;
        do { nb[m++] = (char)('0' + d % 10); d /= 10; } while (d && m < 10);
        while (m) t[n++] = nb[--m];
        t[n] = 0;
        k = put_str(buf, k, cap, t);
        k = put_str(buf, k, cap, unit);
        if (it->ppmd) k = put_str(buf, k, cap, " PPMd");
    }
    static const char *const cn[] = { "", " Crypt13", " Crypt15", " Crypt20", " AES" };
    u32 ci = it->crypt == C_13 ? 1 : it->crypt == C_15 ? 2 : it->crypt == C_20 ? 3 : it->crypt == C_AES ? 4 : 0;
    k = put_str(buf, k, cap, cn[ci]);
    buf[k] = 0;
}

static gz_src *r4_view(gz_archive *a, gz_src *s, u32 idx)
{
    r4_priv *pv = (r4_priv *)a->priv;
    if (idx >= pv->nit) return 0;
    const r4_item *it = &pv->it[idx];
    const gz_entry *e = &a->e[idx];
    if (e->is_dir || it->crypt || it->incomplete || it->method || !it->nseg ||
        e->usize == GZ_SIZE_UNKNOWN || it->nseg > 64)
        return 0;
    r4_rd rd;
    __builtin_memset(&rd, 0, sizeof rd);
    rd.a = a;
    rd.pv = pv;
    rd.s = s;
    gz_src *parts[64];
    u64 left = e->usize;
    u32 np = 0;
    for (u32 k = 0; k < it->nseg && left; k++) {
        const r4_seg *g = &pv->seg[it->seg0 + k];
        gz_src *vs = vol_src(&rd, g->vol);
        u64 take = g->len < left ? g->len : left;
        gz_src *v = vs ? gz_src_sub(vs, g->off, take) : 0;
        if (!v || v->size != take) {
            gz_src_free(v);
            while (np) gz_src_free(parts[--np]);
            return 0;
        }
        parts[np++] = v;
        left -= take;
    }
    if (left) {
        while (np) gz_src_free(parts[--np]);
        return 0;
    }
    if (np == 1) return parts[0];
    if (!np) return gz_src_mem("", 0, 0);
    gz_src *cat = gz_src_concat(parts, np);
    if (!cat) while (np) gz_src_free(parts[--np]);
    return cat;
}

const gz_format gz_fmt_rar = {
    "RAR", "rar r00 exe", 0,
    r4_probe, r4_open, r4_close, r4_extract, r4_extract_solid,
    r4_check_password, r4_method, r4_view, 0
};
