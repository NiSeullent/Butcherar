/*
 * 고깃ZIP - RAR 5.0 archive reader (archives made by RAR 5.x - 7.x)
 *
 *   Headers: signature 52 61 72 21 1A 07 01 00, vint fields, header CRC32,
 *   main / file / service / encryption / end-of-archive headers, extra
 *   records (encryption, BLAKE2sp hash, times, version, redirection, owner,
 *   service data). Quick-open and recovery records are ignored.
 *   Entries: UTF-8 names, Windows attributes or Unix modes, symbolic links
 *   and junctions (target in the link fields), hard links and file copies
 *   (extracted from the file they refer to), NTFS streams (STM) as aux
 *   entries "file:stream", old file versions as "[VER]/n/name" (like 7-Zip),
 *   the CMT service as the archive comment.
 *   Encryption: AES-256-CBC with PBKDF2-HMAC-SHA256 keys (gz_rar5_kdf),
 *   encrypted headers (-hp, password asked at open), password check values,
 *   checksums turned into HMACs ("tweaked" CRC32 / BLAKE2sp).
 *   Volumes: name.partN.rar or name.rar, name.r00, ... (opened through
 *   o->open_volume; opening a later volume starts from the first one when it
 *   can be found); files split across volumes are read as one stream.
 *   Solid archives: files with the solid flag continue the previous file's
 *   decoder state; extract_solid decodes each solid run once, in order.
 *   SFX: the signature is searched in the first 4 MiB of executables.
 *
 * Memory: windows above 4 GiB (1 GiB on 32-bit hosts) are refused with
 * GZ_E_LIMIT; small files get a window no larger than their data.
 */
#include "arc.h"
#include "crc32.h"
#include "rar5dec.h"

GZ_FORMAT(gz_fmt_rar5)

static const u8 sig5[8] = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 };

enum { HT_MAIN = 1, HT_FILE = 2, HT_SERVICE = 3, HT_CRYPT = 4, HT_END = 5 };
#define HF_EXTRA        0x01u
#define HF_DATA         0x02u
#define HF_SPLIT_BEFORE 0x08u
#define HF_SPLIT_AFTER  0x10u
#define MF_VOLUME       0x01u
#define MF_VOLNUM       0x02u
#define MF_SOLID        0x04u
#define FF_DIR          0x01u
#define FF_MTIME        0x02u
#define FF_CRC          0x04u
#define FF_NOSIZE       0x08u
#define CI_SOLID        0x40u
#define CI_RAR5_COMPAT  0x100000u
enum { EX_CRYPT = 1, EX_HASH = 2, EX_TIME = 3, EX_VERSION = 4, EX_REDIR = 5, EX_OWNER = 6, EX_SUBDATA = 7 };
enum { RD_UNIX_LINK = 1, RD_WIN_LINK = 2, RD_JUNCTION = 3, RD_HARD = 4, RD_COPY = 5 };
enum { K_FILE = 0, K_STREAM = 1 };

#define MAX_HDR    (2u << 20)       /* header size limit of the format */
#define MAX_VOLS   9999u
#define SFX_SCAN   (4u << 20)
#define CMT_MAX    (1u << 20)
#define KEEP_WIN   ((u64)64 << 20)  /* windows kept cached between calls */
#define PW_MAX     127              /* password length limit (UTF-16 units) */

typedef struct { u32 vol, pad_; u64 off, len; } r5_seg;

typedef struct {
    u8 salt[16], iv[16], check[8];
    u8 lg2, has_check, mac, ok;     /* ok: AES-256 (version 0) */
} r5_crypt;

typedef struct {
    u32 seg0, nseg;
    u32 comp;            /* compression information                            */
    u32 crc;             /* CRC32 of the last part (an HMAC fold if crypt.mac)  */
    i32 crypt;           /* -1: not encrypted                                  */
    i32 hash;            /* BLAKE2sp digest index, -1: none                    */
    i32 copy_of;         /* hard link / file copy: entry holding the data      */
    i32 group;           /* solid run (index of its first entry), -1: none, -2: broken */
    u64 gwin;            /* first entry of a run: window for the run           */
    u8 has_crc, kind, incomplete, redir;
} r5_item;

typedef struct {
    r5_item *it;   u32 nit, capit;
    r5_seg *seg;   u32 nseg, capseg;
    r5_crypt *cr;  u32 ncr, capcr;
    u8 (*hash)[32]; u32 nhash, caphash;
    i32 *vsrc;     u32 nvol, capvol;    /* volume -> -1 (archive source) or a->vols index */
} r5_priv;

/* per-thread state: decoder + recent key derivations */
typedef struct {
    u8 salt[16], lg2, used, pad_[2];
    u32 pwlen;
    u8 pw[3 * PW_MAX + 4];
    u8 key[32], hkey[32], check[8];
} r5_kdf;

typedef struct {
    gz_rar5_dec *dec;
    r5_kdf kdf[4];
    u32 knext;
} r5_tls;

static void *tls_new(void)
{
    r5_tls *t = (r5_tls *)gz_alloc(sizeof(r5_tls));
    if (t && !(t->dec = gz_rar5_dec_new())) { gz_free(t); t = 0; }
    return t;
}

static void tls_free(void *p)
{
    r5_tls *t = (r5_tls *)p;
    gz_rar5_dec_free(t->dec);
    __builtin_memset(t->kdf, 0, sizeof t->kdf);
    gz_free(t);
}

static r5_tls *get_tls(gz_ctx *c)
{
    return (r5_tls *)gz_ctx_slot(c, GZ_SLOT_RAR, tls_new, tls_free);
}

static u64 win_cap(void)
{
    return sizeof(size_t) == 4 ? (u64)1 << 30 : (u64)1 << 32;
}

/* ---------------- small helpers ---------------- */

static int vint(const u8 *p, u32 n, u32 *i, u64 *v)
{
    u64 x = 0;
    for (u32 sh = 0; sh < 70; sh += 7) {
        if (*i >= n) return 0;
        u8 b = p[(*i)++];
        if (sh == 63 && b > 1) return 0;
        x |= (u64)(b & 0x7F) << sh;
        if (!(b & 0x80)) { *v = x; return 1; }
    }
    return 0;
}

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

static u64 dict_size(u32 comp)
{
    u32 v = comp & 63;
    if (v == 0) return (u64)0x20000 << ((comp >> 10) & 15);
    u64 d = (u64)0x20000 << ((comp >> 10) & 31);
    return d + d / 32 * ((comp >> 15) & 31);
}

/* UTF-16 password -> UTF-8 (at most PW_MAX units, like RAR) */
static u32 pw_utf8(const gzch *w, u8 *out)
{
    if (!w) return 0;
    size_t n = gz_wcslen(w);
    if (n > PW_MAX) n = PW_MAX;
    return (u32)gz_utf16_to_utf8(w, n, out);
}

static const r5_kdf *kdf_get(r5_tls *t, const u8 *pw, u32 pwlen, const u8 *salt, u32 lg2, int *err)
{
    for (u32 i = 0; i < 4; i++) {
        r5_kdf *k = &t->kdf[i];
        if (k->used && k->lg2 == lg2 && k->pwlen == pwlen && !__builtin_memcmp(k->salt, salt, 16) &&
            !__builtin_memcmp(k->pw, pw, pwlen))
            return k;
    }
    r5_kdf *k = &t->kdf[t->knext++ & 3];
    k->used = 0;
    *err = gz_rar5_kdf(pw, pwlen, salt, 16, lg2, k->key, k->hkey, k->check);
    if (*err) return 0;
    __builtin_memcpy(k->salt, salt, 16);
    __builtin_memcpy(k->pw, pw, pwlen);
    k->pwlen = pwlen;
    k->lg2 = (u8)lg2;
    k->used = 1;
    return k;
}

/* 8-byte check value + 4-byte SHA-256 checksum of it */
static int check_valid(const u8 *c12)
{
    u8 h[32];
    gz_sha256_calc(c12, 8, h);
    return !__builtin_memcmp(h, c12 + 8, 4);
}

/* ---------------- gzch name helpers ---------------- */

static int wdigit(gzch c) { return c >= '0' && c <= '9'; }

static size_t wname_start(const gzch *s, size_t n)
{
    size_t b = n;
    while (b && s[b - 1] != '/' && s[b - 1] != '\\') b--;
    return b;
}

/* index of the extension dot within the file name part, or n */
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

/* first volume of the set name belongs to (old style when the extension is
 * a letter and two digits, else the last digit group becomes 1) */
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
    u32 type, flags;
    u64 data_off, data_len;
    u64 next;                /* offset of the following header */
    const u8 *p; u32 n;      /* type specific fields                   */
    const u8 *x; u32 xn;     /* extra area                             */
} r5_hdr;

typedef struct {
    gz_archive *a;
    const gz_open_opts *o;
    gz_ctx *c;
    r5_priv *pv;
    gz_src *src;             /* current volume */
    u32 vol;
    u64 off;
    int enc;                 /* headers encrypted */
    gz_aes aes;
    u8 *buf; u32 cap;
    u32 arc_flags;
    u64 volnum;
    int more;                /* end header: another volume follows */
    i32 pending;             /* file continued in the next volume, -1 */
    i32 last_file;           /* parent of STM services */
    gzch *name;              /* file name of the current volume (owned) */
    int style;               /* volume naming: 0 unknown, 1 new (partN), 2 old (.rNN) */
    u8 pw[3 * PW_MAX + 4]; u32 pwlen; int have_pw;
    /* archive comment */
    int has_cmt;
    r5_item cmt;
    u64 cmt_usize;
    u64 nhdr;
} r5_ost;

static int buf_need(r5_ost *st, u32 n)
{
    if (n <= st->cap) return GZ_OK;
    u8 *b = (u8 *)gz_realloc(st->buf, n);
    if (!b) return GZ_E_NOMEM;
    st->buf = b;
    st->cap = n;
    return GZ_OK;
}

/* Read the header at st->off (decrypting it when headers are encrypted).
 * GZ_E_CRC: checksum mismatch (or wrong key), GZ_E_TRUNC/GZ_E_FORMAT: broken. */
static int read_hdr(r5_ost *st, const gz_aes *aes, r5_hdr *h)
{
    gz_src *s = st->src;
    u64 off = st->off;
    u32 i = 4, total, pre = 0, span;
    u64 hs;
    int r;
    if (off >= s->size) return GZ_E_TRUNC;
    if (!aes) {
        u8 t[8];
        u64 avail = s->size - off;
        u32 n = avail < 8 ? (u32)avail : 8;
        if (n < 6) return GZ_E_TRUNC;
        if ((r = gz_src_read_exact(s, off, t, n))) return r;
        if (!vint(t, n, &i, &hs) || i > 7) return GZ_E_FORMAT;
        if (!hs || hs > MAX_HDR) return GZ_E_FORMAT;
        total = i + (u32)hs;
        if ((r = buf_need(st, total + 16))) return r;
        if ((r = gz_src_read_exact(s, off, st->buf, total))) return r;
        span = total;
    } else {
        u8 iv[16];
        if (s->size - off < 32) return GZ_E_TRUNC;
        if ((r = gz_src_read_exact(s, off, iv, 16))) return r;
        if ((r = buf_need(st, 64))) return r;
        if ((r = gz_src_read_exact(s, off + 16, st->buf, 16))) return r;
        u8 iv2[16];
        __builtin_memcpy(iv2, iv, 16);
        gz_aes_cbc_decrypt(aes, iv2, st->buf, 16);
        if (!vint(st->buf, 16, &i, &hs) || i > 7) return GZ_E_CRC;
        if (!hs || hs > MAX_HDR) return GZ_E_CRC;
        total = i + (u32)hs;
        u32 padded = (total + 15) & ~15u;
        if ((r = buf_need(st, padded + 16))) return r;
        if (padded > 16) {
            if ((r = gz_src_read_exact(s, off + 32, st->buf + 16, padded - 16))) return r;
            gz_aes_cbc_decrypt(aes, iv2, st->buf + 16, padded - 16);
        }
        pre = 16;
        span = padded;
    }
    if (gz_crc32(0, st->buf + 4, total - 4) != rd32(st->buf)) return GZ_E_CRC;
    const u8 *b = st->buf;
    u64 type, flags, xl = 0, dl = 0;
    if (!vint(b, total, &i, &type) || !vint(b, total, &i, &flags)) return GZ_E_FORMAT;
    if ((flags & HF_EXTRA) && !vint(b, total, &i, &xl)) return GZ_E_FORMAT;
    if ((flags & HF_DATA) && !vint(b, total, &i, &dl)) return GZ_E_FORMAT;
    if (xl > total - i || dl > ((u64)1 << 60)) return GZ_E_FORMAT;
    h->type = (u32)(type > 255 ? 255 : type);
    h->flags = (u32)flags;
    h->p = b + i;
    h->n = total - i - (u32)xl;
    h->x = b + total - (u32)xl;
    h->xn = (u32)xl;
    h->data_off = off + pre + span;
    h->data_len = dl;
    h->next = h->data_off + dl;
    return GZ_OK;
}

/* ---------------- extra records ---------------- */

typedef struct {
    int has_crypt; r5_crypt cr;
    int has_hash; u8 hash[32];
    int has_mtime; u64 mtime;          /* FILETIME */
    int has_ver; u64 ver;
    int redir; const u8 *link; u32 link_len;
    const u8 *sub; u32 sub_len;        /* service data (stream name) */
} r5_extra;

static void parse_extra(const u8 *x, u32 n, r5_extra *e)
{
    __builtin_memset(e, 0, sizeof *e);
    u32 i = 0;
    while (i < n) {
        u64 sz, type;
        if (!vint(x, n, &i, &sz) || !sz || sz > n - i) return;
        u32 end = i + (u32)sz, j = i;
        if (!vint(x, end, &j, &type)) return;
        const u8 *p = x;
        switch (type) {
        case EX_CRYPT: {
            u64 ver, fl;
            if (!vint(p, end, &j, &ver) || !vint(p, end, &j, &fl) || end - j < 33) break;
            r5_crypt *c = &e->cr;
            c->lg2 = p[j];
            __builtin_memcpy(c->salt, p + j + 1, 16);
            __builtin_memcpy(c->iv, p + j + 17, 16);
            j += 33;
            if ((fl & 1) && end - j >= 12 && check_valid(p + j)) {
                __builtin_memcpy(c->check, p + j, 8);
                c->has_check = 1;
            }
            c->mac = (fl & 2) != 0;
            c->ok = ver == 0;
            e->has_crypt = 1;
            break;
        }
        case EX_HASH: {
            u64 ht;
            if (vint(p, end, &j, &ht) && ht == 0 && end - j >= 32) {
                __builtin_memcpy(e->hash, p + j, 32);
                e->has_hash = 1;
            }
            break;
        }
        case EX_TIME: {
            u64 fl;
            if (!vint(p, end, &j, &fl)) break;
            int unix_t = (fl & 1) != 0;
            u32 w = unix_t ? 4 : 8, nt = 0;
            u64 t[3];
            for (u32 k = 0; k < 3; k++) {
                if (!(fl & (2u << k))) continue;
                if (end - j < w) { nt = 0; break; }
                t[nt++] = unix_t ? rd32(p + j) : rd64(p + j);
                j += w;
            }
            if (!(fl & 2) || !nt) break;
            if (unix_t) {
                u64 ft = gz_unix_to_filetime((i64)t[0]);
                if ((fl & 0x10) && end - j >= 4) {
                    u32 ns = rd32(p + j);
                    if (ns < 1000000000u) ft += ns / 100;
                }
                e->mtime = ft;
            } else {
                e->mtime = t[0];
            }
            e->has_mtime = 1;
            break;
        }
        case EX_VERSION: {
            u64 fl, v;
            if (vint(p, end, &j, &fl) && vint(p, end, &j, &v) && v) { e->ver = v; e->has_ver = 1; }
            break;
        }
        case EX_REDIR: {
            u64 rt, fl, ln;
            if (!vint(p, end, &j, &rt) || !vint(p, end, &j, &fl) || !vint(p, end, &j, &ln)) break;
            if (ln > end - j || rt < 1 || rt > 5) break;
            e->redir = (int)rt;
            e->link = p + j;
            e->link_len = (u32)ln;
            break;
        }
        case EX_SUBDATA:
            e->sub = p + j;
            e->sub_len = end - j;
            break;
        default:
            break;
        }
        i = end;
    }
}

/* ---------------- building entries ---------------- */

static int add_seg(r5_priv *pv, u32 vol, u64 off, u64 len)
{
    int r = grow_arr((void **)&pv->seg, &pv->capseg, pv->nseg + 1, sizeof(r5_seg));
    if (r) return r;
    r5_seg *g = &pv->seg[pv->nseg++];
    g->vol = vol;
    g->pad_ = 0;
    g->off = off;
    g->len = len;
    return GZ_OK;
}

static int add_crypt(r5_priv *pv, const r5_crypt *c, i32 *idx)
{
    int r = grow_arr((void **)&pv->cr, &pv->capcr, pv->ncr + 1, sizeof(r5_crypt));
    if (r) return r;
    pv->cr[pv->ncr] = *c;
    *idx = (i32)pv->ncr++;
    return GZ_OK;
}

static int add_hash(r5_priv *pv, const u8 *h, i32 *idx)
{
    int r = grow_arr((void **)&pv->hash, &pv->caphash, pv->nhash + 1, 32);
    if (r) return r;
    __builtin_memcpy(pv->hash[pv->nhash], h, 32);
    *idx = (i32)pv->nhash++;
    return GZ_OK;
}

/* final checksums of a file come from its last part */
static int set_sums(r5_priv *pv, r5_item *it, const r5_extra *x, u64 ff, u32 crc)
{
    it->has_crc = (ff & FF_CRC) != 0;
    it->crc = crc;
    it->hash = -1;
    if (x->has_hash) return add_hash(pv, x->hash, &it->hash);
    return GZ_OK;
}

static int add_entry(r5_ost *st, const u8 *nm, u32 nl, const u8 *pre, u32 prel, gz_entry **pe, r5_item **pit)
{
    gz_archive *a = st->a;
    r5_priv *pv = st->pv;
    int r = grow_arr((void **)&pv->it, &pv->capit, pv->nit + 1, sizeof(r5_item));
    if (r) return r;
    if (prel) {
        /* prefix + name in a->raw */
        u32 off, o2;
        if ((r = gz_arc_raw_append(a, pre, prel, &off)) || (r = gz_arc_raw_append(a, nm, nl, &o2))) return r;
        if ((r = gz_arc_add_entry(a, pe))) return r;
        (*pe)->raw_off = off;
        (*pe)->raw_len = prel + nl;
        (*pe)->name_enc = GZ_NE_UTF8;
    } else if ((r = gz_arc_add_named(a, nm, nl, GZ_NE_UTF8, pe))) {
        return r;
    }
    r5_item *it = &pv->it[pv->nit++];
    __builtin_memset(it, 0, sizeof *it);
    it->crypt = it->hash = it->copy_of = it->group = -1;
    it->seg0 = pv->nseg;
    *pit = it;
    return GZ_OK;
}

static u32 fmt_u64(char *o, u64 v)
{
    char t[24];
    u32 n = 0, k = 0;
    do { t[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (n) o[k++] = t[--n];
    return k;
}

static int add_file(r5_ost *st, const r5_hdr *h)
{
    gz_archive *a = st->a;
    r5_priv *pv = st->pv;
    const u8 *p = h->p;
    u32 i = 0, crc = 0, mt32 = 0;
    u64 ff, usize, attr, comp, host, nl;
    if (!vint(p, h->n, &i, &ff) || !vint(p, h->n, &i, &usize) || !vint(p, h->n, &i, &attr)) return GZ_E_FORMAT;
    if (ff & FF_MTIME) {
        if (h->n - i < 4) return GZ_E_FORMAT;
        mt32 = rd32(p + i);
        i += 4;
    }
    if (ff & FF_CRC) {
        if (h->n - i < 4) return GZ_E_FORMAT;
        crc = rd32(p + i);
        i += 4;
    }
    if (!vint(p, h->n, &i, &comp) || !vint(p, h->n, &i, &host) || !vint(p, h->n, &i, &nl)) return GZ_E_FORMAT;
    if (nl > h->n - i) return GZ_E_FORMAT;
    const u8 *nm = p + i;
    r5_extra x;
    parse_extra(h->x, h->xn, &x);
    int svc = h->type == HT_SERVICE;
    int r;

    if (h->flags & HF_SPLIT_BEFORE) {
        /* continuation of the file left open by the previous volume */
        i32 pi = st->pending;
        if (svc || pi < 0) return GZ_OK;
        gz_entry *e = &a->e[pi];
        r5_item *it = &pv->it[pi];
        st->pending = -1;
        if (e->raw_len != nl || __builtin_memcmp(a->raw + e->raw_off, nm, (u32)nl) ||
            it->seg0 + it->nseg != pv->nseg) {
            it->incomplete = 1;
            return GZ_OK;
        }
        if ((r = add_seg(pv, st->vol, h->data_off, h->data_len))) return r;
        it = &pv->it[pi];
        it->nseg++;
        a->e[pi].csize += h->data_len;
        if (h->flags & HF_SPLIT_AFTER) {
            st->pending = pi;
        } else {
            if ((r = set_sums(pv, it, &x, ff, crc))) return r;
            a->e[pi].crc = it->crc;
            a->e[pi].has_crc = it->has_crc && !(it->crypt >= 0 && pv->cr[it->crypt].mac);
        }
        return GZ_OK;
    }
    if (st->pending >= 0 && !svc) {
        /* a new file while the previous one waits for its next part */
        pv->it[st->pending].incomplete = 1;
        st->pending = -1;
    }

    if (svc) {
        int is_cmt = nl == 3 && !__builtin_memcmp(nm, "CMT", 3);
        int is_stm = nl == 3 && !__builtin_memcmp(nm, "STM", 3);
        if (is_cmt && !st->has_cmt && !(h->flags & HF_SPLIT_AFTER)) {
            r5_item *ci = &st->cmt;
            __builtin_memset(ci, 0, sizeof *ci);
            ci->crypt = ci->hash = ci->copy_of = ci->group = -1;
            ci->seg0 = pv->nseg;
            ci->nseg = 1;
            ci->comp = (u32)comp;
            if ((r = add_seg(pv, st->vol, h->data_off, h->data_len))) return r;
            if (x.has_crypt && (r = add_crypt(pv, &x.cr, &ci->crypt))) return r;
            if ((r = set_sums(pv, ci, &x, ff, crc))) return r;
            st->cmt_usize = (ff & FF_NOSIZE) ? GZ_SIZE_UNKNOWN : usize;
            st->has_cmt = 1;
        }
        if (!is_stm || st->last_file < 0 || !x.sub_len) return GZ_OK;
    }

    /* name: plain, "[VER]/n/name" for old versions, "parent:stream" for streams */
    gz_entry *e;
    r5_item *it;
    if (svc) {
        gz_entry *pe = &a->e[st->last_file];
        u32 pl = pe->raw_len, sl = x.sub_len;
        int colon = x.sub[0] != ':';
        if ((size_t)pl + sl + 1 > 0x100000) return GZ_OK;
        u8 *tmp = (u8 *)gz_alloc((size_t)pl + sl + 2);
        if (!tmp) return GZ_E_NOMEM;
        __builtin_memcpy(tmp, a->raw + pe->raw_off, pl);
        if (colon) tmp[pl] = ':';
        __builtin_memcpy(tmp + pl + colon, x.sub, sl);
        r = add_entry(st, tmp, pl + colon + sl, 0, 0, &e, &it);
        gz_free(tmp);
        if (r) return r;
        e->is_aux = 1;
        it->kind = K_STREAM;
    } else if (x.has_ver) {
        char pre[48];
        u32 k = 0;
        const char *v = "[VER]/";
        while (*v) pre[k++] = *v++;
        k += fmt_u64(pre + k, x.ver);
        pre[k++] = '/';
        if ((r = add_entry(st, nm, (u32)nl, (const u8 *)pre, k, &e, &it))) return r;
    } else {
        if ((r = add_entry(st, nm, (u32)nl, 0, 0, &e, &it))) return r;
    }
    i32 idx = (i32)(a->n - 1);
    if (!svc) st->last_file = idx;

    e->is_dir = (ff & FF_DIR) != 0;
    e->usize = (ff & FF_NOSIZE) ? GZ_SIZE_UNKNOWN : usize;
    e->csize = h->data_len;
    e->off = h->data_off;
    e->method = (u16)((comp >> 7) & 7);
    it->comp = (u32)comp;
    if (x.has_mtime) { e->mtime = x.mtime; e->mtime_kind = GZ_MT_FILETIME; }
    else if (ff & FF_MTIME) { e->mtime = gz_unix_to_filetime((i64)mt32); e->mtime_kind = GZ_MT_FILETIME; }
    if (host == 1) {
        e->unix_mode = (u32)attr;
        if (!(attr & 0200)) e->attr |= 1;
    } else {
        e->attr = (u32)attr & 0x27;
    }
    if (e->is_dir) {
        e->attr |= 0x10;
        e->usize = 0;
    }
    if (x.has_crypt) {
        e->enc = x.cr.ok ? GZ_ENC_AES : GZ_ENC_OTHER;
        if ((r = add_crypt(pv, &x.cr, &it->crypt))) return r;
    }
    if (x.redir && e->is_dir && x.redir <= RD_JUNCTION) {
        /* directory symlink / junction: a link entry (attr keeps the directory bit) */
        e->is_dir = 0;
        if (!e->unix_mode) e->unix_mode = 0120777;
    }
    if (x.redir && !e->is_dir && !svc) {
        /* links keep their target in the link fields; a file copy keeps the
         * name of the file with its data there too (is_link stays 0) */
        u32 lo;
        it->redir = (u8)x.redir;
        if ((r = gz_arc_raw_append(a, x.link, x.link_len, &lo))) return r;
        e = &a->e[idx];
        e->is_link = x.redir == RD_HARD ? 2 : x.redir == RD_COPY ? 0 : 1;
        if (e->is_link == 1 && !e->unix_mode) e->unix_mode = 0120777;
        e->link_off = lo;
        e->link_len = x.link_len;
        e->csize = 0;
    }
    if (e->is_dir || it->redir) {
        it->nseg = 0;
    } else {
        if ((r = add_seg(pv, st->vol, h->data_off, h->data_len))) return r;
        it = &pv->it[idx];
        it->nseg = 1;
    }
    if ((r = set_sums(pv, it, &x, ff, crc))) return r;
    if ((h->flags & HF_SPLIT_AFTER) && !svc && it->nseg) {
        st->pending = idx;
        it->has_crc = 0;
        it->hash = -1;
    } else if (h->flags & HF_SPLIT_AFTER) {
        it->incomplete = 1;
    }
    /* HMAC'd sums are not CRCs; links carry no data of their own */
    a->e[idx].has_crc = it->has_crc && !(it->crypt >= 0 && pv->cr[it->crypt].mac) && !it->redir;
    a->e[idx].crc = it->crc;
    return GZ_OK;
}

/* ---------------- volumes ---------------- */

static int add_volume(r5_ost *st, gz_src *s, i32 vsrc_idx)
{
    r5_priv *pv = st->pv;
    if (pv->nvol >= MAX_VOLS) return GZ_E_LIMIT;
    int r = grow_arr((void **)&pv->vsrc, &pv->capvol, pv->nvol + 1, sizeof(i32));
    if (r) return r;
    pv->vsrc[pv->nvol] = vsrc_idx;
    st->vol = pv->nvol++;
    st->src = s;
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

static int try_open(r5_ost *st, const gzch *name, gz_src **out)
{
    *out = 0;
    if (!name || !st->o->open_volume) return GZ_E_VOLUME;
    int r = st->o->open_volume(st->o->user, name, out);
    if (r == GZ_E_CANCEL) return r;
    if (r || !*out) { *out = 0; return GZ_E_VOLUME; }
    u8 sg[8];
    if (gz_src_read_exact(*out, 0, sg, 8) || __builtin_memcmp(sg, sig5, 8)) {
        gz_src_free(*out);
        *out = 0;
        return GZ_E_VOLUME;
    }
    return GZ_OK;
}

/* Open the volume after the current one; GZ_E_VOLUME when it cannot be found. */
static int open_next(r5_ost *st)
{
    gz_src *s = 0;
    gzch *cand[2] = { 0, 0 };
    int sty[2] = { 1, 2 };
    int r = GZ_E_VOLUME;
    if (!st->name) return GZ_E_VOLUME;
    if (st->style != 2) cand[0] = vol_next_new(st->name);
    if (st->style != 1) cand[1] = vol_next_old(st->name);
    if (!st->style) {
        /* a first volume without digits in its name uses the old scheme */
        size_t n = gz_wcslen(st->name), dot = wext(st->name, n);
        if (!dot || !wdigit(st->name[dot - 1])) {
            gzch *t = cand[0];
            cand[0] = cand[1];
            cand[1] = t;
            sty[0] = 2;
            sty[1] = 1;
        }
    }
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
    if ((r = add_volume(st, s, idx))) return r;
    st->off = 8;
    return GZ_OK;
}

/* ---------------- header encryption ---------------- */

/* Archive encryption header: version, flags, KDF count, salt, check value.
 * Finds the password (given, cached or asked) whose key decrypts the headers. */
static int setup_hdr_crypt(r5_ost *st, const r5_hdr *h)
{
    u32 i = 0;
    u64 ver, fl;
    if (!vint(h->p, h->n, &i, &ver) || !vint(h->p, h->n, &i, &fl) || h->n - i < 17) return GZ_E_FORMAT;
    if (ver != 0) return GZ_E_METHOD;
    u32 lg2 = h->p[i];
    const u8 *salt = h->p + i + 1;
    i += 17;
    int has_check = (fl & 1) && h->n - i >= 12 && check_valid(h->p + i);
    const u8 *chk = h->p + i;
    r5_tls *t = get_tls(st->c);
    if (!t) return GZ_E_NOMEM;
    gzch ask[PW_MAX + 2];
    const gzch *pw = st->a->password ? st->a->password : st->o->password;
    int retry = 0;
    st->off = h->next;
    for (int tries = 0; tries < 16; tries++) {
        if (!pw) {
            if (!st->o->ask_password) return GZ_E_PASSWORD;
            ask[0] = 0;
            int r = st->o->ask_password(st->o->user, ask, PW_MAX + 1, retry);
            if (r) return r == GZ_E_CANCEL ? r : GZ_E_PASSWORD;
            ask[PW_MAX + 1] = 0;
            pw = ask;
        }
        u8 pb[3 * PW_MAX + 4];
        u32 pn = pw_utf8(pw, pb);
        int err = GZ_OK;
        const r5_kdf *k = kdf_get(t, pb, pn, salt, lg2, &err);
        if (!k) return err;
        int ok = 0;
        if (has_check) {
            ok = !__builtin_memcmp(k->check, chk, 8);
        } else {
            /* no check value: the next header must decrypt with a valid CRC */
            gz_aes aes;
            r5_hdr t2;
            gz_aes_set_decrypt_key(&aes, k->key, 32);
            ok = read_hdr(st, &aes, &t2) == GZ_OK;
        }
        if (ok) {
            gz_aes_set_decrypt_key(&st->aes, k->key, 32);
            st->enc = 1;
            st->a->headers_enc = 1;
            if (!st->a->password) {
                st->a->password = gz_wcsdup(pw);
                if (!st->a->password) return GZ_E_NOMEM;
            }
            return GZ_OK;
        }
        if (st->a->password) return GZ_E_PASSWORD;     /* later volume, other password */
        pw = 0;
        retry = 1;
    }
    return GZ_E_PASSWORD;
}

/* ---------------- parsing ---------------- */

enum { P_DONE = 0, P_NEXT = 1, P_REDIRECT = 2 };

/* Parse the headers of the current volume. *res: P_DONE, P_NEXT (another
 * volume follows) or P_REDIRECT (this is not the first volume). */
static int parse_volume(r5_ost *st, int first, int *res)
{
    int r, seen_main = 0;
    *res = P_DONE;
    st->enc = 0;
    st->more = 0;
    for (;;) {
        if (gz_cancelled(st->c)) return GZ_E_CANCEL;
        r5_hdr h;
        r = read_hdr(st, st->enc ? &st->aes : 0, &h);
        if (r) {
            if (!seen_main) return r == GZ_E_CRC && st->enc ? GZ_E_PASSWORD : (r == GZ_E_CRC ? GZ_E_FORMAT : r);
            return GZ_OK;              /* damaged or truncated: keep what was read */
        }
        if (++st->nhdr % 4096 == 0 && st->c && st->c->progress)
            st->c->progress(st->c->progress_user, h.next, st->src->size);
        if (h.type == HT_CRYPT) {
            if (seen_main || st->enc) return seen_main ? GZ_OK : GZ_E_FORMAT;
            if ((r = setup_hdr_crypt(st, &h))) return r;
            continue;
        }
        if (!seen_main) {
            if (h.type != HT_MAIN) return GZ_E_FORMAT;
            u32 i = 0;
            u64 af, vn = 0;
            if (!vint(h.p, h.n, &i, &af)) return GZ_E_FORMAT;
            if ((af & MF_VOLNUM) && !vint(h.p, h.n, &i, &vn)) return GZ_E_FORMAT;
            seen_main = 1;
            st->off = h.next;
            if (first) {
                st->arc_flags = (u32)af;
                st->volnum = vn;
                if (first == 1 && (af & MF_VOLUME) && vn > 0) { *res = P_REDIRECT; return GZ_OK; }
            } else if (!(af & MF_VOLUME) || vn != st->volnum + st->vol) {
                return GZ_E_VOLUME;
            }
            continue;
        }
        switch (h.type) {
        case HT_FILE:
        case HT_SERVICE:
            /* a malformed header ends the listing like a damaged one */
            if ((r = add_file(st, &h))) return r == GZ_E_FORMAT ? GZ_OK : r;
            break;
        case HT_END: {
            u32 i = 0;
            u64 ef = 0;
            vint(h.p, h.n, &i, &ef);
            if ((ef & 1) && (st->arc_flags & MF_VOLUME)) *res = P_NEXT;
            return GZ_OK;
        }
        default:
            break;
        }
        if (h.next <= st->off) return GZ_E_FORMAT;
        st->off = h.next;
    }
}

/* first entry of each solid run, windows, hard link / copy targets */
static int finish(r5_ost *st)
{
    gz_archive *a = st->a;
    r5_priv *pv = st->pv;
    i32 last = -1;
    u64 maxd = 0, tot = 0;
    for (u32 i = 0; i <= a->n; i++) {
        r5_item *it = i < a->n ? &pv->it[i] : 0;
        int comp = it && !a->e[i].is_dir && it->kind == K_FILE && !it->redir && it->nseg &&
                   ((it->comp >> 7) & 7) != 0;
        if (it && !comp) continue;
        int cont = it && (it->comp & CI_SOLID) && last >= 0 && pv->it[last].group >= 0;
        if (last >= 0 && !cont) {
            r5_item *g = &pv->it[pv->it[last].group];
            g->gwin = gz_rar5_window_size(maxd, tot);
        }
        if (!it) break;
        if (cont) {
            it->group = pv->it[last].group;
            a->solid = 1;
            u64 dsz = dict_size(it->comp);
            if (dsz > maxd) maxd = dsz;
            if (tot != GZ_SIZE_UNKNOWN) tot = a->e[i].usize == GZ_SIZE_UNKNOWN ? GZ_SIZE_UNKNOWN : tot + a->e[i].usize;
        } else if (it->comp & CI_SOLID) {
            it->group = -2;                    /* continues a stream we do not have */
            last = -1;
            continue;
        } else {
            it->group = (i32)i;
            maxd = dict_size(it->comp);
            tot = a->e[i].usize;
        }
        last = (i32)i;
    }
    /* hard links and file copies: find the target among earlier entries */
    u32 hcap = 0;
    i32 *ht = 0;
    for (u32 i = 0; i < a->n; i++) {
        r5_item *it = &pv->it[i];
        if (it->redir != RD_HARD && it->redir != RD_COPY) continue;
        if (!ht) {
            hcap = 16;
            while (hcap < a->n * 2) hcap <<= 1;
            ht = (i32 *)gz_alloc((size_t)hcap * sizeof(i32));
            if (!ht) return GZ_E_NOMEM;
            for (u32 k = 0; k < hcap; k++) ht[k] = -1;
            for (u32 k = 0; k < a->n; k++) {
                const gz_entry *e = &a->e[k];
                if (e->is_dir || e->is_aux || pv->it[k].redir) continue;
                u32 hv = 2166136261u;
                for (u32 j = 0; j < e->raw_len; j++) hv = (hv ^ a->raw[e->raw_off + j]) * 16777619u;
                u32 slot = hv & (hcap - 1);
                while (ht[slot] >= 0) slot = (slot + 1) & (hcap - 1);
                ht[slot] = (i32)k;
            }
        }
        const gz_entry *e = &a->e[i];
        const u8 *tn = a->raw + e->link_off;
        u32 tl = e->link_len;
        if (!tl) continue;
        u32 hv = 2166136261u;
        for (u32 j = 0; j < tl; j++) hv = (hv ^ tn[j]) * 16777619u;
        for (u32 slot = hv & (hcap - 1); ht[slot] >= 0; slot = (slot + 1) & (hcap - 1)) {
            const gz_entry *t = &a->e[ht[slot]];
            if ((u32)ht[slot] < i && t->raw_len == tl && !__builtin_memcmp(a->raw + t->raw_off, tn, tl)) {
                it->copy_of = ht[slot];
                break;
            }
        }
    }
    gz_free(ht);
    return GZ_OK;
}

/* ---------------- extraction ---------------- */

typedef struct {
    gz_archive *a;
    r5_priv *pv;
    gz_src *s;
    gz_ctx *c;
    const r5_seg *seg;
    u32 nseg, si;
    u64 done;
    int enc;
    gz_aes aes;
    u8 iv[16];
} r5_rd;

typedef struct {
    gz_out *out;
    u32 crc;
    int do_crc, do_b2;
    gz_blake2sp b2;
} r5_sink;

typedef struct { r5_rd rd; r5_sink sk; } r5_io;

static gz_src *vol_src(const r5_rd *r, u32 vol)
{
    if (vol >= r->pv->nvol) return 0;
    i32 k = r->pv->vsrc[vol];
    return k < 0 ? r->s : (u32)k < r->a->nvols ? r->a->vols[k] : 0;
}

static int rd_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    r5_rd *r = &((r5_io *)ctx)->rd;
    *got = 0;
    if (gz_cancelled(r->c)) return GZ_E_CANCEL;
    if (r->enc) {
        cap &= ~15u;
        if (!cap) return GZ_E_IO;
    }
    u32 n = 0;
    while (n < cap && r->si < r->nseg) {
        const r5_seg *g = &r->seg[r->si];
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
    if (r->enc) {
        n &= ~15u;
        gz_aes_cbc_decrypt(&r->aes, r->iv, buf, n);
    }
    *got = n;
    return GZ_OK;
}

static int sk_write(void *ctx, const u8 *p, size_t n)
{
    r5_sink *k = &((r5_io *)ctx)->sk;
    if (k->do_crc) k->crc = gz_crc32(k->crc, p, n);
    if (k->do_b2) gz_blake2sp_update(&k->b2, p, n);
    return k->out ? k->out->write(k->out, p, n) : GZ_OK;
}

typedef struct {
    gz_archive *a;
    r5_priv *pv;
    gz_src *s;
    gz_ctx *c;
    r5_tls *t;
    u8 pw[3 * PW_MAX + 4];
    u32 pwlen;
    int has_pw;
} r5_x;

static int x_init(r5_x *x, gz_archive *a, gz_src *s, gz_ctx *c)
{
    __builtin_memset(x, 0, sizeof *x);
    x->a = a;
    x->pv = (r5_priv *)a->priv;
    x->s = s;
    x->c = c;
    x->t = get_tls(c);
    if (!x->t) return GZ_E_NOMEM;
    const gzch *pw = c->password ? c->password : a->password;
    if (pw) {
        x->pwlen = pw_utf8(pw, x->pw);
        x->has_pw = 1;
    }
    return GZ_OK;
}

static void x_done(r5_x *x)
{
    __builtin_memset(x->pw, 0, sizeof x->pw);
    if (x->t) gz_rar5_dec_trim(x->t->dec, KEEP_WIN);
}

static int item_keys(r5_x *x, const r5_item *it, const r5_kdf **out)
{
    *out = 0;
    if (it->crypt < 0) return GZ_OK;
    const r5_crypt *cr = &x->pv->cr[it->crypt];
    if (!cr->ok) return GZ_E_METHOD;
    if (!x->has_pw) return GZ_E_PASSWORD;
    int err = GZ_OK;
    const r5_kdf *k = kdf_get(x->t, x->pw, x->pwlen, cr->salt, cr->lg2, &err);
    if (!k) return err == GZ_E_LIMIT ? GZ_E_METHOD : err;
    if (cr->has_check && __builtin_memcmp(k->check, cr->check, 8)) return GZ_E_PASSWORD;
    *out = k;
    return GZ_OK;
}

static u32 mac_crc(const u8 *hkey, u32 crc)
{
    u8 raw[4], d[32];
    wr32(raw, crc);
    gz_hmac_sha256_calc(hkey, 32, raw, 4, d);
    u32 v = 0;
    for (u32 i = 0; i < 32; i++) v ^= (u32)d[i] << ((i & 3) * 8);
    return v;
}

static int check_sums(r5_x *x, const r5_item *it, r5_sink *k, const r5_kdf *key)
{
    int mac = key && x->pv->cr[it->crypt].mac;
    if (k->do_crc) {
        u32 v = mac ? mac_crc(key->hkey, k->crc) : k->crc;
        if (v != it->crc) return GZ_E_CRC;
    }
    if (k->do_b2) {
        u8 d[32];
        gz_blake2sp_final(&k->b2, d);
        if (mac) gz_hmac_sha256_calc(key->hkey, 32, d, 32, d);
        if (__builtin_memcmp(d, x->pv->hash[it->hash], 32)) return GZ_E_CRC;
    }
    return GZ_OK;
}

static int copy_stored(r5_x *x, r5_io *io, u64 usize)
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

/* Decode (or copy) the data of item idx into out (NULL: discard).
 * solid: continue the decoder's stream; verify: check the checksums. */
static int item_data(r5_x *x, const r5_item *it, u64 usize, gz_out *out, int solid, int verify)
{
    if (it->incomplete) return GZ_E_VOLUME;
    const r5_kdf *key = 0;
    int r = item_keys(x, it, &key);
    if (r) return r;
    r5_io io;
    __builtin_memset(&io, 0, sizeof io);
    io.rd.a = x->a;
    io.rd.pv = x->pv;
    io.rd.s = x->s;
    io.rd.c = x->c;
    io.rd.seg = x->pv->seg + it->seg0;
    io.rd.nseg = it->nseg;
    if (key) {
        io.rd.enc = 1;
        gz_aes_set_decrypt_key(&io.rd.aes, key->key, 32);
        __builtin_memcpy(io.rd.iv, x->pv->cr[it->crypt].iv, 16);
    }
    io.sk.out = out;
    io.sk.do_crc = verify && it->has_crc;
    io.sk.do_b2 = verify && it->hash >= 0;
    if (io.sk.do_b2) gz_blake2sp_init(&io.sk.b2);
    u32 method = (it->comp >> 7) & 7, ver = it->comp & 63;
    if (!method) {
        r = copy_stored(x, &io, usize);
    } else if (ver > 1 || method > 5) {
        r = GZ_E_METHOD;
    } else {
        const r5_item *g = it->group >= 0 ? &x->pv->it[it->group] : it;
        gz_rar5_params pp;
        pp.window = it->group >= 0 ? g->gwin : gz_rar5_window_size(dict_size(it->comp), usize);
        pp.v7 = ver == 1 && !(it->comp & CI_RAR5_COMPAT);
        pp.solid = solid;
        if (pp.window > win_cap()) return GZ_E_LIMIT;
        gz_stream_io sio = { rd_read, sk_write, &io };
        r = gz_rar5_decode(x->t->dec, &sio, usize, &pp);
    }
    if (!r && verify) r = check_sums(x, it, &io.sk, key);
    if (r && key && !x->pv->cr[it->crypt].has_check && (r == GZ_E_CRC || r == GZ_E_DATA)) r = GZ_E_PASSWORD;
    return r;
}

/* entry whose data an entry extracts (itself, or the target of a link / copy) */
static i32 data_index(const r5_priv *pv, u32 idx)
{
    const r5_item *it = &pv->it[idx];
    return (it->redir == RD_HARD || it->redir == RD_COPY) ? it->copy_of : (i32)idx;
}

/* decode entry di (possibly in a solid run, decoding the run from its start) */
static int data_of(r5_x *x, u32 di, gz_out *out)
{
    const r5_item *it = &x->pv->it[di];
    gz_archive *a = x->a;
    if (it->group == -2) return GZ_E_DATA;
    if (it->group < 0 || (u32)it->group == di) return item_data(x, it, a->e[di].usize, out, 0, 1);
    for (u32 k = (u32)it->group; k <= di; k++) {
        const r5_item *m = &x->pv->it[k];
        if (m->group != it->group) continue;
        int r = item_data(x, m, a->e[k].usize, k == di ? out : 0, k != (u32)it->group, k == di);
        if (r) return r;
    }
    return GZ_OK;
}

/* one entry: open, data (or nothing for directories and links), close */
static int extract_one(r5_x *x, u32 idx, gz_out *out)
{
    gz_entry *e = &x->a->e[idx];
    i32 di = data_index(x->pv, idx);
    const r5_item *ii = &x->pv->it[idx];
    int r;
    if (e->is_dir || (e->is_link == 1 && e->link_len) || (!ii->nseg && !ii->redir)) {
        if ((r = out->open(out, idx))) return r;
        return out->close(out, idx, GZ_OK);
    }
    if (di >= 0) {
        const r5_kdf *k;
        if (item_keys(x, &x->pv->it[di], &k) == GZ_E_PASSWORD) return GZ_E_PASSWORD;
    }
    if ((r = out->open(out, idx))) return r;
    int st = di < 0 ? GZ_E_DATA : data_of(x, (u32)di, out);
    r = out->close(out, idx, st);
    return st ? st : r;
}

static int r5_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    r5_x x;
    int r = x_init(&x, a, s, c);
    if (r) return r;
    r = extract_one(&x, idx, out);
    x_done(&x);
    return r;
}

static int r5_extract_solid(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_ctx *c)
{
    r5_x x;
    int r = x_init(&x, a, s, c);
    if (r) return r;
    r5_priv *pv = x.pv;
    /* last selected member of each run */
    i32 *upto = (i32 *)gz_alloc(((size_t)a->n + 1) * sizeof(i32));
    if (!upto) { x_done(&x); return GZ_E_NOMEM; }
    for (u32 i = 0; i < a->n; i++) upto[i] = -1;
    for (u32 i = 0; i < a->n; i++)
        if (sel[i] && pv->it[i].group >= 0 && !pv->it[i].redir) upto[pv->it[i].group] = (i32)i;
    i32 cur = -1;
    int cerr = GZ_OK;
    int ret = GZ_OK, later = 0;
    for (u32 i = 0; i < a->n; i++) {
        if (gz_cancelled(c)) { ret = GZ_E_CANCEL; break; }
        r5_item *it = &pv->it[i];
        if (it->group < 0 || it->redir) {
            if (!sel[i]) continue;
            /* entries that need the decoder on their own (hard links and copies of
             * solid files, compressed streams) wait until the solid runs are done */
            if (it->redir == RD_HARD || it->redir == RD_COPY || (it->nseg && ((it->comp >> 7) & 7))) {
                later = 1;
                continue;
            }
            r = extract_one(&x, i, out);
            if (r == GZ_E_CANCEL) { ret = r; break; }
            continue;
        }
        i32 g = it->group;
        if (upto[g] < (i32)i) continue;            /* nothing selected from here on */
        if (g != cur) { cur = g; cerr = GZ_OK; }
        int opened = 0;
        if (sel[i]) {
            if (!cerr) {
                /* a wrong password stops the run: later members cannot be decoded */
                const r5_kdf *k;
                int pr = item_keys(&x, it, &k);
                if (pr == GZ_E_PASSWORD || pr == GZ_E_METHOD) cerr = pr;
            }
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
        r5_item *it = &pv->it[i];
        if (!sel[i] || !(it->group < 0 || it->redir)) continue;
        if (!(it->redir == RD_HARD || it->redir == RD_COPY || (it->nseg && ((it->comp >> 7) & 7)))) continue;
        if (gz_cancelled(c)) { ret = GZ_E_CANCEL; break; }
        r = extract_one(&x, i, out);
        if (r == GZ_E_CANCEL) ret = r;
    }
    gz_free(upto);
    x_done(&x);
    return ret;
}

static int r5_check_password(gz_archive *a, gz_src *s, u32 idx, gz_ctx *c)
{
    r5_x x;
    int r = x_init(&x, a, s, c);
    if (r) return r;
    i32 di = data_index(x.pv, idx);
    const r5_kdf *k;
    r = di < 0 ? GZ_OK : item_keys(&x, &x.pv->it[di], &k);
    x_done(&x);
    return r == GZ_E_PASSWORD ? r : GZ_OK;
}

/* ---------------- comment ---------------- */

typedef struct { gz_out o; gz_mem_sink m; } cmt_out;

static int cmt_write(gz_out *o, const u8 *p, size_t n)
{
    return gz_mem_write(&((cmt_out *)o)->m, p, n);
}

static void load_comment(r5_ost *st, gz_src *s)
{
    gz_archive *a = st->a;
    if (!st->has_cmt || !st->cmt_usize || st->cmt_usize > CMT_MAX) return;
    r5_x x;
    if (x_init(&x, a, s, st->c)) return;
    if (!x.has_pw && st->o->password) {
        x.pwlen = pw_utf8(st->o->password, x.pw);
        x.has_pw = 1;
    }
    cmt_out co;
    __builtin_memset(&co, 0, sizeof co);
    co.o.write = cmt_write;
    co.m.limit = CMT_MAX;
    int r = item_data(&x, &st->cmt, st->cmt_usize, &co.o, 0, 1);
    x_done(&x);
    if (!r && co.m.n) {
        u32 n = (u32)co.m.n;
        while (n && !co.m.p[n - 1]) n--;
        a->comment_raw = co.m.p;
        a->comment_len = n;
        a->comment_enc = GZ_NE_UTF8;
        co.m.p = 0;
    }
    gz_mem_sink_free(&co.m);
}

/* ---------------- probe / open ---------------- */

/* A RAR5 signature at off followed by a header with a valid CRC. */
static int sig_at(gz_src *s, u64 off)
{
    u8 b[64];
    if (off + 16 > s->size) return 0;
    u32 n = s->size - off < sizeof b ? (u32)(s->size - off) : (u32)sizeof b;
    if (gz_src_read_exact(s, off, b, n) || __builtin_memcmp(b, sig5, 8)) return 0;
    u32 i = 12;
    u64 hs;
    if (!vint(b, n, &i, &hs) || i > 15 || !hs || hs > 4096) return 0;
    u64 total = i - 8 + hs;
    u8 big[4200];
    if (off + 8 + total > s->size) return 0;
    if (gz_src_read_exact(s, off + 8, big, (u32)total)) return 0;
    return gz_crc32(0, big + 4, (size_t)total - 4) == rd32(big);
}

/* SFX: executables (PE / ELF) with the archive appended: search the signature */
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
        if (want < 16 || gz_src_read_exact(s, base, buf, want)) break;
        for (u32 i = 0; i + 8 <= want && i < 65536; i++) {
            if (buf[i] != 0x52 || buf[i + 1] != 0x61 || buf[i + 2] != 0x72 || __builtin_memcmp(buf + i, sig5, 8))
                continue;
            if (base + i && sig_at(s, base + i)) { found = base + i; break; }
        }
    }
    gz_free(buf);
    return found;
}

static int r5_probe(gz_src *s, const u8 *head, u32 n)
{
    if (n >= 8 && !__builtin_memcmp(head, sig5, 8)) return 95;
    return find_sfx(s, head, n) ? 80 : 0;
}

static void r5_close(gz_archive *a)
{
    r5_priv *pv = (r5_priv *)a->priv;
    if (!pv) return;
    gz_free(pv->it);
    gz_free(pv->seg);
    if (pv->cr) __builtin_memset(pv->cr, 0, (size_t)pv->ncr * sizeof(r5_crypt));
    gz_free(pv->cr);
    gz_free(pv->hash);
    gz_free(pv->vsrc);
    gz_free(pv);
    a->priv = 0;
}

static void open_reset(r5_ost *st)
{
    gz_archive *a = st->a;
    r5_priv *pv = st->pv;
    a->n = 0;
    a->raw_len = 0;
    pv->nit = pv->nseg = pv->ncr = pv->nhash = pv->nvol = 0;
    st->pending = st->last_file = -1;
    st->has_cmt = 0;
}

static int r5_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    u8 head[64];
    u64 base = 0;
    int r, res;
    if (s->size < 16) return GZ_E_FORMAT;
    u32 hn = s->size < 64 ? (u32)s->size : 64;
    if ((r = gz_src_read_exact(s, 0, head, hn))) return r;
    if (__builtin_memcmp(head, sig5, 8) && !(base = find_sfx(s, head, hn))) return GZ_E_FORMAT;
    r5_priv *pv = (r5_priv *)gz_alloc(sizeof(r5_priv));
    if (!pv) return GZ_E_NOMEM;
    a->priv = pv;
    a->sfx_shift = base;
    r5_ost st;
    __builtin_memset(&st, 0, sizeof st);
    st.a = a;
    st.o = o;
    st.c = c;
    st.pv = pv;
    st.pending = st.last_file = -1;
    if (o->file_name && !(st.name = gz_wcsdup(o->file_name))) return GZ_E_NOMEM;
    if ((r = add_volume(&st, s, -1))) goto out;
    st.off = base + 8;
    r = parse_volume(&st, 1, &res);
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
                    st.off = 8;
                    r = parse_volume(&st, 1, &res);
                    if (!r && res == P_REDIRECT) r = GZ_E_FORMAT;
                }
            }
        } else if (!(r = add_volume(&st, s, -1))) {
            /* keep this volume as the start: files continued from before are incomplete */
            st.off = base + 8;
            r = parse_volume(&st, 2, &res);
        }
        gz_free(fn);
    }
    while (!r && res == P_NEXT) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        int vr = open_next(&st);
        if (vr == GZ_E_CANCEL) { r = vr; break; }
        if (vr) break;
        vr = parse_volume(&st, 0, &res);
        if (vr == GZ_E_CANCEL || vr == GZ_E_NOMEM) { r = vr; break; }
        if (vr) break;
    }
    if (r) goto out;
    if (st.pending >= 0) pv->it[st.pending].incomplete = 1;
    if ((r = finish(&st))) goto out;
    load_comment(&st, s);
out:
    gz_free(st.buf);
    gz_free(st.name);
    return r;
}

static u32 put_str(char *b, u32 k, u32 cap, const char *s)
{
    while (*s && k + 1 < cap) b[k++] = *s++;
    return k;
}

/* 128K, 32M, 4G, 1536M (RAR7 fractional sizes stay in the larger unit's divisor) */
static u32 put_size(char *b, u32 k, u32 cap, u64 v)
{
    static const char unit[] = "KMGTP";
    u32 u = 0;
    v >>= 10;
    while (v >= 1024 && !(v & 1023) && u < 4) { v >>= 10; u++; }
    char t[24];
    u32 n = fmt_u64(t, v);
    t[n++] = unit[u];
    t[n] = 0;
    return put_str(b, k, cap, t);
}

static void r5_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    const r5_priv *pv = (const r5_priv *)a->priv;
    u32 idx = (u32)(e - a->e);
    if (!cap) return;
    buf[0] = 0;
    if (idx >= pv->nit) return;
    const r5_item *it = &pv->it[idx];
    u32 k = 0, m = (it->comp >> 7) & 7, v = it->comp & 63;
    if (it->redir) {
        static const char *const rn[] = { "", "Symlink", "Symlink", "Junction", "Hardlink", "Copy" };
        k = put_str(buf, k, cap, rn[it->redir]);
    } else if (!m) {
        k = put_str(buf, k, cap, "Store");
    } else {
        if (v == 1 && !(it->comp & CI_RAR5_COMPAT)) k = put_str(buf, k, cap, "v7:");
        else if (v > 1) k = put_str(buf, k, cap, "v?:");
        char t[4] = { 'm', (char)('0' + m), ':', 0 };
        k = put_str(buf, k, cap, t);
        k = put_size(buf, k, cap, dict_size(it->comp));
    }
    if (it->crypt >= 0) k = put_str(buf, k, cap, pv->cr[it->crypt].ok ? " AES" : " Crypto?");
    buf[k] = 0;
}

static gz_src *r5_view(gz_archive *a, gz_src *s, u32 idx)
{
    r5_priv *pv = (r5_priv *)a->priv;
    if (idx >= pv->nit) return 0;
    const r5_item *it = &pv->it[idx];
    const gz_entry *e = &a->e[idx];
    if (e->is_dir || it->redir || it->crypt >= 0 || it->incomplete || ((it->comp >> 7) & 7) || !it->nseg ||
        e->usize == GZ_SIZE_UNKNOWN || it->nseg > 64)
        return 0;
    r5_rd rd;
    __builtin_memset(&rd, 0, sizeof rd);
    rd.a = a;
    rd.pv = pv;
    rd.s = s;
    gz_src *parts[64];
    u64 left = e->usize;
    u32 np = 0;
    for (u32 k = 0; k < it->nseg && left; k++) {
        const r5_seg *g = &pv->seg[it->seg0 + k];
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
    gz_src *cat = gz_src_concat(parts, np);
    if (!cat) while (np) gz_src_free(parts[--np]);
    return cat;
}

const gz_format gz_fmt_rar5 = {
    "RAR5", "rar exe", 0,
    r5_probe, r5_open, r5_close, r5_extract, r5_extract_solid,
    r5_check_password, r5_method, r5_view, 0
};

