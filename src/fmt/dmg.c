/*
 * 고깃ZIP - Apple disk images (UDIF .dmg: UDRO/UDRW/UDCO/UDZO/UDBZ/ULFO/ULMO)
 *
 *   koly trailer (512 bytes, big-endian; at the end of the file, or at the
 *   start of a few old images) -> partition list: the "blkx" resources of the
 *   XML property list, or of the classic binary resource fork -> one mish
 *   table per partition: runs of 512-byte sectors that are stored, zero /
 *   ignored, or one compressed chunk each (ADC, zlib, bzip2, LZFSE, XZ).
 *   Chunk offsets are relative to DataForkOffset + the mish DataOffset.
 *
 * Entries are the partitions, named like 7-Zip ("4.hfs", "0.ddm", "1.Apple_
 * partition_map"). Partition maps, free space, drivers, GPT/MBR tables and
 * EFI / boot partitions are aux entries, so the core opens the one file
 * system inside automatically ("HFS+ (DMG)"). view() maps sectors to chunks
 * (binary search) and decodes compressed chunks on demand into a small LRU
 * cache owned by the view. The mish CRC-32 of a partition (over everything but
 * the "ignore" runs) is checked when the whole partition is extracted.
 * Encrypted images (encrcdsa / cdsaencr) give GZ_E_METHOD.
 *
 * Entry fields: off = partition index in the private table.
 */
#include "vdisk.h"
#include "crc32.h"
#include "crc64.h"
#include "adc.h"
#include "lzfse.h"
#include "bzip2.h"
#include "lzma.h"
#include "hfs.h"

#define KOLY_SIZE     512u
#define MAX_PARTS     4096u
#define MAX_CHUNKS    (8u << 20)               /* all partitions together         */
#define MAX_UNPACKED  (256u << 20)             /* one decoded chunk               */
#define CACHE_BUDGET  (16u << 20)              /* decoded chunks kept per view    */
#define MAX_XZ_DICT   ((u64)256 << 20)

enum { K_ZERO, K_RAW, K_IGNORE, K_ADC, K_ZLIB, K_BZIP2, K_LZFSE, K_XZ, K_UNKNOWN, K_COUNT };
static const char *const k_kind_name[K_COUNT] = {
    "Zero", "Copy", "Ignore", "ADC", "ZLIB", "BZip2", "LZFSE", "XZ", "Unknown"
};

typedef struct {
    u64 sec, nsec;            /* sectors, relative to the partition start      */
    u64 off, len;             /* absolute file offset / length of the data      */
    u32 kind;                 /* K_*                                             */
} dmg_chunk;

typedef struct {
    dmg_chunk *ch;
    u32 nch;
    u32 kinds;                /* 1 << K_* present                                */
    u64 nsec;
    u32 max_unp;              /* largest compressed chunk, decoded bytes         */
    u32 max_mem;              /* largest ADC / LZFSE chunk, packed bytes         */
} dmg_part;

typedef struct {
    dmg_part *p;
    u32 np;
} dmg_img;

/* ---------------- partition list ---------------- */

typedef struct { u8 *b; size_t n, cap; } dbuf;

static int db_put(dbuf *d, const void *p, size_t n)
{
    if (n > ((size_t)1 << 30) - d->n) return GZ_E_LIMIT;
    if (d->n + n > d->cap) {
        size_t nc = d->cap ? d->cap * 2 : 1024;
        while (nc < d->n + n) nc *= 2;
        u8 *nb = (u8 *)gz_realloc(d->b, nc);
        if (!nb) return GZ_E_NOMEM;
        d->b = nb;
        d->cap = nc;
    }
    if (n) __builtin_memcpy(d->b + d->n, p, n);
    d->n += n;
    return GZ_OK;
}

static u32 kind_of(u32 t)
{
    switch (t) {
    case 0: return K_ZERO;
    case 1: return K_RAW;
    case 2: return K_IGNORE;
    case 0x80000004u: return K_ADC;
    case 0x80000005u: return K_ZLIB;
    case 0x80000006u: return K_BZIP2;
    case 0x80000007u: return K_LZFSE;
    case 0x80000008u: return K_XZ;
    }
    return K_UNKNOWN;
}

/* Parse one mish table. base = absolute offset that chunk offsets are relative to. */
static int parse_mish(const u8 *m, size_t n, u64 base, u64 fsize, dmg_part *p, u32 *budget, u32 *crc, int *has_crc)
{
    *has_crc = 0;
    if (n < 204 || rd32be(m) != 0x6D697368u) return GZ_E_FORMAT;          /* "mish" */
    u64 nsec = rd64be(m + 16);
    u64 doff = rd64be(m + 24);
    u32 cnt = rd32be(m + 200);
    if ((n - 204) / 40 < cnt) return GZ_E_FORMAT;
    if (nsec > GZ_VD_MAX_SIZE >> 9) return GZ_E_LIMIT;
    if (doff > fsize || base > fsize - doff) return GZ_E_FORMAT;
    base += doff;
    if (cnt > *budget) return GZ_E_LIMIT;
    p->nsec = nsec;
    p->ch = (dmg_chunk *)gz_alloc((size_t)cnt * sizeof(dmg_chunk) + 1);
    if (!p->ch) return GZ_E_NOMEM;
    u64 next = 0;                                  /* end of the previous chunk */
    for (u32 i = 0; i < cnt; i++) {
        const u8 *c = m + 204 + (size_t)i * 40;
        u32 t = rd32be(c);
        if (t == 0xFFFFFFFFu) break;                                       /* terminator */
        if (t == 0x7FFFFFFEu) continue;                                    /* comment    */
        u64 sec = rd64be(c + 8), cn = rd64be(c + 16), off = rd64be(c + 24), len = rd64be(c + 32);
        if (!cn) continue;
        u32 k = kind_of(t);
        if (sec < next || sec >= nsec) return GZ_E_FORMAT;                 /* unordered / outside */
        if (cn > nsec - sec) {
            if (k != K_ZERO && k != K_RAW && k != K_IGNORE) return GZ_E_FORMAT;
            cn = nsec - sec;                                               /* clip stored runs */
        }
        if (k != K_ZERO && k != K_IGNORE) {
            if (off > fsize || base > fsize - off) return GZ_E_FORMAT;
            off += base;
            if (len > fsize - off) return GZ_E_TRUNC;
        }
        if (k >= K_ADC && k <= K_XZ) {
            if (cn > MAX_UNPACKED >> 9) return GZ_E_LIMIT;
            u32 unp = (u32)cn << 9;
            if (!len) return GZ_E_FORMAT;
            if (unp > p->max_unp) p->max_unp = unp;
            if (k == K_ADC || k == K_LZFSE) {
                if (len > (u64)unp * 2 + 65536) return GZ_E_FORMAT;     /* no sane encoder */
                if (len > p->max_mem) p->max_mem = (u32)len;
            }
        }
        dmg_chunk *d = &p->ch[p->nch++];
        d->sec = sec;
        d->nsec = cn;
        d->off = off;
        d->len = len;
        d->kind = k;
        p->kinds |= 1u << k;
        next = sec + cn;
    }
    *budget -= p->nch;
    /* UDIF checksum: type 2 = CRC-32 (32 bits), big-endian in the first word */
    if (rd32be(m + 64) == 2 && rd32be(m + 68) == 32) {
        *crc = rd32be(m + 72);
        *has_crc = 1;
    }
    return GZ_OK;
}

/* One partition found in the plist / resource fork: name bytes + mish data. */
typedef struct {
    u32 name_off, name_len;   /* in names */
    u8 macroman;              /* name from the resource fork (Mac Roman), else UTF-8 */
    dmg_part p;
    u32 crc;
    int has_crc;
} dmg_found;

typedef struct {
    dmg_found *f;
    u32 nf, capf;
    dbuf names;
    u64 base, fsize;
    u32 budget;
} dmg_list;

static int list_add(dmg_list *L, const u8 *name, u32 nl, int macroman, const u8 *mish, size_t mn)
{
    if (L->nf >= MAX_PARTS) return GZ_E_LIMIT;
    if (L->nf == L->capf) {
        u32 nc = L->capf ? L->capf * 2 : 16;
        dmg_found *nf = (dmg_found *)gz_realloc(L->f, (size_t)nc * sizeof(dmg_found));
        if (!nf) return GZ_E_NOMEM;
        L->f = nf;
        L->capf = nc;
    }
    dmg_found *f = &L->f[L->nf];
    __builtin_memset(f, 0, sizeof *f);
    f->name_off = (u32)L->names.n;
    f->name_len = nl;
    f->macroman = (u8)macroman;
    int r = db_put(&L->names, name, nl);
    if (r) return r;
    L->nf++;                                      /* counted before parsing: freed on error */
    return parse_mish(mish, mn, L->base, L->fsize, &f->p, &L->budget, &f->crc, &f->has_crc);
}

/* ---- XML property list ---- */

static const u8 *mem_find(const u8 *p, const u8 *e, const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    while ((size_t)(e - p) >= n) {
        const u8 *q = (const u8 *)__builtin_memchr(p, s[0], (size_t)(e - p) - n + 1);
        if (!q) return 0;
        if (!__builtin_memcmp(q, s, n)) return q;
        p = q + 1;
    }
    return 0;
}

static const u8 *skip_ws(const u8 *p, const u8 *e)
{
    while (p < e && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    return p;
}

static int starts(const u8 *p, const u8 *e, const char *s)
{
    for (; *s; s++, p++) if (p >= e || *p != (u8)*s) return 0;
    return 1;
}

/* Value element following <key>name</key> inside [p, e): content range of <tag>. */
static int plist_value(const u8 *p, const u8 *e, const char *key, const char *tag, const u8 **vb, const u8 **ve)
{
    char open[24], close[24];
    u32 k = 0, t = 0;
    open[k++] = '<';
    close[t++] = '<'; close[t++] = '/';
    for (const char *s = tag; *s && k < 20; s++) { open[k++] = *s; close[t++] = *s; }
    open[k++] = '>'; open[k] = 0;
    close[t++] = '>'; close[t] = 0;
    for (const u8 *q = p; (q = mem_find(q, e, "<key>")) != 0;) {
        q += 5;
        const u8 *ke = mem_find(q, e, "</key>");
        if (!ke) return 0;
        const u8 *n = q;
        const char *s = key;
        while (*s && n < ke && *n == (u8)*s) { n++; s++; }
        q = ke + 6;
        if (*s || n != ke) continue;
        q = skip_ws(q, e);
        if (!starts(q, e, open)) return 0;
        q += k;
        const u8 *x = mem_find(q, e, close);
        if (!x) return 0;
        *vb = q;
        *ve = x;
        return 1;
    }
    return 0;
}

static int b64v(u8 c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* base64 (whitespace ignored, stops at '=' or anything else) into out (>= 3/4 of the input) */
static size_t b64_decode(const u8 *p, const u8 *e, u8 *out)
{
    u32 acc = 0, bits = 0;
    size_t n = 0;
    for (; p < e; p++) {
        int v = b64v(*p);
        if (v < 0) {
            if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') continue;
            break;
        }
        acc = acc << 6 | (u32)v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out[n++] = (u8)(acc >> bits); }
    }
    return n;
}

/* XML text with the predefined entities and character references decoded to UTF-8 */
static u32 xml_text(const u8 *p, const u8 *e, u8 *out, u32 cap)
{
    u32 n = 0;
    while (p < e && n + 4 <= cap) {
        if (*p != '&') { out[n++] = *p++; continue; }
        const u8 *sc = p + 1;
        while (sc < e && sc - p < 12 && *sc != ';') sc++;
        if (sc >= e || *sc != ';') { out[n++] = *p++; continue; }
        u32 c = 0;
        const u8 *q = p + 1;
        if (starts(q, sc, "amp")) c = '&';
        else if (starts(q, sc, "lt")) c = '<';
        else if (starts(q, sc, "gt")) c = '>';
        else if (starts(q, sc, "quot")) c = '"';
        else if (starts(q, sc, "apos")) c = '\'';
        else if (*q == '#') {
            q++;
            int hex = q < sc && (*q == 'x' || *q == 'X');
            if (hex) q++;
            for (; q < sc && c < 0x110000; q++) {
                u32 d = *q >= '0' && *q <= '9' ? (u32)(*q - '0') : hex && (*q | 32) >= 'a' && (*q | 32) <= 'f' ? (u32)((*q | 32) - 'a' + 10) : 99;
                if (d >= (hex ? 16u : 10u)) { c = 0; break; }
                c = c * (hex ? 16 : 10) + d;
            }
            if (c >= 0x110000 || (c >= 0xD800 && c < 0xE000)) c = 0;
        }
        if (!c) { out[n++] = *p++; continue; }
        if (c < 0x80) out[n++] = (u8)c;
        else if (c < 0x800) { out[n++] = (u8)(0xC0 | c >> 6); out[n++] = (u8)(0x80 | (c & 63)); }
        else if (c < 0x10000) { out[n++] = (u8)(0xE0 | c >> 12); out[n++] = (u8)(0x80 | ((c >> 6) & 63)); out[n++] = (u8)(0x80 | (c & 63)); }
        else { out[n++] = (u8)(0xF0 | c >> 18); out[n++] = (u8)(0x80 | ((c >> 12) & 63)); out[n++] = (u8)(0x80 | ((c >> 6) & 63)); out[n++] = (u8)(0x80 | (c & 63)); }
        p = sc + 1;
    }
    return n;
}

static int parse_xml(dmg_list *L, const u8 *x, size_t n, gz_ctx *c)
{
    const u8 *e = x + n;
    const u8 *k = mem_find(x, e, "<key>blkx</key>");
    if (!k) return GZ_E_FORMAT;
    const u8 *p = skip_ws(k + 15, e);
    if (!starts(p, e, "<array>")) return GZ_E_FORMAT;
    p += 7;
    u8 *mish = 0;
    size_t mcap = 0;
    int r = GZ_OK;
    for (u32 cnt = 0; !r; cnt++) {
        p = skip_ws(p, e);
        if (p >= e || starts(p, e, "</array>")) break;
        if (!starts(p, e, "<dict>")) { r = GZ_E_FORMAT; break; }
        const u8 *db = p + 6, *de = mem_find(db, e, "</dict>");
        if (!de) { r = GZ_E_FORMAT; break; }
        p = de + 7;
        if ((cnt & 63) == 63 && gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        const u8 *vb, *ve, *nb = 0, *ne = 0;
        if (!plist_value(db, de, "Data", "data", &vb, &ve)) continue;
        if (!plist_value(db, de, "Name", "string", &nb, &ne) || nb == ne)
            if (!plist_value(db, de, "CFName", "string", &nb, &ne)) nb = ne = 0;
        size_t need = (size_t)(ve - vb) / 4 * 3 + 3;
        if (need > mcap) {
            gz_free(mish);
            mcap = need;
            if (!(mish = (u8 *)gz_alloc(mcap))) { r = GZ_E_NOMEM; break; }
        }
        size_t mn = b64_decode(vb, ve, mish);
        u8 nm[1024];
        u32 nl = nb ? xml_text(nb, ne, nm, sizeof nm) : 0;
        r = list_add(L, nm, nl, 0, mish, mn);
    }
    gz_free(mish);
    return r;
}

/* ---- classic resource fork ---- */

static int parse_rsrc(dmg_list *L, const u8 *f, size_t n)
{
    if (n < 16) return GZ_E_FORMAT;
    u32 doff = rd32be(f), moff = rd32be(f + 4), dlen = rd32be(f + 8), mlen = rd32be(f + 12);
    if (doff > n || dlen > n - doff || moff > n || mlen > n - moff || mlen < 30) return GZ_E_FORMAT;
    const u8 *m = f + moff;
    u32 tl = rd16be(m + 24), nl = rd16be(m + 26);
    if (tl + 2u > mlen) return GZ_E_FORMAT;
    const u8 *types = m + tl;
    u32 ntypes = (rd16be(types) + 1u) & 0xFFFF;
    if (tl + 2u + ntypes * 8u > mlen) return GZ_E_FORMAT;
    for (u32 i = 0; i < ntypes; i++) {
        const u8 *t = types + 2 + i * 8;
        if (rd32be(t) != 0x626C6B78u) continue;                             /* "blkx" */
        u32 nref = (rd16be(t + 4) + 1u) & 0xFFFF, rl = rd16be(t + 6);
        if (tl + (u64)rl + (u64)nref * 12 > mlen) return GZ_E_FORMAT;
        for (u32 j = 0; j < nref; j++) {
            const u8 *ref = types + rl + j * 12;
            u32 no = rd16be(ref + 2), dpos = rd32be(ref + 4) & 0xFFFFFF;
            if (dpos > dlen - 4 || dlen < 4) return GZ_E_FORMAT;
            const u8 *d = f + doff + dpos;
            u32 len = rd32be(d);
            if (len > dlen - dpos - 4) return GZ_E_FORMAT;
            const u8 *nm = 0;
            u32 nlen = 0;
            if (no != 0xFFFF && (u64)nl + no < mlen) {
                nm = m + nl + no;
                nlen = *nm++;
                if ((u64)nl + no + 1 + nlen > mlen) nlen = 0;
            }
            int r = list_add(L, nm, nlen, 1, d + 4, len);
            if (r) return r;
        }
    }
    return GZ_OK;
}

/* ---------------- naming ---------------- */

typedef struct { const char *apple, *ext; int aux; } dmg_name;

/* 7-Zip's names: the partition type in "Name (Type : n)" gives the extension */
static const dmg_name k_names[] = {
    { "Apple_HFS", "hfs", 0 }, { "Apple_HFSX", "hfsx", 0 }, { "Apple_UFS", "ufs", 0 },
    { "Apple_APFS", "apfs", 0 }, { "Apple_ISO", "iso", 0 },
    { "C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "efi_system", 1 },
    { "Apple_Free", "free", 1 }, { "DDM", "ddm", 1 },
};

/* Partition types (or whole names without a type) that are partition-map plumbing
 * rather than a file system: aux entries, so they do not block the automatic descent. */
static const char *const k_aux[] = {
    "Apple_partition_map", "GPT ", "MBR", "Driver", "Patches", "Apple_Free", "Apple_Void",
    "Apple_Scratch", "Apple_Boot", "DDM", "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
};

static int has_sub(const u8 *s, u32 n, const char *t)
{
    u32 k = 0;
    while (t[k]) k++;
    for (u32 i = 0; i + k <= n; i++) if (!__builtin_memcmp(s + i, t, k)) return 1;
    return 0;
}

/* "<index>.<ext>" or "<index>_<name>" (UTF-8 into out, cap >= 1100); returns length */
static u32 part_name(const u8 *nm, u32 nl, int macroman, u32 idx, u32 digits, u8 *out, int *aux)
{
    u8 tmp[1024 * 3 / 2 + 8];
    u32 n = 0;
    if (macroman) {                                 /* Mac Roman -> UTF-8 */
        u32 k = 0;
        for (u32 i = 0; i < nl && k + 3 < sizeof tmp; i++) {
            u32 c = nm[i] < 0x80 ? nm[i] : gz_macroman_hi[nm[i] - 0x80];
            if (c < 0x80) tmp[k++] = (u8)c;
            else if (c < 0x800) { tmp[k++] = (u8)(0xC0 | c >> 6); tmp[k++] = (u8)(0x80 | (c & 63)); }
            else { tmp[k++] = (u8)(0xE0 | c >> 12); tmp[k++] = (u8)(0x80 | ((c >> 6) & 63)); tmp[k++] = (u8)(0x80 | (c & 63)); }
        }
        nm = tmp;
        nl = k;
    }
    char d[12];
    u32 nd = 0;
    do { d[nd++] = (char)('0' + idx % 10); idx /= 10; } while (idx);
    while (nd < digits && nd < 10) d[nd++] = '0';
    while (nd) out[n++] = (u8)d[--nd];
    /* "Name (Type : n)" -> Type; the aux test looks at the type when there is one */
    const u8 *ty = nm;
    u32 tl = nl, lp = 0, b = 0, te = 0;
    while (lp < nl && nm[lp] != '(') lp++;
    if (lp < nl) {
        u32 c = b = lp + 1;
        while (c < nl && nm[c] != ':') c++;
        if (c < nl) {
            while (b < c && nm[b] == ' ') b++;
            te = c;
            while (te > b && nm[te - 1] == ' ') te--;
            ty = nm + b;
            tl = te - b;
        }
    }
    *aux = 0;
    for (u32 i = 0; i < GZ_COUNTOF(k_aux); i++) if (has_sub(ty, tl, k_aux[i])) *aux = 1;
    if (lp < nl) {
        if (te > b) {
            const u8 *ext = ty;
            u32 el = tl;
            for (u32 i = 0; i < GZ_COUNTOF(k_names); i++) {
                u32 k = 0;
                while (k_names[i].apple[k] && k < el && (u8)k_names[i].apple[k] == ext[k]) k++;
                if (k == el && !k_names[i].apple[k]) {
                    ext = (const u8 *)k_names[i].ext;
                    el = 0;
                    while (ext[el]) el++;
                    *aux = k_names[i].aux;
                    break;
                }
            }
            out[n++] = '.';
            for (u32 i = 0; i < el && n < 1090; i++) out[n++] = ext[i] == '/' ? '_' : ext[i];
        }
        return n;                     /* "(" without a type: the number alone, like 7-Zip */
    }
    if (nl) out[n++] = '_';
    for (u32 i = 0; i < nl && n < 1090; i++) out[n++] = nm[i] == '/' ? '_' : nm[i];
    return n;
}

/* ---------------- open ---------------- */

static void img_free(dmg_img *im)
{
    if (!im) return;
    for (u32 i = 0; i < im->np; i++) gz_free(im->p[i].ch);
    gz_free(im->p);
    gz_free(im);
}

static void dmg_close(gz_archive *a)
{
    img_free((dmg_img *)a->priv);
    a->priv = 0;
}

static int is_koly(const u8 *h)
{
    return rd32be(h) == 0x6B6F6C79u && rd32be(h + 4) == 4 && rd32be(h + 8) == KOLY_SIZE;
}

/* Read [off, off+len) of s into a new buffer (len checked against the cap). */
static int load(gz_src *s, u64 off, u64 len, u8 **out)
{
    *out = 0;
    if (len > GZ_VD_MAX_TABLE) return GZ_E_LIMIT;
    if (off > s->size || len > s->size - off) return GZ_E_TRUNC;
    u8 *p = (u8 *)gz_alloc((size_t)len + 16);
    if (!p) return GZ_E_NOMEM;
    int r = len ? gz_src_read_exact(s, off, p, (u32)len) : GZ_OK;
    if (r) { gz_free(p); return r; }
    *out = p;
    return GZ_OK;
}

/* Load the partition list given the koly header k and the base offset of the image. */
static int read_list(dmg_list *L, gz_src *s, const u8 *k, u64 base, gz_ctx *c)
{
    u64 xo = rd64be(k + 216), xl = rd64be(k + 224);
    u64 ro = rd64be(k + 40), rl = rd64be(k + 48);
    u64 df = rd64be(k + 24);
    u8 *buf = 0;
    int r;
    if (df > s->size || base > s->size - df) return GZ_E_FORMAT;
    L->base = base + df;
    L->fsize = s->size;
    if (xl) {
        if (xo > s->size || base > s->size - xo) return GZ_E_FORMAT;
        if ((r = load(s, base + xo, xl, &buf))) return r;
        const u8 *p = skip_ws(buf, buf + xl);
        if (!starts(p, buf + xl, "<?xml") && !starts(p, buf + xl, "<plist") && !starts(p, buf + xl, "<!DOCTYPE"))
            r = GZ_E_FORMAT;
        else
            r = parse_xml(L, buf, (size_t)xl, c);
    } else if (rl) {
        if (ro > s->size || base > s->size - ro) return GZ_E_FORMAT;
        if ((r = load(s, base + ro, rl, &buf))) return r;
        r = parse_rsrc(L, buf, (size_t)rl);
    } else {
        r = GZ_E_FORMAT;
    }
    gz_free(buf);
    return r;
}

static void list_free(dmg_list *L)
{
    for (u32 i = 0; i < L->nf; i++) gz_free(L->f[i].p.ch);
    gz_free(L->f);
    gz_free(L->names.b);
    __builtin_memset(L, 0, sizeof *L);
}

static int dmg_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    u8 k[KOLY_SIZE];
    if (s->size < KOLY_SIZE) return GZ_E_FORMAT;
    u8 sig[8];
    int r = gz_src_read_exact(s, 0, sig, 8);
    if (r) return r;
    if (!__builtin_memcmp(sig, "encrcdsa", 8)) return GZ_E_METHOD;           /* encrypted v2 */
    if ((r = gz_src_read_exact(s, s->size - 8, sig, 8))) return r;
    if (!__builtin_memcmp(sig, "cdsaencr", 8)) return GZ_E_METHOD;           /* encrypted v1 */
    u64 hpos = s->size - KOLY_SIZE;
    if ((r = gz_src_read_exact(s, hpos, k, KOLY_SIZE))) return r;
    int front = 0;
    if (!is_koly(k)) {
        if ((r = gz_src_read_exact(s, 0, k, KOLY_SIZE))) return r;
        if (!is_koly(k)) return GZ_E_FORMAT;
        front = 1;
    }
    dmg_list L;
    __builtin_memset(&L, 0, sizeof L);
    L.budget = MAX_CHUNKS;
    r = read_list(&L, s, k, 0, c);
    if (r && r != GZ_E_NOMEM && r != GZ_E_CANCEL) {
        /* image appended to other data (trailer), or offsets after a front header */
        u64 xo = rd64be(k + 216), xl = rd64be(k + 224), ro = rd64be(k + 40), rl = rd64be(k + 48);
        u64 end = xl ? xo + xl : ro + rl, shift = 0;
        if (front) shift = KOLY_SIZE;
        else if (end < hpos && end >= xo && end >= ro) shift = hpos - end;
        if (shift) {
            list_free(&L);
            L.budget = MAX_CHUNKS;
            r = read_list(&L, s, k, shift, c);
        }
    }
    if (!r && !L.nf) r = GZ_E_FORMAT;
    dmg_img *im = 0;
    if (!r) {
        im = (dmg_img *)gz_alloc(sizeof(dmg_img));
        if (im) im->p = (dmg_part *)gz_alloc((size_t)L.nf * sizeof(dmg_part));
        if (!im || !im->p) { gz_free(im); im = 0; r = GZ_E_NOMEM; }
        else a->priv = im;
    }
    u32 digits = 1;
    for (u32 v = 10; v < L.nf && digits < 10; v *= 10) digits++;
    for (u32 i = 0; !r && i < L.nf; i++) {
        dmg_found *f = &L.f[i];
        u8 nm[1100];
        int aux;
        u32 nl = part_name(L.names.b + f->name_off, f->name_len, f->macroman, i, digits, nm, &aux);
        gz_entry *e;
        if ((r = gz_arc_add_named(a, nm, nl, GZ_NE_UTF8, &e))) break;
        im->p[im->np] = f->p;                  /* move the chunk table */
        f->p.ch = 0;
        dmg_part *p = &im->p[im->np];
        e->off = im->np++;
        e->usize = p->nsec << 9;
        u64 cs = 0;
        for (u32 j = 0; j < p->nch; j++)
            if (p->ch[j].kind != K_ZERO && p->ch[j].kind != K_IGNORE) cs += p->ch[j].len;
        e->csize = cs;
        e->attr = 0x20;
        e->is_aux = (u8)aux;
        e->crc = f->crc;
        e->has_crc = (u8)f->has_crc;
        e->aux32 = p->kinds;
    }
    list_free(&L);
    return r;
}

/* ---------------- view ---------------- */

#define SLOTS 4

typedef struct {
    gz_vd_view v;
    const dmg_part *p;
    u8 *buf[SLOTS];           /* decoded chunks, p->max_unp bytes each      */
    u32 key[SLOTS];           /* chunk index + 1, 0 = empty                 */
    u32 age[SLOTS];
    u32 tick, nslots;
    u8 *pack;                 /* compressed ADC / LZFSE chunk               */
    gz_bzip2_dec *bz;
    gz_lzfse_dec *lz;
    gz_lzma_dec *xz;
} dmg_vw;

typedef struct { u8 *dst; u32 cap, n; } buf_sink;

static int buf_write(void *user, const u8 *p, size_t n)
{
    buf_sink *k = (buf_sink *)user;
    if (n > (size_t)(k->cap - k->n)) return GZ_E_DATA;
    __builtin_memcpy(k->dst + k->n, p, n);
    k->n += (u32)n;
    return GZ_OK;
}

static int read_varint(const u8 *p, u32 n, u32 *i, u64 *v)
{
    *v = 0;
    for (u32 sh = 0; sh < 63; sh += 7) {
        if (*i >= n) return GZ_E_DATA;
        u8 b = p[(*i)++];
        *v |= (u64)(b & 0x7F) << sh;
        if (!(b & 0x80)) return (b || !sh) ? GZ_OK : GZ_E_DATA;
    }
    return GZ_E_DATA;
}

/* XZ stream (ULMO chunks): blocks with one LZMA2 filter, decoded into dst. */
static int xz_chunk(dmg_vw *v, gz_src *f, u64 pos, u64 len, buf_sink *k)
{
    static const u8 csz[16] = { 0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64 };
    u8 h[1024];
    u64 end = pos + len;
    if (len < 12) return GZ_E_DATA;
    int r = gz_src_read_exact(f, pos, h, 12);
    if (r) return r;
    if (__builtin_memcmp(h, "\xFD" "7zXZ\0", 6) || h[6] || h[7] > 15 || gz_crc32(0, h + 6, 2) != rd32(h + 8))
        return GZ_E_DATA;
    u32 check = h[7];
    u64 p = pos + 12;
    if (!v->xz) {
        if (!(v->xz = gz_lzma_dec_new())) return GZ_E_NOMEM;
        gz_lzma_dec_set_limit(v->xz, MAX_XZ_DICT);
    }
    for (u32 blocks = 0; blocks < 4096; blocks++) {
        if (p >= end) return GZ_E_TRUNC;
        if ((r = gz_src_read_exact(f, p, h, 1))) return r;
        if (!h[0]) return GZ_OK;                                     /* index: done */
        u32 hs = (h[0] + 1u) * 4;
        if (hs > end - p) return GZ_E_TRUNC;
        if ((r = gz_src_read_exact(f, p, h, hs))) return r;
        if (gz_crc32(0, h, hs - 4) != rd32(h + hs - 4)) return GZ_E_DATA;
        u8 fl = h[1];
        u32 i = 2;
        u64 csize = GZ_SIZE_UNKNOWN, usize = GZ_SIZE_UNKNOWN, id, ps;
        if (fl & 0x3C) return GZ_E_METHOD;
        if ((fl & 0x40) && read_varint(h, hs - 4, &i, &csize)) return GZ_E_DATA;
        if ((fl & 0x80) && read_varint(h, hs - 4, &i, &usize)) return GZ_E_DATA;
        if ((fl & 3) != 0) return GZ_E_METHOD;                       /* filter chains (BCJ, delta) */
        if (read_varint(h, hs - 4, &i, &id) || read_varint(h, hs - 4, &i, &ps)) return GZ_E_DATA;
        if (id != 0x21 || ps != 1 || i >= hs - 4) return GZ_E_METHOD;
        u8 prop = h[i];
        if (usize != GZ_SIZE_UNKNOWN && usize > k->cap - k->n) return GZ_E_DATA;
        p += hs;
        u32 start = k->n;
        gz_pipe pp = { { f, p, end, 0 }, buf_write, k };
        gz_stream_io io = { gz_range_read, gz_pipe_write, &pp };
        u64 used = 0;
        if ((r = gz_lzma2_decode(v->xz, prop, &io, usize, &used))) return r;
        if (csize != GZ_SIZE_UNKNOWN && csize != used) return GZ_E_DATA;
        p += used;
        p += (4 - (used & 3)) & 3;                                   /* block padding */
        u32 cn = csz[check];
        if (cn > end - p || p > end) return GZ_E_TRUNC;
        if (check == 1 || check == 4) {
            u8 cb[8];
            if ((r = gz_src_read_exact(f, p, cb, cn))) return r;
            int bad = check == 1 ? gz_crc32(0, k->dst + start, k->n - start) != rd32(cb)
                                 : gz_crc64(0, k->dst + start, k->n - start) != rd64(cb);
            if (bad) return GZ_E_CRC;
        }
        p += cn;
    }
    return GZ_E_DATA;
}

static int decode_chunk(dmg_vw *v, u32 idx, const u8 **out)
{
    u32 slot = 0;
    for (u32 i = 0; i < v->nslots; i++) {
        if (v->key[i] == idx + 1) { v->age[i] = ++v->tick; *out = v->buf[i]; return GZ_OK; }
        if (v->age[i] < v->age[slot]) slot = i;
    }
    const dmg_part *p = v->p;
    const dmg_chunk *c = &p->ch[idx];
    if (c->kind < K_ADC || c->kind > K_XZ) return GZ_E_METHOD;
    u32 unp = (u32)c->nsec << 9;
    if (!v->buf[slot] && !(v->buf[slot] = (u8 *)gz_alloc(p->max_unp))) return GZ_E_NOMEM;
    u8 *b = v->buf[slot];
    v->key[slot] = 0;
    gz_src *f = v->v.file;
    if (c->off > f->size || c->len > f->size - c->off) return GZ_E_TRUNC;
    buf_sink k = { b, unp, 0 };
    size_t got = 0;
    int r;
    if (c->kind == K_ADC || c->kind == K_LZFSE) {
        if (!v->pack && !(v->pack = (u8 *)gz_alloc(p->max_mem))) return GZ_E_NOMEM;
        if ((r = gz_src_read_exact(f, c->off, v->pack, (u32)c->len))) return r;
    }
    switch (c->kind) {
    case K_ZLIB:
        r = gz_vd_inflate(&v->v, f, c->off, c->len, 1, b, unp, &k.n);
        break;
    case K_BZIP2: {
        if (!v->bz && !(v->bz = gz_bzip2_dec_new())) return GZ_E_NOMEM;
        gz_pipe pp = { { f, c->off, c->off + c->len, 0 }, buf_write, &k };
        gz_stream_io io = { gz_range_read, gz_pipe_write, &pp };
        r = gz_bzip2_decode(v->bz, &io, unp, 0, 0);
        break;
    }
    case K_ADC:
        r = gz_adc_decode(v->pack, (size_t)c->len, b, unp, &got, 0);
        k.n = (u32)got;
        break;
    case K_LZFSE:
        if (!v->lz && !(v->lz = gz_lzfse_dec_new())) return GZ_E_NOMEM;
        r = gz_lzfse_decode_ex(v->lz, v->pack, (size_t)c->len, b, unp, &got, 0);
        k.n = (u32)got;
        break;
    case K_XZ:
        r = xz_chunk(v, f, c->off, c->len, &k);
        break;
    default:
        return GZ_E_METHOD;
    }
    if (!r && k.n != unp) r = GZ_E_DATA;
    if (r) return r;
    v->key[slot] = idx + 1;
    v->age[slot] = ++v->tick;
    *out = b;
    return GZ_OK;
}

static int dmg_map(gz_vd_view *gv, u64 off, gz_vd_ext *x)
{
    dmg_vw *v = (dmg_vw *)gv;
    const dmg_part *p = v->p;
    u64 sec = off >> 9;
    u32 lo = 0, hi = p->nch;                          /* first chunk starting after sec */
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        if (p->ch[mid].sec <= sec) lo = mid + 1; else hi = mid;
    }
    u64 next = lo < p->nch ? p->ch[lo].sec << 9 : gv->s.size;
    x->kind = GZ_VD_ZERO;
    x->len = next - off;                              /* gap: zeros up to the next chunk */
    if (!lo) return GZ_OK;
    const dmg_chunk *c = &p->ch[lo - 1];
    u64 cs = c->sec << 9, ce = (c->sec + c->nsec) << 9;
    if (off >= ce) return GZ_OK;
    u64 in = off - cs;
    x->len = ce - off;
    switch (c->kind) {
    case K_ZERO:
    case K_IGNORE:
        return GZ_OK;
    case K_RAW:
        if (in < c->len) {
            x->kind = GZ_VD_RAW;
            x->pos = c->off + in;
            if (c->len - in < x->len) x->len = c->len - in;
        }
        return GZ_OK;
    }
    const u8 *b;
    int r = decode_chunk(v, lo - 1, &b);
    if (r) return r;
    x->kind = GZ_VD_MEM;
    x->mem = b + in;
    return GZ_OK;
}

static void dmg_fini(gz_vd_view *gv)
{
    dmg_vw *v = (dmg_vw *)gv;
    for (u32 i = 0; i < SLOTS; i++) gz_free(v->buf[i]);
    gz_free(v->pack);
    if (v->bz) gz_bzip2_dec_free(v->bz);
    if (v->lz) gz_lzfse_dec_free(v->lz);
    if (v->xz) gz_lzma_dec_free(v->xz);
}

static gz_src *dmg_view(gz_archive *a, gz_src *s, u32 idx)
{
    const dmg_img *im = (const dmg_img *)a->priv;
    const gz_entry *e = &a->e[idx];
    if (!im || e->off >= im->np) return 0;
    const dmg_part *p = &im->p[e->off];
    dmg_vw *v = (dmg_vw *)gz_vd_view_new(sizeof(dmg_vw), s, im, p->nsec << 9, dmg_map);
    if (!v) return 0;
    v->v.fini = dmg_fini;
    v->p = p;
    v->nslots = p->max_unp <= CACHE_BUDGET / SLOTS ? SLOTS : p->max_unp <= CACHE_BUDGET / 2 ? 2 : 1;
    return &v->v.s;
}

/* CRC of buf (partition bytes [off, off+n)) without the bytes of "ignore" runs;
 * *ci is a chunk cursor that only moves forward. */
static u32 crc_part(const dmg_part *p, u32 *ci, u32 crc, const u8 *buf, u64 off, u32 n)
{
    u64 pos = off, end = off + n;
    while (pos < end) {
        while (*ci < p->nch && (p->ch[*ci].sec + p->ch[*ci].nsec) << 9 <= pos) (*ci)++;
        u64 seg = end;
        if (*ci < p->nch) {
            const dmg_chunk *c = &p->ch[*ci];
            u64 cs = c->sec << 9, ce = (c->sec + c->nsec) << 9;
            if (pos >= cs) {
                seg = ce < end ? ce : end;
                if (c->kind == K_IGNORE) { pos = seg; continue; }
            } else if (cs < end) {
                seg = cs;                                 /* gap before the chunk */
            }
        }
        crc = gz_crc32(crc, buf + (pos - off), (size_t)(seg - pos));
        pos = seg;
    }
    return crc;
}

static int dmg_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    const dmg_img *im = (const dmg_img *)a->priv;
    gz_entry *e = &a->e[idx];
    int r = out->open(out, idx);
    if (r) return r;
    gz_src *v = dmg_view(a, s, idx);
    u8 *buf = gz_ctx_buffer(c, 256u << 10);
    int st = v && buf ? GZ_OK : GZ_E_NOMEM;
    const dmg_part *p = &im->p[e->off];
    u32 crc = 0, ci = 0;
    for (u64 off = 0; !st && off < e->usize;) {
        if (gz_cancelled(c)) { st = GZ_E_CANCEL; break; }
        u32 n = e->usize - off < (256u << 10) ? (u32)(e->usize - off) : (256u << 10);
        if ((st = gz_src_read_exact(v, off, buf, n))) break;
        if (e->has_crc) crc = crc_part(p, &ci, crc, buf, off, n);
        st = out->write(out, buf, n);
        off += n;
    }
    if (!st && e->has_crc && crc != e->crc) st = GZ_E_CRC;
    gz_src_free(v);
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static void dmg_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    char t[96];
    u32 k = 0;
    /* compressed kinds first, then the stored ones */
    static const u8 order[K_COUNT] = { K_ADC, K_ZLIB, K_BZIP2, K_LZFSE, K_XZ, K_UNKNOWN, K_RAW, K_ZERO, K_IGNORE };
    for (u32 i = 0; i < K_COUNT; i++) {
        if (!(e->aux32 & (1u << order[i]))) continue;
        const char *s = k_kind_name[order[i]];
        if (k) t[k++] = ' ';
        while (*s && k + 1 < sizeof t) t[k++] = *s++;
    }
    t[k] = 0;
    gz_vd_method_str(buf, cap, t);
}

/* The trailer outranks the magic of the first chunk's stream (a bzip2 or XZ chunk at
 * offset 0 of a UDBZ / ULMO image looks like a .bz2 / .xz file). */
static int dmg_probe(gz_src *s, const u8 *h, u32 n)
{
    if (n >= 8 && !__builtin_memcmp(h, "encrcdsa", 8)) return 90;
    if (s->size < KOLY_SIZE) return 0;
    u8 k[16];
    if (!gz_src_read_exact(s, s->size - KOLY_SIZE, k, 16) && is_koly(k)) return 98;
    if (n >= 16 && is_koly(h)) return 96;
    if (!gz_src_read_exact(s, s->size - 8, k, 8) && !__builtin_memcmp(k, "cdsaencr", 8)) return 70;
    return 0;
}

GZ_FORMAT(gz_fmt_dmg)
const gz_format gz_fmt_dmg = {
    "DMG", "dmg img smi", GZ_FMT_CONTAINER,
    dmg_probe, dmg_open, dmg_close, dmg_extract, 0, 0, dmg_method, dmg_view, 0
};
