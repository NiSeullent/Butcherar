/*
 * 고깃ZIP - ISO 9660 image writer
 *
 * Level 3 (files of 4 GiB and more become multi-extent files), Joliet (UCS-2,
 * names up to 103 units like genisoimage -joliet-long), Rock Ridge (SUSP SP/CE/ER,
 * RRIP_1991A PX/TF/NM/SL), L and M path tables for both trees. The whole layout
 * is computed from the announced item sizes before the first byte is written,
 * so output is append-only and the same input always gives the same image.
 *
 * Three name spaces, each made collision-free on its own (clashes get "~N"):
 *   primary   d-characters, up to 30 + ".;1" for files / 31 for directories
 *   Joliet    up to 103 UTF-16 units, distinct without regard to case and trailing
 *             dots/spaces (Windows and Linux look Joliet names up that way); no
 *             symlinks (Windows cannot use them)
 *   RR        the POSIX name in UTF-8, at most 253 bytes (Linux drops longer ones),
 *             extension kept when shortened; symlink targets up to 1023 bytes
 *
 * Layout:
 *
 *   0-15   system area (zeros)
 *   16     primary volume descriptor
 *   17     Joliet supplementary volume descriptor
 *   18     volume descriptor set terminator
 *   19..   path tables (primary L, M, Joliet L, M)
 *          primary directories (path table order), each one directly followed
 *          by the Rock Ridge continuation areas of its records (libarchive reads
 *          a CE area only when it immediately follows the directory just read)
 *          Joliet directories (path table order)
 *          one zero block (extent of empty files and symlinks)
 *          file data in item order, each file contiguous and sector aligned
 *
 * A file that cannot be opened or ends early keeps its place: the rest of its
 * extent is zero-filled and the failure goes to o->on_error.
 */
#include "gz_write.h"

#define SECT    2048u
#define NONE    0xFFFFFFFFu
#define JMAX    103u            /* Joliet name units (genisoimage -joliet-long)   */
#define JEXT    16u             /* extension units kept when a name is shortened   */
#define RRMAX   253u            /* Rock Ridge name bytes (Linux isofs drops longer ones) */
#define REXT    32u
#define LINKMAX 1023u           /* symlink target bytes (libisofs rejects longer)  */
#define EXTMAX  0xFFFFF800u     /* bytes per extent of a multi-extent file         */
#define SBCAP   4096u           /* SUSP scratch for one record (and name conversion) */
#define SMAX    48u             /* SUSP entries per record                         */
#define WBCAP   (64u << 10)     /* metadata staging buffer                         */
#define RDCAP   (1u << 20)      /* file data read size                             */
#define T1900   (-2208988800LL) /* range of the 7-byte directory record date       */
#define T2155   5869583999LL

typedef struct {
    const gzch *name;           /* path component (points into the item name)      */
    gzch *jname;                /* Joliet name, host order                         */
    u8 *rname;                  /* Rock Ridge name, UTF-8                          */
    u8 *link;                   /* symlink target, UTF-8                           */
    u64 size;
    i64 mtime;                  /* Unix seconds                                    */
    u32 nlen, parent, item, mode;
    u32 kbeg, nk;               /* children in kids[] (primary order)              */
    u32 jbeg, nj;               /* children in jkids[] (Joliet order, no symlinks) */
    u32 nsub;                   /* subdirectories (PX link count)                  */
    u32 lba, jlba, dsize, jdsize, pnum, jnum, uniq;
    u32 ce_sects;               /* continuation sectors after the primary directory */
    u16 jlen, rlen, linklen;
    u8 is_dir, is_link, hidden, has_time;
    u8 plen, pdot;              /* primary identifier length, '.' index (0xFF none) */
    u8 pname[32];
} inode;

typedef struct {
    const gz_wopts *o;
    const gz_witem *it;
    u32 nit;
    gz_sink *out;
    gz_ctx *c;
    inode *nd;
    u32 nn, ncap;
    u32 *kids, *jkids, *dirs, *jdirs, *tmp;
    u32 ndirs;
    u32 *ht;                    /* directory lookup while building, name sets later */
    u32 hcap, hn;
    gz_arena ar;
    i64 vtime;
    int has_vtime, need_zero;
    u32 pt_size, jpt_size, pt_lba[4];
    u32 ce_lba, ce_cur, ce_wpos;   /* CE area of the directory being processed       */
    u32 zero_lba, data_lba, total;
    u64 wpos;                   /* bytes written so far (layout self-check)        */
    u64 in_total, in_done;
    u8 *rbuf, *own_rbuf;
    u32 sn, slen, wn;
    u16 soff[SMAX + 1];
    u8 vol_p[32];
    gzch vol_j[16];
    u32 vol_jlen;
    u8 rec[256];
    u8 vd[SECT];
    u8 sb[SBCAP];
    u8 wb[WBCAP];
} iso_w;

/* ---------------- small helpers ---------------- */

static void both16(u8 *p, u32 v) { wr16(p, (u16)v); wr16be(p + 2, (u16)v); }
static void both32(u8 *p, u32 v) { wr32(p, v); wr32be(p + 4, v); }
static int is_hi(gzch c) { return c >= 0xD800 && c < 0xDC00; }
static int is_lo(gzch c) { return c >= 0xDC00 && c < 0xE000; }

/* unit i of s[0..n) with lone surrogate halves replaced by U+FFFD (UCS-2 readers) */
static gzch unit(const gzch *s, u32 n, u32 i)
{
    gzch c = s[i];
    if (is_hi(c)) return i + 1 < n && is_lo(s[i + 1]) ? c : 0xFFFD;
    if (is_lo(c)) return i && is_hi(s[i - 1]) ? c : 0xFFFD;
    return c;
}

static int cancelled(const iso_w *w)
{
    return (w->o->cancel && *w->o->cancel) || gz_cancelled(w->c);
}

static void civil(i64 t, u32 v[6])   /* Unix seconds -> y mo d h mi s */
{
    if (t < T1900) t = T1900;
    if (t > T2155) t = T2155;
    i64 days = t / 86400, rem = t % 86400;
    if (rem < 0) { rem += 86400; days--; }
    i64 z = days + 719468;
    i64 era = (z >= 0 ? z : z - 146096) / 146097;
    u32 doe = (u32)(z - era * 146097);
    u32 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    u32 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    u32 mp = (5 * doy + 2) / 153;
    v[2] = doy - (153 * mp + 2) / 5 + 1;
    v[1] = mp < 10 ? mp + 3 : mp - 9;
    v[0] = (u32)((i64)yoe + era * 400 + (v[1] <= 2));
    v[3] = (u32)rem / 3600;
    v[4] = (u32)rem / 60 % 60;
    v[5] = (u32)rem % 60;
}

static void date7(u8 *p, const inode *n)          /* directory record / TF date (UTC) */
{
    if (!n->has_time) { __builtin_memset(p, 0, 7); return; }
    u32 v[6];
    civil(n->mtime, v);
    p[0] = (u8)(v[0] - 1900);
    for (int i = 1; i < 6; i++) p[i] = (u8)v[i];
    p[6] = 0;
}

static void date17(u8 *p, const iso_w *w)         /* volume descriptor date */
{
    u32 v[6] = { 0, 0, 0, 0, 0, 0 };
    if (w->has_vtime) civil(w->vtime, v);
    u32 digits[7] = { v[0] / 100, v[0] % 100, v[1], v[2], v[3], v[4], v[5] };
    for (int i = 0; i < 7; i++) {
        p[2 * i] = (u8)('0' + digits[i] / 10 % 10);
        p[2 * i + 1] = (u8)('0' + digits[i] % 10);
    }
    p[14] = p[15] = '0';
    p[16] = 0;
}

static u32 put_dec(u8 *p, u32 v)                  /* decimal digits, returns count */
{
    u8 t[10];
    u32 n = 0;
    do { t[n++] = (u8)('0' + v % 10); v /= 10; } while (v);
    for (u32 i = 0; i < n; i++) p[i] = t[n - 1 - i];
    return n;
}

static int alloc_arr(u32 **p, u32 n)
{
    *p = (u32 *)gz_alloc((size_t)n * sizeof(u32) + 4);
    return *p ? GZ_OK : GZ_E_NOMEM;
}

/* ---------------- output ---------------- */

static int flush(iso_w *w)
{
    int r = w->wn ? gz_sink_write(w->out, w->wb, w->wn) : GZ_OK;
    w->wn = 0;
    return r;
}

static int emit(iso_w *w, const void *p, u64 n)   /* p == NULL: zeros */
{
    const u8 *s = (const u8 *)p;
    w->wpos += n;
    while (n) {
        if (w->wn == WBCAP) {
            int r = flush(w);
            if (r) return r;
        }
        u32 k = WBCAP - w->wn;
        if (n < k) k = (u32)n;
        if (s) { __builtin_memcpy(w->wb + w->wn, s, k); s += k; }
        else __builtin_memset(w->wb + w->wn, 0, k);
        w->wn += k;
        n -= k;
    }
    return GZ_OK;
}

static int pad_sector(iso_w *w)
{
    u32 r = (u32)(w->wpos & (SECT - 1));
    return r ? emit(w, 0, SECT - r) : GZ_OK;
}

static int at_lba(const iso_w *w, u32 lba)        /* layout self-check */
{
    return w->wpos == (u64)lba * SECT ? GZ_OK : GZ_E_FORMAT;
}

/* ---------------- tree ---------------- */

static int new_node(iso_w *w, u32 parent, const gzch *s, u32 n, u32 *out)
{
    if (w->nn == w->ncap) {
        u32 lim = sizeof(size_t) > 4 ? (1u << 27) : (1u << 23);
        if (w->ncap >= lim) return GZ_E_LIMIT;
        u32 nc = w->ncap ? w->ncap * 2 : 256;
        inode *p = (inode *)gz_realloc(w->nd, (size_t)nc * sizeof(inode));
        if (!p) return GZ_E_NOMEM;
        w->nd = p;
        w->ncap = nc;
    }
    inode *d = &w->nd[w->nn];
    __builtin_memset(d, 0, sizeof *d);
    d->name = s;
    d->nlen = n;
    d->parent = parent;
    d->item = NONE;
    d->pdot = 0xFF;
    d->mtime = w->vtime;
    d->has_time = (u8)w->has_vtime;
    *out = w->nn++;
    return GZ_OK;
}

static u32 hash_units(u32 parent, const gzch *s, u32 n)
{
    u32 h = 2166136261u ^ (parent * 0x9E3779B1u);
    for (u32 i = 0; i < n; i++) h = (h ^ s[i]) * 16777619u;
    return h ^ (h >> 15);
}

static int dt_add(iso_w *w, u32 k)
{
    if ((w->hn + 1) * 2 > w->hcap) {               /* grow and rehash */
        u32 nc = w->hcap ? w->hcap * 2 : 1024;
        if (nc < w->hcap) return GZ_E_LIMIT;
        u32 *t = (u32 *)gz_alloc((size_t)nc * sizeof(u32));
        if (!t) return GZ_E_NOMEM;
        __builtin_memset(t, 0xFF, (size_t)nc * sizeof(u32));
        for (u32 i = 0; i < w->hcap; i++) {
            u32 v = w->ht[i];
            if (v == NONE) continue;
            u32 h = hash_units(w->nd[v].parent, w->nd[v].name, w->nd[v].nlen) & (nc - 1);
            while (t[h] != NONE) h = (h + 1) & (nc - 1);
            t[h] = v;
        }
        gz_free(w->ht);
        w->ht = t;
        w->hcap = nc;
    }
    const inode *n = &w->nd[k];
    u32 h = hash_units(n->parent, n->name, n->nlen) & (w->hcap - 1);
    while (w->ht[h] != NONE) h = (h + 1) & (w->hcap - 1);
    w->ht[h] = k;
    w->hn++;
    return GZ_OK;
}

/* directory child `s` of parent, created when missing */
static int get_dir(iso_w *w, u32 parent, const gzch *s, u32 n, u32 *out)
{
    if (w->hcap) {
        u32 h = hash_units(parent, s, n) & (w->hcap - 1);
        for (u32 v; (v = w->ht[h]) != NONE; h = (h + 1) & (w->hcap - 1)) {
            const inode *d = &w->nd[v];
            if (d->parent == parent && d->nlen == n && !__builtin_memcmp(d->name, s, n * sizeof(gzch))) {
                *out = v;
                return GZ_OK;
            }
        }
    }
    int r = new_node(w, parent, s, n, out);
    if (r) return r;
    w->nd[*out].is_dir = 1;
    w->nd[*out].mode = 040755;
    return dt_add(w, *out);
}

/* UTF-16 -> UTF-8 into w->sb with at most `cap` output bytes, never splitting a
 * character. Input is limited to keep the scratch buffer bounded. */
static u32 to_utf8(iso_w *w, u32 at, const gzch *s, u32 n, u32 cap)
{
    if (n > cap) {                                 /* every unit gives >= 1 byte */
        n = cap;
        if (is_hi(s[n - 1])) n--;                  /* do not split a surrogate pair */
    }
    u32 k = (u32)gz_utf16_to_utf8(s, n, w->sb + at);
    if (k > cap) {
        k = cap;
        while (k && (w->sb[at + k] & 0xC0) == 0x80) k--;
    }
    return k;
}

static u8 *ar_dup(iso_w *w, const void *p, u32 n)
{
    u8 *d = (u8 *)gz_arena_alloc(&w->ar, n ? n : 1);
    if (d && n) __builtin_memcpy(d, p, n);
    return d;
}

static int set_item(iso_w *w, u32 k, u32 i)
{
    const gz_witem *it = &w->it[i];
    inode *n = &w->nd[k];
    n->item = i;
    n->hidden = (it->attr & 2) != 0;
    if (it->mtime) { n->mtime = gz_filetime_to_unix(it->mtime); n->has_time = 1; }
    u32 perm = it->unix_mode & 07777;
    if (n->is_dir) {
        n->mode = 040000 | (perm ? perm : 0755);
        return GZ_OK;
    }
    if (it->is_link && it->link_target && it->link_target[0]) {
        u32 tl = (u32)GZ_MIN(gz_wcslen(it->link_target), (size_t)LINKMAX);
        u32 bl = to_utf8(w, 0, it->link_target, tl, LINKMAX);
        if (bl) {
            n->link = ar_dup(w, w->sb, bl);
            if (!n->link) return GZ_E_NOMEM;
            n->linklen = (u16)bl;
            n->is_link = 1;
            n->mode = 0120000 | (perm ? perm : 0777);
            return GZ_OK;
        }
    }
    /* regular file (other types, and links without a target, become plain files) */
    n->mode = 0100000 | (perm ? perm : ((it->attr & 1) ? 0444 : 0644));
    n->size = it->is_link ? 0 : it->size;
    return GZ_OK;
}

static int report(iso_w *w, u32 item, int err)
{
    if (err == GZ_E_CANCEL || !w->o->on_error) return err;
    return w->o->on_error(w->o->user, &w->it[item], err);
}

static int build_tree(iso_w *w)
{
    u32 root, k;
    int r = new_node(w, 0, 0, 0, &root);
    if (r) return r;
    w->nd[root].is_dir = 1;
    w->nd[root].mode = 040755;
    for (u32 i = 0; i < w->nit; i++) {
        const gz_witem *it = &w->it[i];
        const gzch *p = it->name, *last = 0;
        u32 cur = root, lastn = 0;
        if ((i & 4095) == 0 && cancelled(w)) return GZ_E_CANCEL;
        while (p) {
            const gzch *q = p;
            while (*q && *q != '/') q++;
            u32 n = (u32)(q - p);
            int skip = !n || (p[0] == '.' && (n == 1 || (n == 2 && p[1] == '.')));
            if (!skip) {
                if (last && (r = get_dir(w, cur, last, lastn, &cur))) return r;
                last = p;
                lastn = n;
            }
            p = *q ? q + 1 : 0;
        }
        if (!last) {                               /* empty path: the root itself */
            if (it->is_dir) {
                if (w->nd[root].item == NONE && (r = set_item(w, root, i))) return r;
            } else if ((r = report(w, i, GZ_E_FORMAT))) {
                return r;
            }
            continue;
        }
        if (it->is_dir) {
            if ((r = get_dir(w, cur, last, lastn, &k))) return r;
            if (w->nd[k].item != NONE) continue;   /* duplicate directory item */
        } else if ((r = new_node(w, cur, last, lastn, &k))) {
            return r;
        }
        if ((r = set_item(w, k, i))) return r;
    }
    return GZ_OK;
}

/* ---------------- names ---------------- */

static u8 dchar(gzch c)
{
    if (c >= 'a' && c <= 'z') return (u8)(c - 32);
    if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) return (u8)c;
    return '_';
}

/* Joliet unit: characters Joliet forbids become '_', lone surrogates U+FFFD */
static gzch junit(const gzch *s, u32 n, u32 i)
{
    gzch c = unit(s, n, i);
    return (c < 0x20 || c == '*' || c == '/' || c == ':' || c == ';' || c == '?' || c == '\\') ? '_' : c;
}

/* '.' that starts the extension of a file name: not the first unit, <= maxext units after it */
static u32 ext_dot(const gzch *s, u32 n, u32 maxext)
{
    for (u32 i = n; i-- > 1 && n - i - 1 <= maxext;)
        if (s[i] == '.') return i;
    return NONE;
}

static void prim_name(inode *n)
{
    const gzch *s = n->name;
    u32 dot = n->is_dir ? NONE : ext_dot(s, n->nlen, n->nlen);
    u32 bl = dot == NONE ? n->nlen : dot;
    u32 el = dot == NONE ? 0 : n->nlen - dot - 1;
    if (el > 15) el = 15;
    u32 maxb = n->is_dir ? 31 : 30 - el;
    if (bl > maxb) bl = maxb;
    u32 o = 0;
    for (u32 i = 0; i < bl; i++) n->pname[o++] = dchar(s[i]);
    if (!n->is_dir) {
        n->pdot = (u8)o;
        n->pname[o++] = '.';
        for (u32 i = 0; i < el; i++) n->pname[o++] = dchar(s[dot + 1 + i]);
    }
    n->plen = (u8)o;
}

static int jol_name(iso_w *w, inode *n)
{
    const gzch *s = n->name;
    u32 len = n->nlen, bl = len, dot = NONE;
    if (len > JMAX) {
        dot = n->is_dir ? NONE : ext_dot(s, len, JEXT);
        u32 el = dot == NONE ? 0 : len - dot;
        bl = JMAX - el;
        if (is_hi(junit(s, len, bl - 1))) bl--;   /* do not split a pair */
    }
    u32 tot = bl + (dot == NONE ? 0 : len - dot);
    gzch *d = (gzch *)gz_arena_alloc(&w->ar, tot * sizeof(gzch));
    if (!d) return GZ_E_NOMEM;
    for (u32 i = 0; i < bl; i++) d[i] = junit(s, len, i);
    for (u32 i = bl; i < tot; i++) d[i] = junit(s, len, dot + i - bl);
    n->jname = d;
    n->jlen = (u16)tot;
    return GZ_OK;
}

static int rr_name(iso_w *w, inode *n)
{
    const gzch *s = n->name;
    u32 dot = n->is_dir ? NONE : ext_dot(s, n->nlen, REXT);
    u32 bu = dot == NONE ? n->nlen : dot;
    u32 el = dot == NONE ? 0 : to_utf8(w, 1024, s + dot, n->nlen - dot, 4 * REXT + 4);
    u32 bl = to_utf8(w, 0, s, bu, RRMAX + 1);
    if (bl + el > RRMAX) {                         /* shorten the base, keep the extension */
        bl = RRMAX - el;
        while (bl && (w->sb[bl] & 0xC0) == 0x80) bl--;
    }
    __builtin_memmove(w->sb + bl, w->sb + 1024, el);
    n->rname = ar_dup(w, w->sb, bl + el);
    if (!n->rname) return GZ_E_NOMEM;
    n->rlen = (u16)(bl + el);
    return GZ_OK;
}

/* name sets for uniquification: ns 0 primary, 1 Joliet, 2 Rock Ridge */
static const u8 *ns_key(const inode *n, int ns, u32 *len)
{
    if (ns == 0) {
        *len = n->plen - (n->pdot != 0xFF && n->pdot + 1 == n->plen);  /* "ABC." == "ABC" */
        return n->pname;
    }
    if (ns == 1) { *len = n->jlen * 2u; return (const u8 *)n->jname; }
    *len = n->rlen;
    return n->rname;
}

/* Joliet readers (Windows, Linux) look names up case-insensitively and ignore
 * trailing dots (Windows also spaces), so Joliet names are compared that way.
 * Simple upper-casing of the Latin, Greek, Cyrillic and Armenian letters. */
static u32 jfold(u32 c)
{
    if (c < 0x80) return c >= 'a' && c <= 'z' ? c - 32 : c;
    if (c < 0x100) return c == 0xFF ? 0x178 : c == 0xB5 ? 0x39C : (c >= 0xE0 && c != 0xF7) ? c - 32 : c;
    if (c < 0x180) {                               /* Latin Extended-A: case pairs */
        if (c == 0x130 || c == 0x131 || c == 0x138 || c == 0x149 || c == 0x178) return c;
        if (c == 0x17F) return 'S';
        u32 odd_up = (c >= 0x139 && c <= 0x148) || c >= 0x179;
        return (c & 1) != odd_up ? c - 1 : c;
    }
    if (c >= 0x386 && c < 0x400) {                 /* Greek */
        if (c >= 0x3B1 && c <= 0x3CB) return c == 0x3C2 ? 0x3A3 : c - 32;
        if (c == 0x3AC) return 0x386;
        if (c >= 0x3AD && c <= 0x3AF) return c - 37;
        if (c == 0x3CC) return 0x38C;
        if (c == 0x3CD || c == 0x3CE) return c - 63;
        return c;
    }
    if (c >= 0x400 && c < 0x530) {                 /* Cyrillic */
        if (c >= 0x430 && c <= 0x44F) return c - 32;
        if (c >= 0x450 && c <= 0x45F) return c - 80;
        if ((c >= 0x460 && c <= 0x481) || (c >= 0x48A && c <= 0x4BF) || c >= 0x4D0) return c & ~1u;
        if (c >= 0x4C1 && c <= 0x4CE) return (c & 1) ? c : c - 1;
        return c == 0x4CF ? 0x4C0 : c;
    }
    if (c >= 0x561 && c <= 0x586) return c - 48;   /* Armenian */
    if (c >= 0x1E00 && c <= 0x1EFF && (c < 0x1E96 || c > 0x1E9F)) return c & ~1u;   /* Latin Ext. Additional */
    if (c >= 0xFF41 && c <= 0xFF5A) return c - 32; /* full-width Latin */
    return c;
}

static u32 jtrim(const u8 *p, u32 kl)              /* units without trailing dots / spaces */
{
    u32 n = kl / 2;
    while (n && (rd16(p + 2 * n - 2) == '.' || rd16(p + 2 * n - 2) == ' ')) n--;
    return n;
}

static u32 key_hash(int ns, u32 parent, const u8 *p, u32 n)
{
    u32 h = 2166136261u ^ (parent * 0x9E3779B1u);
    if (ns == 1)
        for (u32 i = 0, m = jtrim(p, n); i < m; i++) h = (h ^ jfold(rd16(p + 2 * i))) * 16777619u;
    else
        for (u32 i = 0; i < n; i++) h = (h ^ p[i]) * 16777619u;
    return h ^ (h >> 15);
}

static int key_eq(int ns, const u8 *a, u32 al, const u8 *b, u32 bl)
{
    if (ns != 1) return al == bl && !__builtin_memcmp(a, b, al);
    u32 n = jtrim(a, al);
    if (n != jtrim(b, bl)) return 0;
    for (u32 i = 0; i < n; i++)
        if (jfold(rd16(a + 2 * i)) != jfold(rd16(b + 2 * i))) return 0;
    return 1;
}

/* free slot for the key, or NULL when taken (*owner = the node holding it) */
static u32 *set_slot(iso_w *w, int ns, u32 parent, const u8 *k, u32 kl, u32 *owner)
{
    u32 h = key_hash(ns, parent, k, kl) & (w->hcap - 1);
    for (u32 v; (v = w->ht[h]) != NONE; h = (h + 1) & (w->hcap - 1)) {
        u32 l;
        const u8 *q = ns_key(&w->nd[v], ns, &l);
        if (w->nd[v].parent == parent && key_eq(ns, q, l, k, kl)) { *owner = v; return 0; }
    }
    return &w->ht[h];
}

/* make a candidate name with counter v; returns its key into key/klen */
static void candidate(iso_w *w, const inode *n, int ns, u32 v, u8 *buf, u32 *blen)
{
    u8 dg[10];
    u32 nd = put_dec(dg, v), o = 0;
    if (ns == 0) {
        u32 bl = n->pdot == 0xFF ? n->plen : n->pdot;
        u32 el = n->pdot == 0xFF ? 0 : n->plen - n->pdot;          /* incl. '.' */
        u32 maxb = (n->is_dir ? 31 : 31 - el) - nd;
        if (bl > maxb) bl = maxb;
        __builtin_memcpy(buf, n->pname, bl);
        __builtin_memcpy(buf + bl, dg, nd);
        __builtin_memcpy(buf + bl + nd, n->pname + n->plen - el, el);
        *blen = bl + nd + el;
        return;
    }
    if (ns == 1) {
        const gzch *s = n->jname;
        u32 dot = n->is_dir ? NONE : ext_dot(s, n->jlen, JEXT);
        u32 bl = dot == NONE ? n->jlen : dot, el = dot == NONE ? 0 : n->jlen - dot;
        u32 maxb = JMAX - el - 1 - nd;
        if (bl > maxb) { bl = maxb; if (is_hi(s[bl - 1])) bl--; }
        gzch *d = (gzch *)buf;
        for (u32 i = 0; i < bl; i++) d[o++] = s[i];
        d[o++] = '~';
        for (u32 i = 0; i < nd; i++) d[o++] = dg[i];
        for (u32 i = 0; i < el; i++) d[o++] = s[dot + i];
        *blen = o * 2;
        return;
    }
    const u8 *s = n->rname;
    u32 dot = NONE;
    if (!n->is_dir)
        for (u32 i = n->rlen; i-- > 1 && n->rlen - i <= REXT;)
            if (s[i] == '.') { dot = i; break; }
    u32 bl = dot == NONE ? n->rlen : dot, el = dot == NONE ? 0 : n->rlen - dot;
    u32 maxb = RRMAX - el - 1 - nd;
    if (bl > maxb) { bl = maxb; while (bl && (s[bl] & 0xC0) == 0x80) bl--; }
    __builtin_memcpy(buf, s, bl);
    o = bl;
    buf[o++] = '~';
    __builtin_memcpy(buf + o, dg, nd);
    o += nd;
    __builtin_memcpy(buf + o, s + n->rlen - el, el);
    *blen = o + el;
}

static int assign(iso_w *w, inode *n, int ns, const u8 *buf, u32 bl)
{
    if (ns == 0) {
        __builtin_memcpy(n->pname, buf, bl);
        n->plen = (u8)bl;
        if (!n->is_dir) {                          /* key dropped a trailing '.' */
            u32 d = NONE;
            for (u32 i = 0; i < bl; i++) if (buf[i] == '.') d = i;
            if (d == NONE) { n->pname[bl] = '.'; d = bl; n->plen++; }
            n->pdot = (u8)d;
        }
        return GZ_OK;
    }
    u8 *d = ar_dup(w, buf, bl);
    if (!d) return GZ_E_NOMEM;
    if (ns == 1) { n->jname = (gzch *)d; n->jlen = (u16)(bl / 2); }
    else { n->rname = d; n->rlen = (u16)bl; }
    return GZ_OK;
}

/* Rename clashing names in one name space. The first node keeps a name; the others
 * get numbered variants, counted per clashing name (its holder's `uniq`). Each try
 * with a new number is a different string, so a free one is found within
 * (directory size + 1) tries. */
static int uniquify(iso_w *w, int ns)
{
    __builtin_memset(w->ht, 0xFF, (size_t)w->hcap * sizeof(u32));
    u32 ndup = 0, own;
    for (u32 i = 0; i < w->nn; i++) w->nd[i].uniq = 0;
    for (u32 i = 1; i < w->nn; i++) {
        if (ns == 1 && w->nd[i].is_link) continue;
        u32 kl;
        const u8 *k = ns_key(&w->nd[i], ns, &kl);
        u32 *s = set_slot(w, ns, w->nd[i].parent, k, kl, &own);
        if (s) *s = i;
        else { w->tmp[ndup++] = i; w->nd[i].uniq = own; }   /* dups never hold a name yet */
    }
    gzch bufw[JMAX + RRMAX / 2 + 8];               /* u16 aligned for Joliet names */
    u8 *buf = (u8 *)bufw;
    for (u32 j = 0; j < ndup; j++) {
        inode *n = &w->nd[w->tmp[j]];
        inode *holder = &w->nd[n->uniq];
        for (;;) {
            u32 v = ++holder->uniq, bl;
            if (!v) return GZ_E_LIMIT;
            candidate(w, n, ns, v, buf, &bl);
            u32 kl = bl;
            if (ns == 0 && !n->is_dir && buf[bl - 1] == '.') kl--;
            u32 *s = set_slot(w, ns, n->parent, buf, kl, &own);
            if (!s) continue;
            int r = assign(w, n, ns, buf, bl);
            if (r) return r;
            *s = w->tmp[j];
            break;
        }
    }
    return GZ_OK;
}

/* ---------------- sorting ---------------- */

/* ISO 9660 9.3: name parts compared padded with spaces, then extension parts */
static int cmp_pad8(const u8 *a, u32 an, const u8 *b, u32 bn)
{
    for (u32 i = 0, n = GZ_MAX(an, bn); i < n; i++) {
        u32 x = i < an ? a[i] : ' ', y = i < bn ? b[i] : ' ';
        if (x != y) return x < y ? -1 : 1;
    }
    return 0;
}

static int cmp_pad16(const gzch *a, u32 an, const gzch *b, u32 bn)
{
    for (u32 i = 0, n = GZ_MAX(an, bn); i < n; i++) {
        u32 x = i < an ? a[i] : ' ', y = i < bn ? b[i] : ' ';
        if (x != y) return x < y ? -1 : 1;
    }
    return 0;
}

static int cmp_prim(const iso_w *w, u32 x, u32 y)
{
    const inode *a = &w->nd[x], *b = &w->nd[y];
    u32 ab = a->pdot == 0xFF ? a->plen : a->pdot, bb = b->pdot == 0xFF ? b->plen : b->pdot;
    int r = cmp_pad8(a->pname, ab, b->pname, bb);
    if (!r) {
        u32 ae = a->plen - ab - (ab < a->plen), be = b->plen - bb - (bb < b->plen);
        r = cmp_pad8(a->pname + a->plen - ae, ae, b->pname + b->plen - be, be);
    }
    return r ? r : (x < y ? -1 : x > y);
}

static int cmp_jol(const iso_w *w, u32 x, u32 y)
{
    const inode *a = &w->nd[x], *b = &w->nd[y];
    u32 ad = a->is_dir ? NONE : ext_dot(a->jname, a->jlen, a->jlen);
    u32 bd = b->is_dir ? NONE : ext_dot(b->jname, b->jlen, b->jlen);
    u32 ab = ad == NONE ? a->jlen : ad, bb = bd == NONE ? b->jlen : bd;
    int r = cmp_pad16(a->jname, ab, b->jname, bb);
    if (!r) {
        u32 ae = ad == NONE ? 0 : a->jlen - ad - 1, be = bd == NONE ? 0 : b->jlen - bd - 1;
        r = cmp_pad16(a->jname + a->jlen - ae, ae, b->jname + b->jlen - be, be);
    }
    return r ? r : (x < y ? -1 : x > y);
}

typedef int (*cmp_fn)(const iso_w *, u32, u32);

static void msort(const iso_w *w, u32 *a, u32 *t, u32 n, cmp_fn cmp)
{
    for (u32 i = 0; i < n; i += 16) {              /* insertion-sorted runs */
        u32 e = GZ_MIN(i + 16, n);
        for (u32 j = i + 1; j < e; j++) {
            u32 v = a[j], k = j;
            while (k > i && cmp(w, a[k - 1], v) > 0) { a[k] = a[k - 1]; k--; }
            a[k] = v;
        }
    }
    u32 *s = a, *d = t;
    for (u32 wd = 16; wd < n; wd *= 2) {
        for (u32 lo = 0; lo < n; lo += 2 * wd) {
            u32 mid = GZ_MIN(lo + wd, n), hi = GZ_MIN(lo + 2 * wd, n), i = lo, j = mid, o = lo;
            while (i < mid && j < hi) d[o++] = cmp(w, s[j], s[i]) < 0 ? s[j++] : s[i++];
            while (i < mid) d[o++] = s[i++];
            while (j < hi) d[o++] = s[j++];
        }
        u32 *x = s; s = d; d = x;
    }
    if (s != a) __builtin_memcpy(a, s, (size_t)n * sizeof(u32));
}

static int build_dirs(iso_w *w)
{
    u32 nn = w->nn;
    int r;
    if ((r = alloc_arr(&w->kids, nn)) || (r = alloc_arr(&w->jkids, nn)) || (r = alloc_arr(&w->dirs, nn)) ||
        (r = alloc_arr(&w->jdirs, nn)) || (r = alloc_arr(&w->tmp, nn)))
        return r;
    for (u32 i = 1; i < nn; i++) {                 /* child counts */
        inode *p = &w->nd[w->nd[i].parent];
        p->nk++;
        if (!w->nd[i].is_link) p->nj++;
        if (w->nd[i].is_dir) p->nsub++;
    }
    u32 kb = 0, jb = 0;
    for (u32 i = 0; i < nn; i++) {
        w->nd[i].kbeg = kb; kb += w->nd[i].nk; w->nd[i].nk = 0;
        w->nd[i].jbeg = jb; jb += w->nd[i].nj; w->nd[i].nj = 0;
    }
    for (u32 i = 1; i < nn; i++) {
        inode *p = &w->nd[w->nd[i].parent];
        w->kids[p->kbeg + p->nk++] = i;
        if (!w->nd[i].is_link) w->jkids[p->jbeg + p->nj++] = i;
    }
    return GZ_OK;
}

static int names(iso_w *w)
{
    int r;
    for (u32 i = 1; i < w->nn; i++) {
        inode *n = &w->nd[i];
        prim_name(n);
        if ((r = jol_name(w, n)) || (r = rr_name(w, n))) return r;
    }
    gz_free(w->ht);                                /* directory lookup -> name sets */
    u32 cap = 16;
    while (cap < w->nn * 2) cap *= 2;
    w->hcap = cap;
    w->ht = (u32 *)gz_alloc((size_t)cap * sizeof(u32));
    if (!w->ht) return GZ_E_NOMEM;
    for (int ns = 0; ns < 3; ns++)
        if ((r = uniquify(w, ns))) return r;
    for (u32 i = 0; i < w->nn; i++) {
        inode *n = &w->nd[i];
        if (!n->is_dir) continue;
        msort(w, w->kids + n->kbeg, w->tmp, n->nk, cmp_prim);
        msort(w, w->jkids + n->jbeg, w->tmp, n->nj, cmp_jol);
    }
    /* breadth-first directory order = path table order */
    for (int t = 0; t < 2; t++) {
        u32 *q = t ? w->jdirs : w->dirs, head = 0, cnt = 1;
        q[0] = 0;
        if (t) w->nd[0].jnum = 1; else w->nd[0].pnum = 1;
        while (head < cnt) {
            const inode *d = &w->nd[q[head++]];
            const u32 *k = t ? w->jkids + d->jbeg : w->kids + d->kbeg;
            for (u32 i = 0, m = t ? d->nj : d->nk; i < m; i++) {
                inode *c = &w->nd[k[i]];
                if (!c->is_dir) continue;
                q[cnt++] = k[i];
                if (t) c->jnum = cnt; else c->pnum = cnt;
            }
        }
        w->ndirs = cnt;
    }
    return GZ_OK;
}

static void volume_label(iso_w *w)
{
    const gzch *l = w->o->label;
    u32 n = l ? (u32)gz_wcslen(l) : 0;
    if (!n && w->nd[0].nk == 1 && w->nd[w->kids[0]].is_dir) {   /* one top folder */
        l = w->nd[w->kids[0]].name;
        n = w->nd[w->kids[0]].nlen;
    }
    u32 alnum = 0, o = 0;
    for (u32 i = 0; i < n && o < 32; i++) {
        u8 c = l[i] == ' ' ? '_' : dchar(l[i]);
        alnum += c != '_';
        w->vol_p[o++] = c;
    }
    if (!alnum) {                                  /* nothing left of it in d-characters */
        static const char def[] = "GOGITZIP";
        for (o = 0; def[o]; o++) w->vol_p[o] = (u8)def[o];
    }
    while (o < 32) w->vol_p[o++] = ' ';
    u32 j = 0;
    if (l && n) {
        for (; j < n && j < 16; j++) w->vol_j[j] = l[j] < 0x20 ? '_' : unit(l, n, j);
        if (j == 16 && n > 16 && is_hi(w->vol_j[15])) j--;
    } else {
        for (; j < 8; j++) w->vol_j[j] = w->vol_p[j];
    }
    w->vol_jlen = j;
}

/* ---------------- Rock Ridge / SUSP ---------------- */

static u8 *sx(iso_w *w, const char *sig, u32 len)  /* start a SUSP entry in the scratch */
{
    if (w->sn >= SMAX || w->slen + len > SBCAP) return 0;
    u8 *p = w->sb + w->slen;
    p[0] = (u8)sig[0];
    p[1] = (u8)sig[1];
    p[2] = (u8)len;
    p[3] = 1;
    w->slen += len;
    w->soff[++w->sn] = (u16)w->slen;
    return p;
}

typedef struct { u8 *e; u8 last; } sl_state;     /* open SL entry, flags of its last record */

static void sl_raw(iso_w *w, sl_state *st, u8 flags, const u8 *s, u32 n)
{
    if (w->slen + 2 + n > SBCAP) return;
    u8 *p = w->sb + w->slen;
    p[0] = flags;
    p[1] = (u8)n;
    if (n) __builtin_memcpy(p + 2, s, n);
    w->slen += 2 + n;
    w->soff[w->sn] = (u16)w->slen;
    st->e[2] = (u8)(st->e[2] + 2 + n);
    st->last = flags;
}

/* Append one SL component record. An SL entry never ends right after a complete
 * component: Linux then implies a '/', libarchive does not. Entries end after a
 * continued record instead (an empty one when needed, so 2 bytes are kept free). */
static void sl_comp(iso_w *w, sl_state *st, u8 flags, const u8 *s, u32 n)
{
    if (st->e && st->e[2] + 2 + n + ((flags & 1) ? 0 : 2) > 255) {
        if (!(st->last & 1)) sl_raw(w, st, 1, 0, 0);
        st->e[4] |= 1;                             /* link continues in the next SL */
        st->e = 0;
    }
    if (!st->e) {
        if (!(st->e = sx(w, "SL", 5))) return;
        st->e[4] = 0;
    }
    sl_raw(w, st, flags, s, n);
}

/* Components of a target. Repeated '/' collapse; a trailing '/' is kept as an empty
 * last component ("dir/" is stored as "dir" + "", which Linux, BSD and libarchive
 * read back as "dir/"). */
static void sl_build(iso_w *w, const u8 *t, u32 n)
{
    sl_state st = { 0, 0 };
    u32 i = 0, comps = 0;
    if (n && t[0] == '/') sl_comp(w, &st, 8, 0, 0);
    while (i < n) {
        while (i < n && t[i] == '/') i++;
        u32 j = i;
        while (j < n && t[j] != '/') j++;
        if (j == i) break;
        if (j - i == 1 && t[i] == '.') sl_comp(w, &st, 2, 0, 0);
        else if (j - i == 2 && t[i] == '.' && t[i + 1] == '.') sl_comp(w, &st, 4, 0, 0);
        else
            for (u32 k = i; k < j;) {              /* long components continue */
                u32 m = GZ_MIN(j - k, 246u);       /* 5 + 2 + 246 leaves 2 bytes free */
                sl_comp(w, &st, k + m < j ? 1 : 0, t + k, m);
                k += m;
            }
        comps++;
        i = j;
    }
    if (comps && t[n - 1] == '/') sl_comp(w, &st, 0, 0, 0);
}

static const char er_id[] = "RRIP_1991A";
static const char er_des[] = "THE ROCK RIDGE INTERCHANGE PROTOCOL PROVIDES SUPPORT FOR POSIX FILE SYSTEM SEMANTICS";
static const char er_src[] = "PLEASE CONTACT DISC PUBLISHER FOR SPECIFICATION SOURCE.  SEE PUBLISHER IDENTIFIER "
                             "IN PRIMARY VOLUME DESCRIPTOR FOR CONTACT INFORMATION.";

/* SUSP entries of one primary record describing node n (kind 0 '.', 1 '..', 2 entry) */
static void susp_build(iso_w *w, const inode *n, int kind, int root_dot)
{
    u8 *p;
    w->sn = 0;
    w->slen = 0;
    w->soff[0] = 0;
    if (root_dot && (p = sx(w, "SP", 7))) { p[4] = 0xBE; p[5] = 0xEF; p[6] = 0; }
    if ((p = sx(w, "PX", 36))) {
        both32(p + 4, n->mode);
        both32(p + 12, n->is_dir ? 2 + n->nsub : 1);
        both32(p + 20, 0);
        both32(p + 28, 0);
    }
    if ((p = sx(w, "TF", 26))) {                   /* modify, access, attributes */
        p[4] = 0x0E;
        date7(p + 5, n);
        __builtin_memcpy(p + 12, p + 5, 7);
        __builtin_memcpy(p + 19, p + 5, 7);
    }
    if (kind == 2) {
        const u8 *s = n->rname;
        for (u32 left = n->rlen; left;) {
            u32 k = GZ_MIN(left, 250u);
            if (!(p = sx(w, "NM", 5 + k))) break;
            p[4] = left > k;                       /* CONTINUE */
            __builtin_memcpy(p + 5, s, k);
            s += k;
            left -= k;
        }
        if (n->is_link) sl_build(w, n->link, n->linklen);
    }
    if (root_dot && (p = sx(w, "ER", 8 + 10 + 84 + 135))) {
        p[4] = 10; p[5] = 84; p[6] = 135; p[7] = 1;
        __builtin_memcpy(p + 8, er_id, 10);
        __builtin_memcpy(p + 18, er_des, 84);
        __builtin_memcpy(p + 102, er_src, 135);
    }
}

static void put_ce(const iso_w *w, u8 *p, u32 pos, u32 len)
{
    p[0] = 'C'; p[1] = 'E'; p[2] = 28; p[3] = 1;
    both32(p + 4, w->ce_lba + pos / SECT);
    both32(p + 12, pos % SECT);
    both32(p + 20, len);
}

/* Split the scratch entries between the record (cap bytes) and continuation pieces.
 * mode 0: allocate pieces only; 1: also write the pieces (CE region pass);
 * 2: write the inline part to dst. Returns the inline length (even). */
static int susp_pack(iso_w *w, u32 cap, int mode, u8 *dst, u32 *inl)
{
    const u16 *so = w->soff;
    u32 sn = w->sn, i = 0, used;
    cap &= ~1u;
    if (w->slen <= cap) {
        if (mode == 2) __builtin_memcpy(dst, w->sb, w->slen);
        used = w->slen;
    } else {
        struct { u32 b, e, len, pos; } pc[16];
        u32 np = 0, first;
        while (i < sn && (u32)so[i + 1] + 28 <= cap) i++;
        first = i;
        while (i < sn && np < 16) {                /* pieces of <= 1 sector */
            u32 b = i, len;
            if (w->slen - so[i] <= SECT) { len = w->slen - so[i]; i = sn; }
            else {
                while ((u32)so[i + 1] - so[b] + 28 <= SECT) i++;
                len = so[i] - so[b] + 28;
            }
            if ((w->ce_cur % SECT) + len > SECT) w->ce_cur += SECT - w->ce_cur % SECT;
            pc[np].b = b; pc[np].e = i; pc[np].len = len; pc[np].pos = w->ce_cur;
            w->ce_cur += len;
            np++;
        }
        if (i < sn) return GZ_E_LIMIT;             /* cannot happen with the caps above */
        used = so[first] + 28;
        if (mode == 2) {
            __builtin_memcpy(dst, w->sb, so[first]);
            put_ce(w, dst + so[first], pc[0].pos, pc[0].len);
        } else if (mode == 1) {
            for (u32 k = 0; k < np; k++) {
                u8 ce[28];
                int r = emit(w, 0, pc[k].pos - w->ce_wpos);
                if (!r) r = emit(w, w->sb + so[pc[k].b], so[pc[k].e] - so[pc[k].b]);
                if (!r && k + 1 < np) { put_ce(w, ce, pc[k + 1].pos, pc[k + 1].len); r = emit(w, ce, 28); }
                if (r) return r;
                w->ce_wpos = pc[k].pos + pc[k].len;
            }
        }
    }
    if (used & 1) { if (mode == 2) dst[used] = 0; used++; }
    *inl = used;
    return GZ_OK;
}

/* ---------------- directories ---------------- */

static u32 n_ext(const inode *n)
{
    if (n->is_dir || n->size <= 0xFFFFFFFFu) return 1;
    return (u32)((n->size + EXTMAX - 1) / EXTMAX);
}

static u32 rec_head(const iso_w *w, u8 *r, const inode *n, u32 e, int jol, int kind, u32 idlen, u32 sua)
{
    u32 hl = 33 + idlen + !(idlen & 1), lba, len;
    u8 fl = 0;
    if (n->is_dir) {
        lba = jol ? n->jlba : n->lba;
        len = jol ? n->jdsize : n->dsize;
        fl = 2;
    } else if (!n->size || n->is_link) {
        lba = w->zero_lba;
        len = 0;
    } else {
        u32 ne = n_ext(n);
        lba = n->lba + e * (EXTMAX / SECT);
        len = ne == 1 ? (u32)n->size : (e + 1 < ne ? EXTMAX : (u32)(n->size - (u64)e * EXTMAX));
        if (e + 1 < ne) fl = 0x80;
    }
    if (jol && kind == 2 && n->hidden) fl |= 1;
    r[0] = (u8)(hl + sua);
    r[1] = 0;
    both32(r + 2, lba);
    both32(r + 10, len);
    date7(r + 18, n);
    r[25] = fl;
    r[26] = r[27] = 0;
    both16(r + 28, 1);
    r[32] = (u8)idlen;
    if (!(idlen & 1)) r[33 + idlen] = 0;
    return hl;
}

/* One directory of the primary (jol 0) or Joliet (jol 1) tree.
 * mode 0: measure (sets dsize/jdsize and ce_sects); 1: write the CE area that
 * follows a primary directory; 2: write the directory extent. Every mode replays
 * the same records, so CE pieces land at the same offsets each time. */
static int dir_pass(iso_w *w, u32 d, int jol, int mode)
{
    const inode *dn = &w->nd[d];
    u32 nk = jol ? dn->nj : dn->nk;
    const u32 *kids = jol ? w->jkids + dn->jbeg : w->kids + dn->kbeg;
    u64 pos = 0;
    int r;
    w->ce_cur = w->ce_wpos = 0;
    w->ce_lba = dn->lba + dn->dsize / SECT;
    for (u32 i = 0; i < nk + 2; i++) {
        u32 k = i == 0 ? d : i == 1 ? dn->parent : kids[i - 2];
        int kind = i < 2 ? (int)i : 2;
        const inode *n = &w->nd[k];
        u32 ne = kind == 2 ? n_ext(n) : 1;
        for (u32 e = 0; e < ne; e++) {
            u8 *rec = w->rec;
            u32 idlen = kind < 2 ? 1 : jol ? n->jlen * 2u : n->plen + (n->is_dir ? 0 : 2u);
            u32 hl = 33 + idlen + !(idlen & 1), sua = 0;
            if (!jol) {
                susp_build(w, n, kind, d == 0 && kind == 0);
                if ((r = susp_pack(w, 255 - hl, mode, rec + hl, &sua))) return r;
            }
            u32 len = hl + sua;
            if ((pos % SECT) + len > SECT) {
                u32 gap = SECT - (u32)(pos % SECT);
                if (mode == 2 && (r = emit(w, 0, gap))) return r;
                pos += gap;
            }
            pos += len;
            if (mode != 2) continue;
            rec_head(w, rec, n, e, jol, kind, idlen, sua);
            if (kind < 2) rec[33] = (u8)kind;
            else if (jol)
                for (u32 j = 0; j < n->jlen; j++) wr16be(rec + 33 + 2 * j, n->jname[j]);
            else {
                __builtin_memcpy(rec + 33, n->pname, n->plen);
                if (!n->is_dir) { rec[33 + n->plen] = ';'; rec[34 + n->plen] = '1'; }
            }
            if ((r = emit(w, rec, len))) return r;
        }
    }
    u64 size = (pos + SECT - 1) / SECT * SECT;
    if (mode == 0) {
        if (size > EXTMAX) return GZ_E_LIMIT;
        if (jol) w->nd[d].jdsize = (u32)size;
        else { w->nd[d].dsize = (u32)size; w->nd[d].ce_sects = (w->ce_cur + SECT - 1) / SECT; }
    } else if (mode == 1) {
        if ((r = emit(w, 0, (u64)dn->ce_sects * SECT - w->ce_wpos))) return r;
    } else {
        if (size != (jol ? dn->jdsize : dn->dsize)) return GZ_E_FORMAT;
        if (size > pos && (r = emit(w, 0, size - pos))) return r;
    }
    return GZ_OK;
}

static u32 pt_idlen(const inode *n, int jol, int root)
{
    return root ? 1 : jol ? n->jlen * 2u : n->plen;
}

static int write_pt(iso_w *w, int jol, int be)
{
    const u32 *q = jol ? w->jdirs : w->dirs;
    u8 r[8 + 2 * JMAX + 2];
    for (u32 i = 0; i < w->ndirs; i++) {
        const inode *n = &w->nd[q[i]];
        u32 il = pt_idlen(n, jol, q[i] == 0), lba = jol ? n->jlba : n->lba;
        u32 par = jol ? w->nd[n->parent].jnum : w->nd[n->parent].pnum;
        if (par > 0xFFFF) par = 0xFFFF;            /* > 65535 directories: clamp */
        r[0] = (u8)il;
        r[1] = 0;
        if (be) { wr32be(r + 2, lba); wr16be(r + 6, (u16)par); }
        else { wr32(r + 2, lba); wr16(r + 6, (u16)par); }
        if (q[i] == 0) r[8] = 0;
        else if (jol) for (u32 j = 0; j < n->jlen; j++) wr16be(r + 8 + 2 * j, n->jname[j]);
        else __builtin_memcpy(r + 8, n->pname, n->plen);
        if (il & 1) r[8 + il] = 0;
        int e = emit(w, r, 8 + il + (il & 1));
        if (e) return e;
    }
    return pad_sector(w);
}

/* ---------------- volume descriptors ---------------- */

static void fill_text(u8 *p, u32 n, const char *s, int jol)
{
    u32 i = 0;
    if (jol) {
        for (; i + 1 < n; i += 2) { p[i] = 0; p[i + 1] = (u8)(*s ? *s++ : ' '); }
        if (i < n) p[i] = 0;
    } else {
        for (; i < n; i++) p[i] = (u8)(*s ? *s++ : ' ');
    }
}

static void put_vd(const iso_w *w, u8 *p, int jol)
{
    const inode *root = &w->nd[0];
    __builtin_memset(p, 0, SECT);
    p[0] = jol ? 2 : 1;
    __builtin_memcpy(p + 1, "CD001", 5);
    p[6] = 1;
    fill_text(p + 8, 32, "", jol);                 /* system identifier */
    if (jol) {
        u32 i = 0;
        for (; i < w->vol_jlen; i++) wr16be(p + 40 + 2 * i, w->vol_j[i]);
        for (; i < 16; i++) wr16be(p + 40 + 2 * i, ' ');
        p[88] = '%'; p[89] = '/'; p[90] = 'E';     /* UCS-2 level 3 */
    } else {
        __builtin_memcpy(p + 40, w->vol_p, 32);
    }
    both32(p + 80, w->total);
    both16(p + 120, 1);
    both16(p + 124, 1);
    both16(p + 128, SECT);
    both32(p + 132, jol ? w->jpt_size : w->pt_size);
    wr32(p + 140, w->pt_lba[jol ? 2 : 0]);
    wr32be(p + 148, w->pt_lba[jol ? 3 : 1]);
    u8 *r = p + 156;                               /* root directory record */
    rec_head(w, r, root, 0, jol, 0, 1, 0);
    r[33] = 0;
    fill_text(p + 190, 128, "", jol);              /* volume set */
    fill_text(p + 318, 128, "", jol);              /* publisher */
    fill_text(p + 446, 128, "", jol);              /* data preparer */
    fill_text(p + 574, 128, "GOGITZIP", jol);      /* application */
    fill_text(p + 702, 37, "", jol);
    fill_text(p + 739, 37, "", jol);
    fill_text(p + 776, 37, "", jol);
    date17(p + 813, w);                            /* creation */
    date17(p + 830, w);                            /* modification */
    for (int i = 0; i < 16; i++) p[847 + i] = p[864 + i] = '0';   /* expiration, effective: none */
    p[881] = 1;
}

/* ---------------- layout ---------------- */

static int layout(iso_w *w)
{
    int r;
    for (u32 i = 0; i < w->ndirs; i++)
        if ((r = dir_pass(w, w->dirs[i], 0, 0)) || (r = dir_pass(w, w->jdirs[i], 1, 0))) return r;
    u32 ps = 0, js = 0;
    for (u32 i = 0; i < w->ndirs; i++) {
        u32 a = pt_idlen(&w->nd[w->dirs[i]], 0, w->dirs[i] == 0);
        u32 b = pt_idlen(&w->nd[w->jdirs[i]], 1, w->jdirs[i] == 0);
        ps += 8 + a + (a & 1);
        js += 8 + b + (b & 1);
    }
    w->pt_size = ps;
    w->jpt_size = js;
    u64 cur = 19;
    w->pt_lba[0] = (u32)cur; cur += (ps + SECT - 1) / SECT;
    w->pt_lba[1] = (u32)cur; cur += (ps + SECT - 1) / SECT;
    w->pt_lba[2] = (u32)cur; cur += (js + SECT - 1) / SECT;
    w->pt_lba[3] = (u32)cur; cur += (js + SECT - 1) / SECT;
    for (u32 t = 0; t < 2; t++)
        for (u32 i = 0; i < w->ndirs; i++) {
            inode *n = &w->nd[t ? w->jdirs[i] : w->dirs[i]];
            if (t) { n->jlba = (u32)cur; cur += n->jdsize / SECT; }
            else { n->lba = (u32)cur; cur += n->dsize / SECT + n->ce_sects; }
            if (cur > 0xFFFFFFFFu) return GZ_E_LIMIT;
        }
    for (u32 i = 1; i < w->nn; i++)
        if (!w->nd[i].is_dir && (!w->nd[i].size || w->nd[i].is_link)) w->need_zero = 1;
    w->zero_lba = (u32)cur;
    cur += w->need_zero;
    w->data_lba = (u32)cur;
    w->in_total = 0;
    for (u32 i = 1; i < w->nn; i++) {
        inode *n = &w->nd[i];
        if (n->is_dir || n->is_link || !n->size) continue;
        n->lba = (u32)cur;
        cur += n->size / SECT + ((n->size & (SECT - 1)) != 0);
        if (cur > 0xFFFFFFFFu) return GZ_E_LIMIT;  /* volume size is 32-bit sectors */
        w->in_total += n->size;
    }
    w->total = (u32)cur;
    return GZ_OK;
}

/* ---------------- writing ---------------- */

static int write_meta(iso_w *w)
{
    u8 *vd = w->vd;
    int r = emit(w, 0, 16 * SECT);
    if (r) return r;
    for (int j = 0; j < 2; j++) {
        put_vd(w, vd, j);
        if ((r = emit(w, vd, SECT))) return r;
    }
    __builtin_memset(vd, 0, SECT);
    vd[0] = 255;
    __builtin_memcpy(vd + 1, "CD001", 5);
    vd[6] = 1;
    if ((r = emit(w, vd, SECT))) return r;
    for (int t = 0; t < 4; t++) {
        if ((r = at_lba(w, w->pt_lba[t])) || (r = write_pt(w, t >= 2, t & 1))) return r;
    }
    /* each primary directory with its continuation area, then the Joliet tree */
    for (u32 t = 0; t < 2; t++)
        for (u32 i = 0; i < w->ndirs; i++) {
            if ((i & 255) == 0 && cancelled(w)) return GZ_E_CANCEL;
            u32 d = t ? w->jdirs[i] : w->dirs[i];
            if ((r = at_lba(w, t ? w->nd[d].jlba : w->nd[d].lba)) || (r = dir_pass(w, d, (int)t, 2))) return r;
            if (!t && (r = dir_pass(w, d, 0, 1))) return r;
        }
    if (w->need_zero && (r = emit(w, 0, SECT))) return r;
    if ((r = at_lba(w, w->data_lba))) return r;
    return flush(w);
}

static void progress(iso_w *w)
{
    if (w->o->progress) w->o->progress(w->o->user, w->in_done, w->in_total);
}

/* zeros for the rest of a failed file (progress and cancel as for real data) */
static int fill_zero(iso_w *w, u64 left)
{
    int r = flush(w);
    __builtin_memset(w->rbuf, 0, RDCAP);
    while (!r && left) {
        u32 k = left < RDCAP ? (u32)left : RDCAP;
        if (cancelled(w)) return GZ_E_CANCEL;
        if ((r = gz_sink_write(w->out, w->rbuf, k))) break;
        w->wpos += k;
        w->in_done += k;
        left -= k;
        progress(w);
    }
    return r;
}

static int write_file(iso_w *w, inode *n)
{
    const gz_witem *it = &w->it[n->item];
    u64 left = n->size;
    gz_wsrc *src = 0;
    int werr = GZ_OK, err = w->o->open_item ? w->o->open_item(w->o->user, it, &src) : GZ_E_IO;
    if (!err && !src) err = GZ_E_IO;
    if (!err) {
        while (left) {
            if (cancelled(w)) { err = GZ_E_CANCEL; break; }
            u32 cap = left < RDCAP ? (u32)left : RDCAP, got = 0;
            err = src->read(src, w->rbuf, cap, &got);
            if (!err && (!got || got > cap)) err = got ? GZ_E_IO : GZ_E_TRUNC;   /* short file */
            if (err || (werr = gz_sink_write(w->out, w->rbuf, got))) break;
            w->wpos += got;
            left -= got;
            w->in_done += got;
            progress(w);
        }
        if (w->o->close_item) w->o->close_item(w->o->user, it, src);
    }
    if (werr) return werr;                         /* output failure: abort */
    if (err) {
        int r = report(w, n->item, err);
        if (r || (r = fill_zero(w, left))) return r;   /* keep the layout valid */
    }
    int r = pad_sector(w);
    return r ? r : flush(w);
}

/* Empty regular files are opened and closed too, like the other writers do (the
 * engine counts opened items and reports unreadable ones); nothing is read. */
static int touch_file(iso_w *w, const inode *n)
{
    const gz_witem *it = &w->it[n->item];
    u32 type = it->unix_mode & 0170000;
    if (it->is_link || (type && type != 0100000) || !w->o->open_item) return GZ_OK;
    gz_wsrc *src = 0;
    int err = w->o->open_item(w->o->user, it, &src);
    if (!err && src && w->o->close_item) w->o->close_item(w->o->user, it, src);
    return err ? report(w, n->item, err) : GZ_OK;
}

static int write_data(iso_w *w)
{
    progress(w);
    for (u32 i = 1; i < w->nn; i++) {
        inode *n = &w->nd[i];
        if (n->is_dir || n->is_link) continue;
        if (cancelled(w)) return GZ_E_CANCEL;
        int r = n->size ? at_lba(w, n->lba) : touch_file(w, n);
        if (r || (n->size && (r = write_file(w, n)))) return r;
    }
    return at_lba(w, w->total);
}

static int iso_write(const gz_wopts *o, const gz_witem *items, u32 n, gz_sink *out, gz_ctx *c)
{
    iso_w *w = (iso_w *)gz_alloc(sizeof(iso_w));
    if (!w) return GZ_E_NOMEM;
    w->o = o;
    w->it = items;
    w->nit = n;
    w->out = out;
    w->c = c;
    for (u32 i = 0; i < n; i++) {                  /* volume time: newest item */
        if (!items[i].mtime) continue;
        i64 t = gz_filetime_to_unix(items[i].mtime);
        if (!w->has_vtime || t > w->vtime) w->vtime = t;
        w->has_vtime = 1;
    }
    int r = build_tree(w);
    if (!r) r = build_dirs(w);
    if (!r) { volume_label(w); r = names(w); }
    if (!r) r = layout(w);
    if (!r) {
        w->rbuf = c ? gz_ctx_buffer(c, RDCAP) : 0;
        if (!w->rbuf) w->rbuf = w->own_rbuf = (u8 *)gz_alloc(RDCAP);
        if (!w->rbuf) r = GZ_E_NOMEM;
    }
    if (!r && cancelled(w)) r = GZ_E_CANCEL;
    if (!r) r = write_meta(w);
    if (!r) r = write_data(w);
    gz_free(w->own_rbuf);
    gz_free(w->nd);
    gz_free(w->ht);
    gz_free(w->kids);
    gz_free(w->jkids);
    gz_free(w->dirs);
    gz_free(w->jdirs);
    gz_free(w->tmp);
    gz_arena_free(&w->ar);
    gz_free(w);
    return r;
}

GZ_WRITER(gz_wr_iso)
const gz_writer gz_wr_iso = { GZ_WF_ISO, "ISO", "iso", 1u << GZ_WM_STORE, 0, iso_write };
