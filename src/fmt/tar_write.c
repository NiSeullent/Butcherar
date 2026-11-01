/*
 * 고깃ZIP - TAR writer: POSIX ustar headers, pax extended headers ('x') when a
 * value does not fit (non-ASCII or long names and link targets, sizes of 8 GiB
 * and more, times before 1970 or after 2242). Sizes that need pax are also
 * stored GNU base-256 in the ustar field for readers without pax support.
 *
 * Output is strictly sequential (see tar_write.h): headers are written before the
 * data, so an input that shrinks while it is read is padded with zeros and
 * reported through o->on_error, one that grows is cut at the size in the header.
 */
#include "gz_write.h"
#include "tar_write.h"

#define BLK 512u
#define RECORD 10240u
#define BUF (256u << 10)
#define OCT11 ((u64)1 << 33)        /* first value that needs more than 11 octal digits */

typedef struct tw {
    const gz_wopts *o;
    gz_sink *out;
    gz_ctx *c;
    u8 *nb; u32 ncap;               /* name bytes          */
    u8 *lb; u32 lcap;               /* link target bytes   */
    u8 *pax; u32 plen, pcap;        /* pax records         */
    u8 *buf;
    u64 total, done;
} tw;

static const u8 zero_blk[BLK];

static int tw_cancelled(const tw *t)
{
    return (t->o->cancel && *t->o->cancel) || gz_cancelled(t->c);
}

static int grow(u8 **p, u32 *cap, u64 need)
{
    if (need <= *cap) return GZ_OK;
    if (need > (64u << 20)) return GZ_E_LIMIT;
    u32 nc = *cap ? *cap : 256;
    while (nc < need) nc *= 2;
    u8 *np = (u8 *)gz_realloc(*p, nc);
    if (!np) return GZ_E_NOMEM;
    *p = np;
    *cap = nc;
    return GZ_OK;
}

/* UTF-16 -> UTF-8; lone U+DC80..U+DCFF stand for raw bytes (POSIX file names
 * that were not UTF-8) and are written back as those bytes */
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

static int to_utf8(const gzch *s, u8 **buf, u32 *cap, u32 *len, int dir_slash)
{
    size_t n = gz_wcslen(s);
    if (n > (4u << 20)) return GZ_E_LIMIT;
    int r = grow(buf, cap, (u64)n * 3 + 2);
    if (r) return r;
    *len = w2u(s, n, *buf);
    if (dir_slash && (!*len || (*buf)[*len - 1] != '/')) (*buf)[(*len)++] = '/';
    return GZ_OK;
}

static int is_ascii(const u8 *p, u32 n)
{
    for (u32 i = 0; i < n; i++) if (p[i] & 0x80) return 0;
    return 1;
}

/* cut n bytes of UTF-8 to at most max without splitting a character */
static u32 cut_utf8(const u8 *p, u32 n, u32 max)
{
    if (n <= max) return n;
    u32 k = max;
    while (k && (p[k] & 0xC0) == 0x80) k--;
    return k;
}

static void put_oct(u8 *f, u32 w, u64 v)        /* w - 1 digits + NUL */
{
    f[w - 1] = 0;
    for (u32 i = w - 1; i-- > 0;) { f[i] = (u8)('0' + (v & 7)); v >>= 3; }
}

static void put_b256(u8 *f, u32 w, u64 v)       /* GNU base-256, positive */
{
    for (u32 i = w; i-- > 1;) { f[i] = (u8)v; v >>= 8; }
    f[0] = 0x80;
}

/* ustar name field (+ prefix): 1 if the whole name fits */
static int ustar_name(u8 *h, const u8 *nm, u32 n)
{
    if (n <= 100) { __builtin_memcpy(h, nm, n); return 1; }
    /* prefix (<= 155) "/" name (<= 100), never splitting at a trailing slash */
    for (u32 p = 1; p <= 155 && p < n; p++) {
        if (nm[p] != '/' || n - p - 1 > 100 || p + 1 >= n || (p + 2 == n && nm[n - 1] == '/')) continue;
        __builtin_memcpy(h + 345, nm, p);
        __builtin_memcpy(h, nm + p + 1, n - p - 1);
        return 1;
    }
    __builtin_memcpy(h, nm, cut_utf8(nm, n, 100));      /* fallback for pax-less readers */
    return 0;
}

static int ustar_fits(const u8 *nm, u32 n)
{
    if (n <= 100) return 1;
    for (u32 p = 1; p <= 155 && p < n; p++)
        if (nm[p] == '/' && n - p - 1 <= 100 && p + 1 < n && !(p + 2 == n && nm[n - 1] == '/')) return 1;
    return 0;
}

static int write_header(tw *t, const u8 *nm, u32 nn, u8 type, u32 mode, u64 size, i64 mtime,
                        const u8 *lk, u32 ln)
{
    u8 h[BLK];
    __builtin_memset(h, 0, sizeof h);
    ustar_name(h, nm, nn);
    put_oct(h + 100, 8, mode & 07777);
    put_oct(h + 108, 8, 0);
    put_oct(h + 116, 8, 0);
    if (size < OCT11) put_oct(h + 124, 12, size);
    else put_b256(h + 124, 12, size);
    put_oct(h + 136, 12, (mtime >= 0 && (u64)mtime < OCT11) ? (u64)mtime : 0);
    h[156] = type;
    if (ln) __builtin_memcpy(h + 157, lk, cut_utf8(lk, ln, 100));
    __builtin_memcpy(h + 257, "ustar", 6);
    h[263] = '0';
    h[264] = '0';
    put_oct(h + 329, 8, 0);
    put_oct(h + 337, 8, 0);
    __builtin_memset(h + 148, ' ', 8);
    u32 sum = 0;
    for (u32 i = 0; i < BLK; i++) sum += h[i];
    put_oct(h + 148, 7, sum);          /* 6 digits, NUL, then the space already there */
    return gz_sink_write(t->out, h, BLK);
}

static u32 dec(u8 *o, u64 v)            /* decimal digits of v, returns length */
{
    u8 tmp[24];
    u32 n = 0;
    do { tmp[n++] = (u8)('0' + v % 10); v /= 10; } while (v);
    for (u32 i = 0; i < n; i++) o[i] = tmp[n - 1 - i];
    return n;
}

/* append "<len> key=value\n"; the length counts its own digits */
#define pax_add(t, key, v, vn) pax_add_(t, key, sizeof key - 1, v, vn)
static int pax_add_(tw *t, const char *key, u32 kn, const u8 *v, u32 vn)
{
    u64 base = (u64)kn + vn + 3;      /* ' ' '=' '\n' */
    u8 d[24];
    u32 digits = dec(d, base);
    if (dec(d, base + digits) > digits) digits++;
    u64 len = base + digits;
    int r = grow(&t->pax, &t->pcap, (u64)t->plen + len);
    if (r) return r;
    u8 *o = t->pax + t->plen;
    o += dec(o, len);
    *o++ = ' ';
    __builtin_memcpy(o, key, kn);
    o += kn;
    *o++ = '=';
    __builtin_memcpy(o, v, vn);
    o += vn;
    *o = '\n';
    t->plen += (u32)len;
    return GZ_OK;
}

static int write_zeros(tw *t, u64 n)
{
    while (n) {
        u32 k = n > BLK ? BLK : (u32)n;
        int r = gz_sink_write(t->out, zero_blk, k);
        if (r) return r;
        n -= k;
    }
    return GZ_OK;
}

static int pad_block(tw *t, u64 size)
{
    u32 pad = (u32)((BLK - (size & (BLK - 1))) & (BLK - 1));
    return pad ? gz_sink_write(t->out, zero_blk, pad) : GZ_OK;
}

static i64 unix_time(u64 ft)
{
    if (!ft) return 0;
    return gz_filetime_to_unix(ft);    /* floor for positive times */
}

/* copy exactly size bytes of the file into the archive (after its header) */
static int copy_data(tw *t, const gz_witem *it, gz_wsrc *src, u64 size)
{
    const gz_wopts *o = t->o;
    u64 left = size;
    int bad = 0;
    while (left) {
        if (tw_cancelled(t)) return GZ_E_CANCEL;
        u32 want = left < BUF ? (u32)left : BUF, got = 0;
        int r = bad ? GZ_OK : src->read(src, t->buf, want, &got);
        if (r == GZ_E_CANCEL) return r;
        if (!bad && (r || !got)) {
            /* read error or the file shrank: the header is out, keep the archive valid */
            bad = r ? r : GZ_E_TRUNC;
            int er = o->on_error ? o->on_error(o->user, it, bad) : bad;
            if (er) return er;
        }
        if (bad) {
            int w = write_zeros(t, left);
            if (w) return w;
            t->done += left;
            left = 0;
            break;
        }
        if (got > want) got = want;
        r = gz_sink_write(t->out, t->buf, got);
        if (r) return r;
        left -= got;
        t->done += got;
        if (o->progress) o->progress(o->user, t->done, t->total);
    }
    return pad_block(t, size);
}

static int write_item(tw *t, const gz_witem *it)
{
    const gz_wopts *o = t->o;
    const gzch *name = it->name;
    while (*name == '/') name++;
    while (name[0] == '.' && name[1] == '/') { name += 2; while (*name == '/') name++; }
    if (!name[0]) return GZ_OK;

    int is_link = it->is_link && it->link_target;
    int is_dir = !is_link && it->is_dir;
    u8 type = is_link ? '2' : is_dir ? '5' : '0';
    u64 size = (is_link || is_dir) ? 0 : it->size;
    u32 mode = it->unix_mode & 07777;
    if (!mode) mode = is_link ? 0777 : is_dir ? 0755 : (it->attr & 1) ? 0444 : 0644;
    i64 mt = unix_time(it->mtime);

    u32 nn, ln = 0;
    int r = to_utf8(name, &t->nb, &t->ncap, &nn, is_dir);
    if (!r && is_link) r = to_utf8(it->link_target, &t->lb, &t->lcap, &ln, 0);
    if (r) return r;

    gz_wsrc *src = 0;
    if (type == '0') {
        r = o->open_item(o->user, it, &src);
        if (r) {
            if (r == GZ_E_CANCEL) return r;
            return o->on_error ? o->on_error(o->user, it, r) : r;    /* GZ_OK: skip the item */
        }
    }

    /* pax extended header for what ustar cannot hold */
    t->plen = 0;
    if (!is_ascii(t->nb, nn) || !ustar_fits(t->nb, nn)) r = pax_add(t, "path", t->nb, nn);
    if (!r && is_link && (!is_ascii(t->lb, ln) || ln > 100)) r = pax_add(t, "linkpath", t->lb, ln);
    if (!r && size >= OCT11) {
        u8 d[24];
        r = pax_add(t, "size", d, dec(d, size));
    }
    if (!r && (mt < 0 || (u64)mt >= OCT11)) {
        u8 d[24];
        u32 k = 0;
        if (mt < 0) d[k++] = '-';
        k += dec(d + k, mt < 0 ? (u64)0 - (u64)mt : (u64)mt);
        r = pax_add(t, "mtime", d, k);
    }
    if (!r && t->plen) {
        static const u8 pn[] = "././@PaxHeader";
        r = write_header(t, pn, sizeof pn - 1, 'x', 0644, t->plen, mt, 0, 0);
        if (!r) r = gz_sink_write(t->out, t->pax, t->plen);
        if (!r) r = pad_block(t, t->plen);
    }
    if (!r) r = write_header(t, t->nb, nn, type, mode, size, mt, t->lb, ln);
    if (!r && src) r = copy_data(t, it, src, size);
    if (src) o->close_item(o->user, it, src);
    return r;
}

int gz_tar_write(const gz_wopts *o, const gz_witem *items, u32 n, gz_sink *out, gz_ctx *c)
{
    tw t;
    __builtin_memset(&t, 0, sizeof t);
    t.o = o;
    t.out = out;
    t.c = c;
    for (u32 i = 0; i < n; i++)
        if (!items[i].is_dir && !items[i].is_link) t.total += items[i].size;
    t.buf = (u8 *)gz_alloc(BUF);
    int r = t.buf ? GZ_OK : GZ_E_NOMEM;
    for (u32 i = 0; i < n && !r; i++) {
        if (tw_cancelled(&t)) { r = GZ_E_CANCEL; break; }
        r = write_item(&t, &items[i]);
    }
    if (!r) r = write_zeros(&t, 2 * BLK);
    if (!r) {
        u64 rem = out->pos % RECORD;
        if (rem) r = write_zeros(&t, RECORD - rem);
    }
    if (!r && o->progress) o->progress(o->user, t.done, t.total);
    gz_free(t.buf);
    gz_free(t.nb);
    gz_free(t.lb);
    gz_free(t.pax);
    return r;
}

static int tar_write(const gz_wopts *o, const gz_witem *items, u32 n, gz_sink *out, gz_ctx *c)
{
    return gz_tar_write(o, items, n, out, c);
}

GZ_WRITER(gz_wr_tar)
const gz_writer gz_wr_tar = { GZ_WF_TAR, "TAR", "tar", (1u << GZ_WM_DEFAULT) | (1u << GZ_WM_STORE), 0, tar_write };
