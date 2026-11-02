/*
 * 고깃ZIP - TAR writer: POSIX ustar headers, pax extended headers ('x') when a
 * value does not fit (non-ASCII or long names and link targets, sizes of 8 GiB
 * and more, times before 1970 or after 2242). Sizes that need pax are also
 * stored GNU base-256 in the ustar field for readers without pax support.
 *
 * The stream is generated on demand (gz_tar_reader, see tar_write.h): headers
 * are produced before the data, so an input that shrinks while it is read is
 * padded with zeros and reported through o->on_error, one that grows is cut at
 * the size in the header.
 */
#include "gz_write.h"
#include "tar_write.h"

#define BLK 512u
#define RECORD 10240u
#define BUF (256u << 10)
#define OCT11 ((u64)1 << 33)        /* first value that needs more than 11 octal digits */

enum { P_NEXT, P_HDR, P_DATA, P_ZERO, P_END, P_DONE };

struct gz_tar_reader {
    const gz_wopts *o;
    const gz_witem *items;
    u32 n, idx;                     /* items, next item to start              */
    gz_ctx *c;
    int phase, err;                 /* P_*, sticky error                      */
    u8 *nb; u32 ncap;               /* name bytes                             */
    u8 *lb; u32 lcap;               /* link target bytes                      */
    u8 *pax; u32 plen, pcap;        /* pax records                            */
    u8 *hb; u32 hlen, hpos, hcap;   /* headers of the current member          */
    const gz_witem *it;             /* member being written                   */
    gz_wsrc *src;                   /* its open input                         */
    u64 left;                       /* data bytes still due                   */
    u32 zleft;                      /* zero padding still due                 */
    int bad;                        /* input failed: the rest is zeros        */
    u64 pos;                        /* bytes produced                         */
    u64 total, done;                /* progress                               */
};

static int tw_cancelled(const gz_tar_reader *t)
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

/* see tar_write.h */
u32 gz_tar_name_utf8(const gzch *s, size_t n, u8 *o)
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
    *len = gz_tar_name_utf8(s, n, *buf);
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

/* append a ustar header block to the pending header bytes */
static int put_header(gz_tar_reader *t, const u8 *nm, u32 nn, u8 type, u32 mode, u64 size, i64 mtime,
                      const u8 *lk, u32 ln)
{
    int r = grow(&t->hb, &t->hcap, (u64)t->hlen + BLK);
    if (r) return r;
    u8 *h = t->hb + t->hlen;
    __builtin_memset(h, 0, BLK);
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
    t->hlen += BLK;
    return GZ_OK;
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
static int pax_add_(gz_tar_reader *t, const char *key, u32 kn, const u8 *v, u32 vn)
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

static u32 pad_of(u64 size) { return (u32)((BLK - (size & (BLK - 1))) & (BLK - 1)); }

static i64 unix_time(u64 ft)
{
    if (!ft) return 0;
    return gz_filetime_to_unix(ft);    /* floor for positive times */
}

/* Prepare the next member: open its file and build its headers into hb.
 * GZ_OK with t->hlen == 0: nothing to write for this item (skipped). */
static int start_item(gz_tar_reader *t, const gz_witem *it)
{
    const gz_wopts *o = t->o;
    const gzch *name = it->name;
    t->hlen = t->hpos = 0;
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

    if (type == '0') {
        r = o->open_item(o->user, it, &t->src);
        if (r) {
            t->src = 0;
            if (r == GZ_E_CANCEL) return r;
            return o->on_error ? o->on_error(o->user, it, r) : r;    /* GZ_OK: skip the item */
        }
    }
    t->it = it;
    t->left = size;
    t->bad = 0;

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
        u32 pl = t->plen, pp = pad_of(pl);
        r = put_header(t, pn, sizeof pn - 1, 'x', 0644, pl, mt, 0, 0);
        if (!r) r = grow(&t->hb, &t->hcap, (u64)t->hlen + pl + pp);
        if (!r) {
            __builtin_memcpy(t->hb + t->hlen, t->pax, pl);
            __builtin_memset(t->hb + t->hlen + pl, 0, pp);
            t->hlen += pl + pp;
        }
    }
    if (!r) r = put_header(t, t->nb, nn, type, mode, size, mt, t->lb, ln);
    return r;
}

static void end_item(gz_tar_reader *t)
{
    if (t->src) t->o->close_item(t->o->user, t->it, t->src);
    t->src = 0;
}

int gz_tar_reader_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    gz_tar_reader *t = (gz_tar_reader *)ctx;
    const gz_wopts *o = t->o;
    u32 n = 0;
    int r = t->err;
    *got = 0;
    if (r) return r;
    if (t->phase != P_DONE && tw_cancelled(t)) { r = GZ_E_CANCEL; goto fail; }
    while (n < cap) {
        u32 room = cap - n;
        switch (t->phase) {
        case P_NEXT:
            end_item(t);
            if (t->idx >= t->n) {
                /* two zero blocks, then pad to a full record */
                u64 rem = (t->pos + n + 2 * BLK) % RECORD;
                t->zleft = 2 * BLK + (rem ? (u32)(RECORD - rem) : 0);
                t->phase = P_END;
                break;
            }
            if (tw_cancelled(t)) { r = GZ_E_CANCEL; goto fail; }
            r = start_item(t, &t->items[t->idx++]);
            if (r) goto fail;
            if (t->hlen) t->phase = P_HDR;
            break;
        case P_HDR: {
            u32 k = t->hlen - t->hpos;
            if (k > room) k = room;
            __builtin_memcpy(buf + n, t->hb + t->hpos, k);
            n += k;
            t->hpos += k;
            if (t->hpos == t->hlen) t->phase = t->src ? P_DATA : P_NEXT;
            break;
        }
        case P_DATA: {
            if (!t->left) {
                t->zleft = pad_of(t->it->size);
                t->phase = P_ZERO;
                break;
            }
            u32 want = t->left < room ? (u32)t->left : room, g = 0;
            if (want > BUF) want = BUF;
            if (!t->bad) {
                r = t->src->read(t->src, buf + n, want, &g);
                if (r == GZ_E_CANCEL) goto fail;
                if (r || !g) {
                    /* read error or the file shrank: the header is out, keep the archive valid */
                    t->bad = r ? r : GZ_E_TRUNC;
                    r = o->on_error ? o->on_error(o->user, t->it, t->bad) : t->bad;
                    if (r) goto fail;
                }
            }
            if (t->bad) {
                g = want;
                __builtin_memset(buf + n, 0, g);
            }
            if (g > want) g = want;
            n += g;
            t->left -= g;
            t->done += g;
            if (o->progress) o->progress(o->user, t->done, t->total);
            break;
        }
        case P_ZERO:
        case P_END: {
            u32 k = t->zleft < room ? t->zleft : room;
            __builtin_memset(buf + n, 0, k);
            n += k;
            t->zleft -= k;
            if (!t->zleft) {
                if (t->phase == P_ZERO) {
                    t->phase = P_NEXT;
                } else {
                    t->phase = P_DONE;
                    if (o->progress) o->progress(o->user, t->done, t->total);
                }
            }
            break;
        }
        default:            /* P_DONE */
            goto out;
        }
    }
out:
    t->pos += n;
    *got = n;
    return GZ_OK;
fail:
    end_item(t);
    t->err = r;
    return r;
}

gz_tar_reader *gz_tar_reader_new(const gz_wopts *o, const gz_witem *items, u32 n, gz_ctx *c)
{
    gz_tar_reader *t = (gz_tar_reader *)gz_alloc(sizeof *t);
    if (!t) return 0;
    t->o = o;
    t->items = items;
    t->n = n;
    t->c = c;
    t->phase = P_NEXT;
    for (u32 i = 0; i < n; i++)
        if (!items[i].is_dir && !items[i].is_link) t->total += items[i].size;
    return t;
}

void gz_tar_reader_free(gz_tar_reader *t)
{
    if (!t) return;
    end_item(t);
    gz_free(t->nb);
    gz_free(t->lb);
    gz_free(t->pax);
    gz_free(t->hb);
    gz_free(t);
}

u64 gz_tar_size_estimate(const gz_witem *items, u32 n)
{
    u64 s = 2 * BLK + RECORD;
    for (u32 i = 0; i < n; i++) {
        u64 z = (items[i].is_dir || items[i].is_link) ? 0 : items[i].size;
        s += 3 * BLK + ((z + BLK - 1) & ~(u64)(BLK - 1));
    }
    return s;
}

int gz_tar_write(const gz_wopts *o, const gz_witem *items, u32 n, gz_sink *out, gz_ctx *c)
{
    gz_tar_reader *t = gz_tar_reader_new(o, items, n, c);
    u8 *buf = (u8 *)gz_alloc(BUF);
    int r = t && buf ? GZ_OK : GZ_E_NOMEM;
    while (!r) {
        u32 got = 0;
        r = gz_tar_reader_read(t, buf, BUF, &got);
        if (r || !got) break;
        r = gz_sink_write(out, buf, got);
    }
    gz_free(buf);
    gz_tar_reader_free(t);
    return r;
}

static int tar_write(const gz_wopts *o, const gz_witem *items, u32 n, gz_sink *out, gz_ctx *c)
{
    return gz_tar_write(o, items, n, out, c);
}

GZ_WRITER(gz_wr_tar)
const gz_writer gz_wr_tar = { GZ_WF_TAR, "TAR", "tar", (1u << GZ_WM_DEFAULT) | (1u << GZ_WM_STORE), 0, tar_write };
