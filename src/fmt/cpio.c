/*
 * 고깃ZIP - CPIO archives
 *
 *   newc  "070701"  110-byte hex header, name end and data end padded to 4
 *   crc   "070702"  newc + 32-bit sum of the data bytes in the check field
 *   odc   "070707"  76-byte octal header (POSIX, macOS Payload), no padding
 *   bin   070707    26-byte binary header, either byte order, padded to 2
 *
 * Plain .cpio files are random access (entries are stored). cpio streams inside
 * compressed files (streamfmt.c) and RPM payloads use the push parser below.
 * Archives that follow TRAILER!!! after zero padding (initramfs) are listed too.
 */
#include "cpio.h"

enum { K_NONE = 0, K_NEWC, K_CRC, K_ODC, K_BIN_LE, K_BIN_BE };
enum { T_SKIP = 0, T_FILE, T_DIR, T_LINK };

#define CPIO_NAME_MAX 65536u      /* longest name accepted (PATH_MAX is 4096)       */
#define CPIO_LINK_MAX 16384u      /* symlink targets up to this size go to the list */
#define F_MULTI       1u          /* regular file with nlink > 1: hard link member  */

typedef struct {
    int kind;
    u32 hsize, align;             /* fixed header size; alignment of name and data ends */
    u32 mode, nlink, namesize, check;
    u64 key;                      /* device + inode (hard link groups) */
    u64 size;
    i64 mtime;
} cpio_hdr;

/* ---------------- header decoding ---------------- */

static int kind_of(const u8 *p, u32 n)
{
    if (n >= 2 && p[0] == 0xC7 && p[1] == 0x71) return K_BIN_LE;
    if (n >= 2 && p[0] == 0x71 && p[1] == 0xC7) return K_BIN_BE;
    if (n < 6 || p[0] != '0' || p[1] != '7' || p[2] != '0' || p[3] != '7' || p[4] != '0') return K_NONE;
    return p[5] == '1' ? K_NEWC : p[5] == '2' ? K_CRC : p[5] == '7' ? K_ODC : K_NONE;
}

int gz_cpio_magic(const u8 *p, u32 n) { return kind_of(p, n) != K_NONE; }

static u32 hsize_of(int k) { return k == K_ODC ? 76 : (k == K_BIN_LE || k == K_BIN_BE) ? 26 : 110; }

static u32 pad_to(u64 pos, u32 align) { return (u32)(0 - pos) & (align - 1); }

static int hex8(const u8 *p, u32 *v)
{
    u32 x = 0;
    for (int i = 0; i < 8; i++) {
        u32 c = p[i], d;
        if (c - '0' < 10) d = c - '0';
        else if ((c | 0x20) - 'a' < 6) d = (c | 0x20) - 'a' + 10;
        else return 0;
        x = x << 4 | d;
    }
    *v = x;
    return 1;
}

static int octn(const u8 *p, u32 n, u64 *v)
{
    u64 x = 0;
    for (u32 i = 0; i < n; i++) {
        u32 d = (u32)p[i] - '0';
        if (d > 7) return 0;
        x = x << 3 | d;
    }
    *v = x;
    return 1;
}

static u32 bin16(const u8 *p, int be) { return be ? rd16be(p) : rd16(p); }

static int parse_hdr(const u8 *h, int kind, cpio_hdr *ch)
{
    ch->kind = kind;
    ch->hsize = hsize_of(kind);
    if (kind == K_NEWC || kind == K_CRC) {
        u32 f[13];
        for (int i = 0; i < 13; i++)
            if (!hex8(h + 6 + 8 * i, &f[i])) return GZ_E_FORMAT;
        ch->align = 4;
        ch->mode = f[1];
        ch->nlink = f[4];
        ch->mtime = f[5];
        ch->size = f[6];
        ch->key = (u64)f[0] | (u64)((f[7] << 20) ^ f[8]) << 32;
        ch->namesize = f[11];
        ch->check = f[12];
    } else if (kind == K_ODC) {
        /* magic dev ino mode uid gid nlink rdev (6 digits each) mtime(11) namesize(6) filesize(11) */
        u64 v[11];
        static const u8 off[11] = { 6, 12, 18, 24, 30, 36, 42, 48, 59, 65, 76 };
        for (int i = 0; i < 10; i++)
            if (!octn(h + off[i], (u32)(off[i + 1] - off[i]), &v[i])) return GZ_E_FORMAT;
        ch->align = 1;
        ch->mode = (u32)v[2];
        ch->nlink = (u32)v[5];
        ch->mtime = (i64)v[7];
        ch->namesize = (u32)v[8];
        ch->size = v[9];
        ch->key = v[1] | v[0] << 32;
        ch->check = 0;
    } else {
        int be = kind == K_BIN_BE;
        ch->align = 2;
        ch->mode = bin16(h + 6, be);
        ch->nlink = bin16(h + 12, be);
        ch->mtime = (i64)(bin16(h + 16, be) << 16 | bin16(h + 18, be));
        ch->namesize = bin16(h + 20, be);
        ch->size = bin16(h + 22, be) << 16 | bin16(h + 24, be);
        ch->key = bin16(h + 4, be) | (u64)bin16(h + 2, be) << 32;
        ch->check = 0;
    }
    if (!ch->namesize || ch->namesize > CPIO_NAME_MAX) return GZ_E_FORMAT;
    return GZ_OK;
}

static int type_of(u32 mode)
{
    switch (mode & 0170000) {
    case 0100000: case 0: return T_FILE;     /* 0: very old writers */
    case 0040000: return T_DIR;
    case 0120000: return T_LINK;
    default: return T_SKIP;                  /* devices, fifos, sockets */
    }
}

static u32 name_len(const u8 *p, u32 n)
{
    u32 k = 0;
    while (k < n && p[k]) k++;
    return k;
}

static int is_trailer(const u8 *p, u32 n) { return n == 10 && !__builtin_memcmp(p, "TRAILER!!!", 10); }

static u32 byte_sum(const u8 *p, size_t n)
{
    u32 a = 0, b = 0, c = 0, d = 0;
    size_t i = 0;
    for (; i + 4 <= n; i += 4) { a += p[i]; b += p[i + 1]; c += p[i + 2]; d += p[i + 3]; }
    for (; i < n; i++) a += p[i];
    return a + b + c + d;
}

/* ---------------- listing helpers ---------------- */

static int add_entry(gz_archive *a, const cpio_hdr *ch, const u8 *name, u32 nlen, u64 data_off, int type)
{
    gz_entry *e;
    int r = gz_arc_add_named(a, name, nlen, GZ_NE_LEGACY, &e);
    if (r) return r;
    e->is_dir = (u8)(type == T_DIR || (nlen && name[nlen - 1] == '/'));
    e->is_link = (u8)(type == T_LINK && !e->is_dir);
    /* a symlink target kept in the listing is no data; a longer one is */
    int data = !e->is_dir && (type == T_FILE || (type == T_LINK && ch->size > CPIO_LINK_MAX));
    e->usize = e->csize = data ? ch->size : 0;
    e->off = data_off;
    e->aux = ch->key;
    e->aux32 = ch->check;
    e->method = (u16)ch->kind;
    if (type == T_FILE && ch->nlink > 1 && !e->is_dir) e->flags = F_MULTI;
    e->mtime = gz_unix_to_filetime(ch->mtime);
    e->mtime_kind = GZ_MT_FILETIME;
    e->unix_mode = (ch->mode & 07777) | (e->is_dir ? 0040000u : e->is_link ? 0120000u : 0100000u);
    if (ch->mode && !(ch->mode & 0200)) e->attr |= 1;
    if (e->is_dir) e->attr |= 0x10;
    return GZ_OK;
}

static int set_link(gz_archive *a, u32 idx, const u8 *t, u32 n)
{
    n = name_len(t, n);
    if (!n) return GZ_OK;
    u32 off;
    int r = gz_arc_raw_append(a, t, n, &off);
    if (r) return r;
    a->e[idx].link_off = off;
    a->e[idx].link_len = n;
    return GZ_OK;
}

/* Hard links: newc/crc writers store the data with one member of a link group
 * (GNU cpio: the last), the others have size 0. Those become is_link = 2 entries
 * naming the member that holds the data. */
static int link_fixup(gz_archive *a, u32 first)
{
    u32 cnt = 0;
    for (u32 i = first; i < a->n; i++) cnt += a->e[i].flags & F_MULTI;
    if (cnt < 2) return GZ_OK;
    u32 cap = 16;
    while (cap < cnt * 2) cap <<= 1;
    u32 *tab = (u32 *)gz_alloc((size_t)cap * sizeof(u32));      /* entry index + 1, 0 = empty */
    if (!tab) return GZ_E_NOMEM;
    for (int pass = 0; pass < 2; pass++) {
        for (u32 i = first; i < a->n; i++) {
            gz_entry *e = &a->e[i];
            if (!(e->flags & F_MULTI)) continue;
            u32 h = (u32)((e->aux * 0x9E3779B97F4A7C15ull) >> 40) & (cap - 1);
            while (tab[h] && a->e[tab[h] - 1].aux != e->aux) h = (h + 1) & (cap - 1);
            if (!pass) {
                if (!tab[h] || e->usize) tab[h] = i + 1;      /* the last member with data */
                continue;
            }
            const gz_entry *d = &a->e[tab[h] - 1];
            if (d != e && !e->usize && d->usize) {
                e->is_link = 2;
                e->link_off = d->raw_off;
                e->link_len = d->raw_len;
            }
        }
    }
    gz_free(tab);
    return GZ_OK;
}

/* ---------------- push parser ---------------- */

enum { S_HDR, S_NAME, S_PADN, S_DATA, S_PADD, S_ZERO };
enum { D_SKIP, D_FILE, D_LINK };

struct gz_cpio_parser {
    gz_archive *a;
    gz_ctx *c;
    const u8 *sel;
    gz_out *out;
    int extracting;
    int state, done, trailer, dkind;
    cpio_hdr ch;
    u8 hdr[112];
    u32 hlen;
    u8 *name; u32 name_cap, nlen;
    u8 *lnk; u32 llen;            /* symlink target being collected (listing) */
    u64 pos, left;                /* stream offset, data bytes left */
    u32 pad;
    u32 sum;                      /* crc format checksum of the current entry */
    u32 first;                    /* a->n when the parser was created */
    i32 lidx;                     /* listing: entry whose target is collected */
    u32 next_idx, want;           /* extraction: next entry index, selected entries left */
    i32 cur;                      /* entry being written, -1 none */
    int cur_status;
};

gz_cpio_parser *gz_cpio_parser_new(gz_archive *a, const u8 *sel, gz_out *out, gz_ctx *c)
{
    gz_cpio_parser *t = (gz_cpio_parser *)gz_alloc(sizeof(gz_cpio_parser));
    if (!t) return 0;
    t->a = a;
    t->c = c;
    t->sel = sel;
    t->out = out;
    t->extracting = out != 0;
    t->first = a->n;
    t->cur = t->lidx = -1;
    if (t->extracting) {
        for (u32 i = 0; i < a->n; i++) t->want += sel[i] != 0;
        if (!t->want) t->done = 1;
    }
    return t;
}

void gz_cpio_parser_free(gz_cpio_parser *t)
{
    if (!t) return;
    gz_free(t->name);
    gz_free(t->lnk);
    gz_free(t);
}

int gz_cpio_done(const gz_cpio_parser *t) { return t->done; }

static void entry_done(gz_cpio_parser *t)
{
    if (t->want && !--t->want) t->done = 1;
}

/* name complete: decide what the data is and announce the entry */
static int begin_data(gz_cpio_parser *t)
{
    const cpio_hdr *ch = &t->ch;
    u32 nlen = name_len(t->name, ch->namesize);
    t->state = S_DATA;
    t->left = ch->size;
    t->dkind = D_SKIP;
    t->sum = 0;
    t->cur = t->lidx = -1;
    if (is_trailer(t->name, nlen)) { t->trailer = 1; return GZ_OK; }
    int type = type_of(ch->mode);
    if (type == T_SKIP) return GZ_OK;
    if (!t->extracting) {
        int r = add_entry(t->a, ch, t->name, nlen, t->pos, type);
        if (r) return r;
        const gz_entry *e = &t->a->e[t->a->n - 1];
        if (e->is_link && !e->usize && ch->size) {
            if (!t->lnk && !(t->lnk = (u8 *)gz_alloc(CPIO_LINK_MAX))) return GZ_E_NOMEM;
            t->dkind = D_LINK;
            t->llen = 0;
            t->lidx = (i32)t->a->n - 1;
        }
        return GZ_OK;
    }
    u32 idx = t->next_idx++;
    if (idx >= t->a->n || !t->sel[idx]) return GZ_OK;
    int r = t->out->open(t->out, idx);
    if (r == GZ_E_CANCEL) return r;
    if (r) { entry_done(t); return GZ_OK; }          /* skipped / reported by the engine */
    const gz_entry *e = &t->a->e[idx];
    if (e->usize && ch->size && !e->is_dir && !(e->is_link && e->link_len)) {
        t->dkind = D_FILE;
        t->cur = (i32)idx;
        t->cur_status = GZ_OK;
    } else {
        t->out->close(t->out, idx, GZ_OK);
        entry_done(t);
    }
    return GZ_OK;
}

static int end_data(gz_cpio_parser *t)
{
    if (t->dkind == D_LINK && t->lidx >= 0) {
        int r = set_link(t->a, (u32)t->lidx, t->lnk, t->llen);
        if (r) return r;
    }
    if (t->cur >= 0) {
        int st = t->cur_status;
        if (!st && t->ch.kind == K_CRC && t->sum != t->ch.check) st = GZ_E_CRC;
        t->out->close(t->out, (u32)t->cur, st);
        t->cur = -1;
        entry_done(t);
    }
    t->lidx = -1;
    t->pad = pad_to(t->pos, t->ch.align);
    t->state = S_PADD;
    return GZ_OK;
}

static int data_chunk(gz_cpio_parser *t, const u8 *p, size_t n)
{
    if (t->dkind == D_LINK) {
        __builtin_memcpy(t->lnk + t->llen, p, n);      /* size <= CPIO_LINK_MAX */
        t->llen += (u32)n;
    } else if (t->cur >= 0 && t->cur_status == GZ_OK) {
        if (t->ch.kind == K_CRC) t->sum += byte_sum(p, n);
        int r = t->out->write(t->out, p, n);
        if (r) {
            t->cur_status = r;
            if (r == GZ_E_CANCEL) return r;
        }
    }
    return GZ_OK;
}

/* a complete fixed header is in t->hdr */
static int got_header(gz_cpio_parser *t)
{
    int r = parse_hdr(t->hdr, t->ch.kind, &t->ch);
    if (r) {
        if (t->trailer) { t->done = 1; return GZ_OK; }   /* junk after the archive */
        return r;
    }
    t->trailer = 0;
    if (t->name_cap < t->ch.namesize) {
        u32 nc = t->ch.namesize < 4096 ? 4096 : t->ch.namesize;
        gz_free(t->name);
        t->name = (u8 *)gz_alloc(nc);
        t->name_cap = t->name ? nc : 0;
        if (!t->name) return GZ_E_NOMEM;
    }
    t->nlen = 0;
    t->state = S_NAME;
    return GZ_OK;
}

int gz_cpio_feed(void *parser, const u8 *p, size_t n)
{
    gz_cpio_parser *t = (gz_cpio_parser *)parser;
    int r;
    for (;;) {
        /* transitions that consume no input */
        if (t->state == S_PADN && !t->pad) { if ((r = begin_data(t))) return r; continue; }
        if (t->state == S_DATA && !t->left) { if ((r = end_data(t))) return r; continue; }
        if (t->state == S_PADD && !t->pad) { t->state = t->trailer ? S_ZERO : S_HDR; t->hlen = 0; continue; }
        if (t->done || !n) break;
        switch (t->state) {
        case S_ZERO: {                       /* padding after TRAILER!!! */
            size_t k = 0;
            while (k < n && !p[k]) k++;
            p += k; n -= k; t->pos += k;
            if (n) { t->state = S_HDR; t->hlen = 0; }
            break;
        }
        case S_HDR: {
            u32 need = t->hlen < 6 ? 6 : t->ch.hsize;
            u32 take = need - t->hlen;
            if (take > n) take = (u32)n;
            __builtin_memcpy(t->hdr + t->hlen, p, take);
            t->hlen += take; p += take; n -= take; t->pos += take;
            if (t->hlen < need) break;
            if (need == 6) {
                int k = kind_of(t->hdr, 6);
                if (!k) {
                    if (t->trailer) { t->done = 1; break; }
                    return GZ_E_FORMAT;
                }
                t->ch.kind = k;
                t->ch.hsize = hsize_of(k);
                break;
            }
            if ((r = got_header(t))) return r;
            break;
        }
        case S_NAME: {
            u32 take = t->ch.namesize - t->nlen;
            if (take > n) take = (u32)n;
            __builtin_memcpy(t->name + t->nlen, p, take);
            t->nlen += take; p += take; n -= take; t->pos += take;
            if (t->nlen == t->ch.namesize) {
                t->pad = pad_to(t->pos, t->ch.align);
                t->state = S_PADN;
            }
            break;
        }
        case S_PADN: case S_PADD: {
            u32 take = t->pad < n ? t->pad : (u32)n;
            t->pad -= take; p += take; n -= take; t->pos += take;
            break;
        }
        default: {                           /* S_DATA */
            size_t take = n < t->left ? n : (size_t)t->left;
            if ((r = data_chunk(t, p, take))) return r;
            p += take; n -= take; t->pos += take; t->left -= take;
            break;
        }
        }
    }
    if (t->c && gz_cancelled(t->c)) return GZ_E_CANCEL;
    return GZ_OK;
}

int gz_cpio_finish(gz_cpio_parser *t, int status)
{
    if (t->extracting) {
        if (t->cur >= 0) {
            int st = status ? status : GZ_E_TRUNC;
            t->out->close(t->out, (u32)t->cur, st);
            t->cur = -1;
            return st;
        }
        if (!status && t->want) status = GZ_E_TRUNC;    /* selected entries never reached */
        return status;
    }
    int r = link_fixup(t->a, t->first);
    return status ? status : r;
}

/* ---------------- whole streams ---------------- */

static int parser_sink(void *u, const u8 *p, size_t n)
{
    gz_cpio_parser *t = (gz_cpio_parser *)u;
    int r = gz_cpio_feed(t, p, n);
    if (r) return r;
    return t->done ? GZ_E_SKIP : GZ_OK;
}

int gz_cpio_list_stream(gz_archive *a, gz_src *s, gz_decode_fn dec, gz_ctx *c)
{
    gz_cpio_parser *t = gz_cpio_parser_new(a, 0, 0, c);
    if (!t) return GZ_E_NOMEM;
    int r = dec(s, parser_sink, t, c);
    if (r == GZ_E_SKIP) r = GZ_OK;
    r = gz_cpio_finish(t, r);
    gz_cpio_parser_free(t);
    if (r == GZ_E_CANCEL || r == GZ_E_NOMEM) return r;
    if (r && !a->n) return r;
    return GZ_OK;                 /* tolerate a damaged tail: entries found so far */
}

int gz_cpio_extract_stream(gz_archive *a, gz_src *s, gz_decode_fn dec, const u8 *sel,
                           gz_out *out, gz_ctx *c)
{
    gz_cpio_parser *t = gz_cpio_parser_new(a, sel, out, c);
    if (!t) return GZ_E_NOMEM;
    int r = t->done ? GZ_OK : dec(s, parser_sink, t, c);
    if (r == GZ_E_SKIP) r = GZ_OK;
    r = gz_cpio_finish(t, r);
    gz_cpio_parser_free(t);
    return r;
}

const gz_stream_codec *gz_stream_codec_find(gz_src *s)
{
    u32 n = s->size < 65536 ? (u32)s->size : 65536;
    if (!n) return 0;
    u8 *head = (u8 *)gz_alloc(n);
    if (!head) return 0;
    const gz_stream_codec *best = 0;
    if (!gz_src_read_exact(s, 0, head, n)) {
        int bs = 0;
        for (u32 i = 0; gz_formats[i]; i++) {
            const gz_format *f = gz_formats[i];
            if (f->open != gz_sfmt_open || !f->impl || !f->probe) continue;
            int sc = f->probe(s, head, n);
            if (sc > bs) { bs = sc; best = (const gz_stream_codec *)f->impl; }
        }
    }
    gz_free(head);
    return best;
}

int gz_stream_copy(gz_src *s, gz_sink_fn sink, void *user, gz_ctx *c)
{
    u8 *buf = gz_ctx_buffer(c, 256u << 10);
    if (!buf) return GZ_E_NOMEM;
    for (u64 off = 0; off < s->size;) {
        if (gz_cancelled(c)) return GZ_E_CANCEL;
        u32 n = s->size - off < (256u << 10) ? (u32)(s->size - off) : (256u << 10);
        int r = gz_src_read_exact(s, off, buf, n);
        if (r) return r;
        r = sink(user, buf, n);
        if (r) return r;
        off += n;
    }
    return GZ_OK;
}

/* ---------------- plain .cpio (random access) ---------------- */

static int cpio_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    int k = kind_of(h, n);
    cpio_hdr ch;
    if (!k || n < hsize_of(k) || parse_hdr(h, k, &ch)) return 0;
    if (k == K_BIN_LE || k == K_BIN_BE) {
        /* only a 2-byte magic: also want the NUL-terminated name inside the head */
        if (26 + ch.namesize > n || h[26 + ch.namesize - 1]) return 0;
        return 70;
    }
    return 95;
}

/* read-ahead window: headers, names and link targets of small entries come
 * from one read instead of two or three per entry. The read size adapts: it
 * grows while one read serves several requests (many small entries) and
 * shrinks when every header needs a read of its own (big entries). */
#define WIN_CAP (256u << 10)
typedef struct { gz_src *s; u8 *buf; u64 base; u32 len, chunk, hits; } win;

/* n bytes at off (n <= WIN_CAP); NULL with *err set when the source ends first */
static const u8 *win_get(win *w, u64 off, u32 n, int *err)
{
    if (off >= w->base && off - w->base <= w->len && n <= w->len - (off - w->base)) {
        w->hits++;
        return w->buf + (off - w->base);
    }
    if (off > w->s->size || n > w->s->size - off) { *err = GZ_E_TRUNC; return 0; }
    if (w->hits > 4 && w->chunk < WIN_CAP) w->chunk *= 2;
    else if (w->hits < 2 && w->chunk > 4096) w->chunk /= 2;
    w->hits = 0;
    u32 want = w->chunk > n ? w->chunk : n;
    if (want > w->s->size - off) want = (u32)(w->s->size - off);
    w->len = 0;
    if ((*err = gz_src_read_exact(w->s, off, w->buf, want))) return 0;
    w->base = off;
    w->len = want;
    return w->buf;
}

/* first non-zero byte at or after off (s->size when there is none) */
static int skip_zeros(win *w, u64 *off, gz_ctx *c)
{
    while (*off < w->s->size) {
        if (gz_cancelled(c)) return GZ_E_CANCEL;
        u32 n = w->s->size - *off < 65536 ? (u32)(w->s->size - *off) : 65536;
        int r = GZ_OK;
        const u8 *p = win_get(w, *off, n, &r);
        if (!p) return r;
        u32 k = 0;
        while (k < n && !p[k]) k++;
        *off += k;
        if (k < n) break;
    }
    return GZ_OK;
}

static int cpio_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    win w = { s, (u8 *)gz_alloc(WIN_CAP), 0, 0, 16384, 0 };
    if (!w.buf) return GZ_E_NOMEM;
    u64 off = 0, last = 0;
    int after = 0, r = GZ_OK;
    while (off < s->size) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        if (c->progress && off - last > (4u << 20)) { last = off; c->progress(c->progress_user, off, s->size); }
        if (after) {                         /* zero padding, maybe another archive */
            if ((r = skip_zeros(&w, &off, c)) || off >= s->size) break;
        }
        u32 avail = s->size - off < 110 ? (u32)(s->size - off) : 110;
        const u8 *h = win_get(&w, off, avail, &r);
        if (!h) break;
        int k = kind_of(h, avail);
        cpio_hdr ch;
        if (!k || avail < hsize_of(k) || parse_hdr(h, k, &ch)) {
            r = after ? GZ_OK : !k ? GZ_E_FORMAT : avail < hsize_of(k) ? GZ_E_TRUNC : GZ_E_FORMAT;
            break;
        }
        after = 0;
        u64 noff = off + ch.hsize;                       /* <= size: avail >= hsize */
        const u8 *name = win_get(&w, noff, ch.namesize, &r);
        if (!name) break;
        u64 data = noff + ch.namesize;
        data += pad_to(data, ch.align);
        if (data > s->size || ch.size > s->size - data) { r = GZ_E_TRUNC; break; }
        u64 next = data + ch.size;
        next += pad_to(next, ch.align);
        u32 nlen = name_len(name, ch.namesize);
        off = next;
        if (is_trailer(name, nlen)) { after = 1; continue; }
        int type = type_of(ch.mode);
        if (type == T_SKIP) continue;
        if ((r = add_entry(a, &ch, name, nlen, data, type))) break;
        const gz_entry *e = &a->e[a->n - 1];
        if (e->is_link && !e->usize && ch.size) {
            const u8 *tg = win_get(&w, data, (u32)ch.size, &r);
            if (!tg || (r = set_link(a, a->n - 1, tg, (u32)ch.size))) break;
        }
    }
    gz_free(w.buf);
    if (r == GZ_E_CANCEL || r == GZ_E_NOMEM) return r;
    int fr = link_fixup(a, 0);
    if (fr) return fr;
    if (r && !a->n) return r;
    return GZ_OK;                 /* tolerate a damaged tail: entries found so far */
}

/* crc format: sum the data bytes on the way out */
typedef struct { gz_out o; gz_out *in; u32 sum, want; } sum_out;

static int so_open(gz_out *o, u32 idx) { sum_out *k = (sum_out *)o; return k->in->open(k->in, idx); }
static int so_write(gz_out *o, const u8 *p, size_t n)
{
    sum_out *k = (sum_out *)o;
    k->sum += byte_sum(p, n);
    return k->in->write(k->in, p, n);
}
static int so_close(gz_out *o, u32 idx, int st)
{
    sum_out *k = (sum_out *)o;
    if (!st && k->sum != k->want) st = GZ_E_CRC;
    int r = k->in->close(k->in, idx, st);
    return st ? st : r;
}

static int cpio_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    const gz_entry *e = &a->e[idx];
    if (e->method != K_CRC || !e->usize || e->is_dir || (e->is_link && e->link_len))
        return gz_extract_stored(a, s, idx, e->off, out, c);
    sum_out k = { { so_open, so_write, so_close, 0 }, out, 0, e->aux32 };
    return gz_extract_stored(a, s, idx, e->off, &k.o, c);
}

static void cpio_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a; (void)e;
    if (cap >= 6) __builtin_memcpy(buf, "Store", 6);
}

static gz_src *cpio_view(gz_archive *a, gz_src *s, u32 idx)
{
    const gz_entry *e = &a->e[idx];
    if (e->is_dir || e->is_link) return 0;
    return gz_src_sub(s, e->off, e->usize);
}

GZ_FORMAT(gz_fmt_cpio)
const gz_format gz_fmt_cpio = {
    "CPIO", "cpio", 0, cpio_probe, cpio_open, 0, cpio_extract, 0, 0, cpio_method, cpio_view, 0
};
