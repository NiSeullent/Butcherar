/*
 * 고깃ZIP - LHA / LZH reader (LHarc, LHA, LArc, LHa for UNIX, UNLHA32 ...)
 *
 *   header levels 0, 1, 2, 3; extended headers: common CRC (0x00), file name
 *   (0x01), directory name (0x02, 0xFF separators), DOS attributes (0x40),
 *   Windows timestamps (0x41), 64-bit sizes (0x42), Unix permissions (0x50),
 *   Unix time (0x54); level-0 Unix extension area; symlinks ("name|target");
 *   methods -lh0- -lz4- -pm0- (stored), -lhd- (directory), -lh1- -lh4..7-,
 *   -lzs- -lz5-; CRC-16 of the data; SFX stubs. Names are kept raw: often
 *   Shift-JIS or another legacy code page, decoded by the core.
 */
#include "arc.h"
#include "lzh.h"

#define L3_MAX_HDR (1u << 20)
#define L1_MAX_EXT (1u << 20)

enum { M_STORE = 0, M_DIR = 0xFE, M_UNSUP = 0xFF };

static int method_id(const u8 *m)
{
    if (m[0] != '-' || m[4] != '-') return -1;
    if (m[1] == 'l' && m[2] == 'h') {
        switch (m[3]) {
        case '0': return M_STORE;
        case '1': return GZ_LZH_LH1;
        case '4': return GZ_LZH_LH4;
        case '5': return GZ_LZH_LH5;
        case '6': return GZ_LZH_LH6;
        case '7': return GZ_LZH_LH7;
        case 'd': return M_DIR;
        }
        return M_UNSUP;
    }
    if (m[1] == 'l' && m[2] == 'z') {
        if (m[3] == 's') return GZ_LZH_LZS;
        if (m[3] == '5') return GZ_LZH_LZ5;
        if (m[3] == '4') return M_STORE;
        return M_UNSUP;
    }
    if (m[1] == 'p' && m[2] == 'm') return m[3] == '0' ? M_STORE : M_UNSUP;
    if (m[1] == 'l' || m[1] == 'p') return M_UNSUP;
    return -1;
}

/* does a plausible header start at h (n bytes available)? */
static int header_ok(const u8 *h, u32 n)
{
    if (n < 24 || method_id(h + 2) < 0) return 0;
    switch (h[20]) {
    case 0: case 1: {
        u32 hs = (u32)h[0] + 2, sum = 0;
        if (h[0] < (h[20] ? 25 : 22) || h[21] + (h[20] ? 25u : 22u) > h[0] || hs > n) return 0;
        for (u32 i = 2; i < hs; i++) sum += h[i];
        return (sum & 0xff) == h[1];
    }
    case 2: return rd16(h) >= 26;
    case 3: return rd16(h) == 4;
    }
    return 0;
}

static int lzh_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (header_ok(h, n)) return 90;
    /* SFX: LHA's self-extractors put the archive after the stub */
    if (n < 2 || h[0] != 'M' || h[1] != 'Z') return 0;
    for (u32 i = 2; i + 24 <= n; i++)
        if (h[i + 2] == '-' && h[i + 3] == 'l' && h[i + 6] == '-' && header_ok(h + i, n - i)) return 70;
    return 0;
}

/* ---------------- header parsing ---------------- */

typedef struct {
    u8 *buf; u32 cap;
    /* results */
    u8 name[1024]; u32 name_len, name_set;
    u8 dir[1024]; u32 dir_len;
    u64 csize, usize;
    u64 mtime; int mtime_kind;
    u32 attr, unix_mode;
    u16 crc;
    int has_hcrc; u16 hcrc;
    int win_time;                       /* 0x41 seen: more precise than 0x54 */
    u8 os;
} lzh_hdr;

static int hbuf(lzh_hdr *x, u32 need)
{
    if (need <= x->cap) return GZ_OK;
    u32 nc = need < 4096 ? 4096 : need;
    u8 *nb = (u8 *)gz_realloc(x->buf, nc);
    if (!nb) return GZ_E_NOMEM;
    x->buf = nb;
    x->cap = nc;
    return GZ_OK;
}

static void set_bytes(u8 *dst, u32 *dl, const u8 *src, u32 n, u32 cap)
{
    if (n > cap) n = cap;
    __builtin_memcpy(dst, src, n);
    *dl = n;
}

/* one extended header: type t, data d[0..n) (data is in x->buf and may be modified) */
static void ext_header(lzh_hdr *x, u32 t, u8 *d, u32 n)
{
    switch (t) {
    case 0x00:                                   /* header CRC-16, computed with the field zeroed */
        if (n >= 2) { x->has_hcrc = 1; x->hcrc = rd16(d); d[0] = d[1] = 0; }
        break;
    case 0x01:                                   /* file name ('/' is not a separator here) */
        set_bytes(x->name, &x->name_len, d, n, sizeof x->name);
        for (u32 i = 0; i < x->name_len; i++) if (x->name[i] == '/') x->name[i] = '_';
        x->name_set = 1;
        break;
    case 0x02:                                   /* directory, 0xFF separated */
        set_bytes(x->dir, &x->dir_len, d, n, sizeof x->dir - 1);
        for (u32 i = 0; i < x->dir_len; i++) if (x->dir[i] == 0xff) x->dir[i] = '/';
        if (x->dir_len && x->dir[x->dir_len - 1] != '/') x->dir[x->dir_len++] = '/';
        break;
    case 0x40:                                   /* MS-DOS attributes */
        if (n >= 2) x->attr = rd16(d) & 0x37;
        break;
    case 0x41:                                   /* Windows FILETIMEs: create, modify, access */
        if (n >= 24 && rd64(d + 8)) { x->mtime = rd64(d + 8); x->mtime_kind = GZ_MT_FILETIME; x->win_time = 1; }
        break;
    case 0x42:                                   /* 64-bit sizes */
        if (n >= 16) { x->csize = rd64(d); x->usize = rd64(d + 8); }
        break;
    case 0x50:                                   /* Unix permissions */
        if (n >= 2) x->unix_mode = rd16(d);
        break;
    case 0x54:                                   /* Unix modification time */
        if (n >= 4 && !x->win_time) {
            x->mtime = gz_unix_to_filetime((i64)(i32)rd32(d));
            x->mtime_kind = GZ_MT_FILETIME;
        }
        break;
    }
}

/* walk the extended headers in buf[off..len): size field (fs bytes), then
 * [type][data][next size] blocks; off is the position of the first size field */
static int walk_ext(lzh_hdr *x, u32 off, u32 len, u32 fs)
{
    for (u32 k = 0; k < 65536; k++) {
        if (off + fs > len) return GZ_E_FORMAT;
        u32 sz = fs == 4 ? rd32(x->buf + off) : rd16(x->buf + off);
        if (!sz) return GZ_OK;
        if (sz < fs + 1 || sz > len - off - fs) return GZ_E_FORMAT;
        ext_header(x, x->buf[off + fs], x->buf + off + fs + 1, sz - fs - 1);
        off += sz;
    }
    return GZ_E_FORMAT;
}

/* Parse the header at pos. Returns GZ_OK (data at *data), 1 at the end of the
 * archive, or an error. */
static int parse_header(gz_src *s, u64 pos, lzh_hdr *x, u64 *data)
{
    u8 b[24];
    if (pos >= s->size) return 1;
    u32 avail = s->size - pos < 24 ? (u32)(s->size - pos) : 24;
    if (avail < 22) {
        if (avail >= 1 && gz_src_read_exact(s, pos, b, 1) == GZ_OK && b[0] == 0) return 1;
        return GZ_E_TRUNC;
    }
    int r = gz_src_read_exact(s, pos, b, avail);
    if (r) return r;
    if (b[0] == 0) return 1;                     /* end marker */
    if (method_id(b + 2) < 0) return GZ_E_FORMAT;
    x->name_len = x->dir_len = x->name_set = 0;
    x->mtime = 0; x->mtime_kind = GZ_MT_NONE;
    x->attr = 0; x->unix_mode = 0;
    x->has_hcrc = 0;
    x->win_time = 0;
    x->os = 0;
    u32 level = b[20], hlen;
    switch (level) {
    case 0: case 1: {
        hlen = (u32)b[0] + 2;
        u32 minl = level ? 25 : 22;
        if (b[0] < minl) return GZ_E_FORMAT;
        if ((r = hbuf(x, hlen + 8))) return r;
        if ((r = gz_src_read_exact(s, pos, x->buf, hlen))) return r;
        const u8 *h = x->buf;
        u32 sum = 0;
        for (u32 i = 2; i < hlen; i++) sum += h[i];
        if ((sum & 0xff) != h[1]) return GZ_E_FORMAT;
        u32 nl = h[21];
        if (minl + nl > h[0]) return GZ_E_FORMAT;
        x->csize = rd32(h + 7);
        x->usize = rd32(h + 11);
        x->mtime = rd32(h + 15);
        x->mtime_kind = GZ_MT_DOS;
        x->attr = h[19] & 0x37;
        set_bytes(x->name, &x->name_len, h + 22, nl, sizeof x->name);
        x->crc = rd16(h + 22 + nl);
        if (level == 0) {
            /* optional extension area: OS id, then for Unix: version 0, time, mode, uid, gid */
            u32 xl = h[0] - 22 - nl;
            const u8 *xa = h + 24 + nl;
            if (xl >= 12 && xa[0] == 'U' && xa[1] == 0) {
                x->os = 'U';
                x->mtime = gz_unix_to_filetime((i64)(i32)rd32(xa + 2));
                x->mtime_kind = GZ_MT_FILETIME;
                x->unix_mode = rd16(xa + xl - 6);
            }
            *data = pos + hlen;
            return GZ_OK;
        }
        x->os = h[24 + nl];
        /* level 1: extended headers follow the base header and count as compressed data */
        u32 len = hlen;
        u64 p = pos + hlen;
        for (;;) {
            u32 nx = rd16(x->buf + len - 2);
            if (!nx) break;
            if (nx < 3 || nx > x->csize || len + nx > L1_MAX_EXT) return GZ_E_FORMAT;
            x->csize -= nx;
            if ((r = hbuf(x, len + nx + 8))) return r;
            if ((r = gz_src_read_exact(s, p, x->buf + len, nx))) return r;
            len += nx;
            p += nx;
        }
        if ((r = walk_ext(x, hlen - 2, len, 2))) return r;
        if (x->has_hcrc && gz_crc16(0, x->buf, len) != x->hcrc) return GZ_E_FORMAT;
        *data = p;
        return GZ_OK;
    }
    case 2: {
        hlen = rd16(b);
        if (hlen < 26) return GZ_E_FORMAT;
        if ((r = hbuf(x, hlen + 8))) return r;
        if ((r = gz_src_read_exact(s, pos, x->buf, hlen))) return r;
        const u8 *h = x->buf;
        x->os = h[23];
        u32 tot = hlen;
        if (x->os == 'K') {                       /* OS-9/68K LHa writes 2 extra bytes */
            if ((r = gz_src_read_exact(s, pos + hlen, x->buf + hlen, 2))) return r;
            tot += 2;
        }
        x->csize = rd32(h + 7);
        x->usize = rd32(h + 11);
        x->mtime = gz_unix_to_filetime((i64)(i32)rd32(h + 15));
        x->mtime_kind = GZ_MT_FILETIME;
        x->crc = rd16(h + 21);
        if ((r = walk_ext(x, 24, tot, 2))) return r;
        if (x->has_hcrc && gz_crc16(0, x->buf, tot) != x->hcrc) return GZ_E_FORMAT;
        *data = pos + tot;
        return GZ_OK;
    }
    case 3: {
        if (rd16(b) != 4) return GZ_E_FORMAT;
        u8 h3[32];
        if ((r = gz_src_read_exact(s, pos, h3, 32))) return r;
        hlen = rd32(h3 + 24);
        if (hlen < 32 || hlen > L3_MAX_HDR) return GZ_E_FORMAT;
        if ((r = hbuf(x, hlen + 8))) return r;
        if ((r = gz_src_read_exact(s, pos, x->buf, hlen))) return r;
        const u8 *h = x->buf;
        x->os = h[23];
        x->csize = rd32(h + 7);
        x->usize = rd32(h + 11);
        x->mtime = gz_unix_to_filetime((i64)(i32)rd32(h + 15));
        x->mtime_kind = GZ_MT_FILETIME;
        x->crc = rd16(h + 21);
        if ((r = walk_ext(x, 28, hlen, 4))) return r;
        if (x->has_hcrc && gz_crc16(0, x->buf, hlen) != x->hcrc) return GZ_E_FORMAT;
        *data = pos + hlen;
        return GZ_OK;
    }
    }
    return GZ_E_FORMAT;
}

static int lzh_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    u64 pos = 0;
    {
        u8 head[256];
        u32 n = s->size < sizeof head ? (u32)s->size : (u32)sizeof head;
        int r = gz_src_read_exact(s, 0, head, n);
        if (r) return r;
        if (!header_ok(head, n)) {
            /* SFX: find the first header in the first 64 KiB */
            u32 max = s->size < 65536 + 512 ? (u32)s->size : 65536 + 512;
            u8 *buf = (u8 *)gz_alloc(max);
            if (!buf) return GZ_E_NOMEM;
            r = gz_src_read_exact(s, 0, buf, max);
            u32 i = 1;
            for (; !r && i + 24 <= max; i++)
                if (buf[i + 2] == '-' && buf[i + 3] == 'l' && buf[i + 6] == '-' && header_ok(buf + i, max - i)) break;
            int found = !r && i + 24 <= max;
            gz_free(buf);
            if (!found) return r ? r : GZ_E_FORMAT;
            pos = i;
            a->sfx_shift = pos;
        }
    }
    lzh_hdr *x = (lzh_hdr *)gz_alloc(sizeof(lzh_hdr));
    if (!x) return GZ_E_NOMEM;
    int r = GZ_OK, dos = 0;
    u8 meth[5];
    for (;;) {
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        u64 data;
        r = parse_header(s, pos, x, &data);
        if (r == 1) { r = GZ_OK; break; }
        if (r) break;
        if (gz_src_read_exact(s, pos + 2, meth, 5)) { r = GZ_E_TRUNC; break; }
        int mid = method_id(meth);
        if (data + x->csize > s->size || data + x->csize < data) { r = GZ_E_TRUNC; break; }
        pos = data + x->csize;
        if (x->os == 0 || x->os == 'M' || x->os == 'w' || x->os == 'W' || x->os == '2') dos = 1;

        /* full name = directory + file name */
        u8 full[2048];
        u32 fl = 0;
        __builtin_memcpy(full, x->dir, x->dir_len);
        fl = x->dir_len;
        __builtin_memcpy(full + fl, x->name, x->name_len);
        fl += x->name_len;
        for (u32 i = 0; i < fl; i++) if (full[i] == 0xff) full[i] = '/';
        int is_dir = mid == M_DIR;
        u32 link_at = 0;
        if (is_dir && (x->unix_mode & 0170000) == 0120000) {
            for (u32 i = 0; i < fl; i++) if (full[i] == '|') { link_at = i + 1; break; }
            if (link_at) is_dir = 0;
        }
        gz_entry *e;
        if ((r = gz_arc_add_named(a, full, link_at ? link_at - 1 : fl, GZ_NE_LEGACY, &e))) break;
        if (link_at) {
            u32 lo;
            if ((r = gz_arc_raw_append(a, full + link_at, fl - link_at, &lo))) break;
            e = &a->e[a->n - 1];
            e->link_off = lo;
            e->link_len = fl - link_at;
            e->is_link = 1;
        }
        e->off = data;
        e->csize = x->csize;
        e->usize = (is_dir || link_at) ? 0 : x->usize;
        e->mtime = x->mtime;
        e->mtime_kind = (u8)x->mtime_kind;
        e->attr = x->attr;
        e->unix_mode = x->unix_mode;
        e->aux32 = x->crc;
        e->method = (u16)mid;
        __builtin_memcpy(&e->aux, meth, 5);
        e->is_dir = (u8)is_dir;
        if (is_dir) e->attr |= 0x10;
        if (!is_dir && e->unix_mode && (e->unix_mode & 0170000) == 0) e->unix_mode |= 0100000;
    }
    gz_free(x->buf);
    gz_free(x);
    if (r == GZ_E_NOMEM || r == GZ_E_CANCEL) return r;
    if (a->n == 0) return r ? r : GZ_E_FORMAT;
    a->win_names = dos;
    return GZ_OK;                 /* damaged tail: keep what was listed */
}

/* ---------------- extraction ---------------- */

typedef struct { gz_pipe pp; u16 crc; u64 n; } lzh_sink;

static int lsink_write(void *ctx, const u8 *p, size_t n)
{
    lzh_sink *k = (lzh_sink *)ctx;
    k->crc = gz_crc16(k->crc, p, n);
    k->n += n;
    return k->pp.sink(k->pp.user, p, n);
}

static int out_write(void *user, const u8 *p, size_t n)
{
    gz_out *o = (gz_out *)user;
    return o->write(o, p, n);
}

static int lzh_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    gz_entry *e = &a->e[idx];
    if (!e->is_dir && !e->is_link && e->method == M_UNSUP) return GZ_E_METHOD;
    int r = out->open(out, idx);
    if (r) return r;
    int st = GZ_OK;
    if (!e->is_dir && !e->is_link && e->usize) {
        lzh_sink k;
        __builtin_memset(&k, 0, sizeof k);
        k.pp.rd.src = s;
        k.pp.rd.pos = e->off;
        k.pp.rd.end = e->off + e->csize;
        k.pp.rd.cancel = c->cancel;
        k.pp.sink = out_write;
        k.pp.user = out;
        gz_stream_io io = { gz_range_read, lsink_write, &k };
        if (e->method == M_STORE) {
            u8 *buf = gz_ctx_buffer(c, 256u << 10);
            if (!buf) st = GZ_E_NOMEM;
            u64 left = e->usize < e->csize ? e->usize : e->csize;
            while (!st && left) {
                u32 got = 0;
                st = gz_range_read(&k.pp.rd, buf, left < (256u << 10) ? (u32)left : (256u << 10), &got);
                if (!st && !got) st = GZ_E_TRUNC;
                if (!st) st = lsink_write(&k, buf, got);
                left -= got;
            }
            if (!st && k.n != e->usize) st = GZ_E_TRUNC;
        } else {
            gz_lzh_dec *d = (gz_lzh_dec *)gz_ctx_slot(c, GZ_SLOT_MISC4, gz_lzh_slot_new, gz_lzh_slot_free);
            st = d ? gz_lzh_decode(d, &io, e->usize, e->method) : GZ_E_NOMEM;
        }
        if (!st && k.crc != (u16)e->aux32) st = GZ_E_CRC;
    }
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static void lzh_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    u8 m[5];
    __builtin_memcpy(m, &e->aux, 5);
    u32 i = 0;
    for (u32 k = 1; k < 4 && i + 1 < cap; k++) {
        u8 ch = m[k];
        buf[i++] = (char)(ch >= 'a' && ch <= 'z' ? ch - 32 : (ch >= 0x20 && ch < 0x7f ? ch : '?'));
    }
    if (cap) buf[i] = 0;
}

static gz_src *lzh_view(gz_archive *a, gz_src *s, u32 idx)
{
    gz_entry *e = &a->e[idx];
    if (e->is_dir || e->is_link || e->method != M_STORE || e->usize > e->csize) return 0;
    if (e->off + e->usize > s->size) return 0;
    return gz_src_sub(s, e->off, e->usize);
}

GZ_FORMAT(gz_fmt_lzh)
const gz_format gz_fmt_lzh = {
    "LZH", "lzh lha lzs",
    0, lzh_probe, lzh_open, 0, lzh_extract, 0, 0, lzh_method, lzh_view, 0
};
