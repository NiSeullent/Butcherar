/*
 * 고깃ZIP - Microsoft single-file compression: "SZDD" (compress.exe / expand.exe,
 * SETUP.EX_), QBasic 4.5 "SZ", and "KWAJ" (methods: none, XOR, SZDD LZSS,
 * LZ+Huffman, MS-ZIP).
 *
 * The original file name is restored: SZDD keeps the replaced last character of
 * the name in its header ("SETUP.EX_" + 'E' = "SETUP.EXE"), KWAJ may store the
 * name and extension.
 */
#include "arc.h"
#include "lzh.h"

enum { K_SZDD = 1, K_SZQB, K_KWAJ };
enum { KW_NONE = 0, KW_XOR, KW_SZDD, KW_LZH, KW_MSZIP };

static const u8 sig_szdd[8] = { 'S', 'Z', 'D', 'D', 0x88, 0xF0, 0x27, 0x33 };
static const u8 sig_szqb[8] = { 'S', 'Z', ' ', 0x88, 0xF0, 0x27, 0x33, 0xD1 };
static const u8 sig_kwaj[8] = { 'K', 'W', 'A', 'J', 0x88, 0xF0, 0x27, 0xD1 };

static int kind_of(const u8 *h, u32 n)
{
    if (n < 12) return 0;
    if (!__builtin_memcmp(h, sig_szdd, 8) && n >= 14) return K_SZDD;
    if (!__builtin_memcmp(h, sig_szqb, 8)) return K_SZQB;
    if (!__builtin_memcmp(h, sig_kwaj, 8) && n >= 14) return K_KWAJ;
    return 0;
}

static int mslz_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    int k = kind_of(h, n);
    if (k == K_KWAJ) return rd16(h + 8) <= KW_MSZIP && rd16(h + 10) >= 14 ? 95 : 0;
    return k ? 95 : 0;
}

/* archive base name (UTF-8) */
static u32 base_name(const gz_open_opts *o, u8 *out, u32 cap)
{
    const gzch *fn = o->file_name;
    if (!fn) return 0;
    const gzch *b1 = gz_wcsrchr(fn, '\\'), *b2 = gz_wcsrchr(fn, '/');
    const gzch *b = b1 > b2 ? b1 + 1 : (b2 ? b2 + 1 : fn);
    size_t n = gz_wcslen(b);
    if (n > cap / 3) n = cap / 3;
    return (u32)gz_utf16_to_utf8(b, n, out);
}

/* "SETUP.EX_" + 'E' -> "SETUP.EXE" (as 7-Zip, plus matching the name's case) */
static u32 szdd_name(u8 *nm, u32 n, u8 repl)
{
    if (!n || nm[n - 1] != '_') return n;
    n--;
    if (!repl && n >= 3 && nm[n - 3] == '.') {
        static const char ext[6][4] = { "bin", "dll", "exe", "kmd", "pdf", "sys" };
        for (u32 i = 0; i < 6; i++)
            if ((nm[n - 2] | 0x20) == (u8)ext[i][0] && (nm[n - 1] | 0x20) == (u8)ext[i][1]) {
                repl = (u8)ext[i][2];
                if (nm[n - 1] >= 'A' && nm[n - 1] <= 'Z') repl -= 32;
                break;
            }
    }
    if (repl >= 0x20 && repl < 0x80) {
        if (repl >= 'A' && repl <= 'Z' && n && nm[n - 1] >= 'a' && nm[n - 1] <= 'z') repl += 32;
        nm[n++] = repl;
    }
    if (n && nm[n - 1] == '.') n--;
    return n;
}

static int mslz_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)c;
    u8 h[64];
    u32 hn = s->size < sizeof h ? (u32)s->size : (u32)sizeof h;
    int r = gz_src_read_exact(s, 0, h, hn);
    if (r) return r;
    int kind = kind_of(h, hn);
    if (!kind) return GZ_E_FORMAT;
    u8 name[1100];
    u32 nl = base_name(o, name, 1024);
    u64 data, usize = GZ_SIZE_UNKNOWN;
    u32 method = 0;
    int ne = GZ_NE_UTF8;                 /* derived from the archive name */
    if (kind == K_SZDD) {
        usize = rd32(h + 10);
        data = 14;
        nl = szdd_name(name, nl, h[9]);
    } else if (kind == K_SZQB) {
        usize = rd32(h + 8);
        data = 12;
        nl = szdd_name(name, nl, 0);
    } else {
        method = rd16(h + 8);
        data = rd16(h + 10);
        u32 fl = rd16(h + 12), p = 14;
        if (method > KW_MSZIP) return GZ_E_METHOD;
        u8 x[2 + 9 + 4 + 16];
        u32 xn = s->size - p < sizeof x ? (u32)(s->size - p) : (u32)sizeof x;
        if (fl & 1) {
            if (gz_src_read_exact(s, p, x, 4)) return GZ_E_TRUNC;
            usize = rd32(x);
            p += 4;
        }
        if (fl & 2) p += 2;
        if (fl & 4) {
            if (gz_src_read_exact(s, p, x, 2)) return GZ_E_TRUNC;
            p += 2 + rd16(x);
        }
        if (fl & 0x18) {
            /* stored name (up to 8 chars) and extension (up to 3), NUL terminated */
            u32 kn = 0;
            u8 kname[16];
            for (int part = 0; part < 2; part++) {
                if (!(fl & (part ? 0x10 : 0x08))) continue;
                u32 max = part ? 4 : 9;
                xn = s->size > p ? (s->size - p < max ? (u32)(s->size - p) : max) : 0;
                if (xn < 1 || gz_src_read_exact(s, p, x, xn)) return GZ_E_TRUNC;
                u32 i = 0;
                while (i < xn && x[i]) i++;
                if (i == xn && i == max) return GZ_E_FORMAT;
                if (part) kname[kn++] = '.';
                __builtin_memcpy(kname + kn, x, i);
                kn += i;
                p += i + 1;
            }
            if (kn && !(kn == 1 && kname[0] == '.')) {
                __builtin_memcpy(name, kname, kn);
                nl = kn;
                ne = GZ_NE_OEM;
            }
        } else if (nl && name[nl - 1] == '_') {
            nl--;                     /* "FILE.EX_" without a stored name */
        }
        if (data > s->size) return GZ_E_TRUNC;
    }
    if (!nl) { __builtin_memcpy(name, "data", 4); nl = 4; }
    if (data > s->size) return GZ_E_TRUNC;
    gz_entry *e;
    r = gz_arc_add_named(a, name, nl, ne, &e);
    if (r) return r;
    e->off = data;
    e->csize = s->size - data;
    e->usize = usize;
    e->method = (u16)(kind << 8 | method);
    e->attr = 0x20;
    if (kind == K_KWAJ) gz_arc_set_type(a, "KWAJ");
    else gz_arc_set_type(a, "SZDD");
    return GZ_OK;
}

/* ---------------- extraction ---------------- */

typedef struct { gz_range_reader rd; gz_out *out; u64 n; int xorff; } ms_io;

static int ms_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    ms_io *x = (ms_io *)ctx;
    int r = gz_range_read(&x->rd, buf, cap, got);
    if (!r && x->xorff) for (u32 i = 0; i < *got; i++) buf[i] ^= 0xff;
    return r;
}

static int ms_write(void *ctx, const u8 *p, size_t n)
{
    ms_io *x = (ms_io *)ctx;
    x->n += n;
    return x->out->write(x->out, p, n);
}


/* KWAJ MS-ZIP (as libmspack): blocks of [len16]['C''K'][deflate stream] until a
 * zero length; each block may refer to the previous 32 KiB of output. The length
 * field is not trusted: the next block starts at the byte after the deflate stream. */
typedef struct {
    gz_range_reader rd;      /* first: gz_range_read casts the ctx */
    gz_out *out;
    u8 *hist;                /* last 32 KiB of output */
    u32 hist_len;
    u64 n, limit;            /* limit: stored length (GZ_SIZE_UNKNOWN: none) */
} mz_io;

static int mz_write(void *ctx, const u8 *p, size_t n)
{
    mz_io *m = (mz_io *)ctx;
    if (m->limit != GZ_SIZE_UNKNOWN && n > m->limit - m->n) return GZ_E_DATA;   /* longer than stored */
    if (n >= GZ_INFLATE_DICT_MAX) {
        __builtin_memcpy(m->hist, p + n - GZ_INFLATE_DICT_MAX, GZ_INFLATE_DICT_MAX);
        m->hist_len = GZ_INFLATE_DICT_MAX;
    } else {
        u32 keep = m->hist_len + (u32)n > GZ_INFLATE_DICT_MAX ? GZ_INFLATE_DICT_MAX - (u32)n : m->hist_len;
        __builtin_memmove(m->hist, m->hist + m->hist_len - keep, keep);
        __builtin_memcpy(m->hist + keep, p, n);
        m->hist_len = keep + (u32)n;
    }
    m->n += n;
    return m->out->write(m->out, p, n);
}

static int kwaj_mszip(gz_src *s, u64 pos, u64 usize, gz_out *out, gz_ctx *c, u64 *produced)
{
    gz_inflater *z = gz_ctx_inflater(c);
    u8 *hist = (u8 *)gz_alloc(GZ_INFLATE_DICT_MAX);
    if (!z || !hist) { gz_free(hist); return GZ_E_NOMEM; }
    mz_io m;
    __builtin_memset(&m, 0, sizeof m);
    m.out = out;
    m.hist = hist;
    m.limit = usize;
    m.rd.src = s;
    m.rd.end = s->size;
    m.rd.cancel = c->cancel;
    int st = GZ_OK;
    for (;;) {
        u8 b[4];
        if (pos + 2 > s->size) break;                 /* missing terminator: tolerated */
        if ((st = gz_src_read_exact(s, pos, b, 2))) break;
        if (rd16(b) == 0) break;
        if ((st = gz_src_read_exact(s, pos + 2, b, 2))) break;
        if (b[0] != 'C' || b[1] != 'K') { st = GZ_E_DATA; break; }
        /* the inflater copies the history into its window before the sink updates it */
        m.rd.pos = pos + 4;
        gz_stream_io io = { gz_range_read, mz_write, &m };
        st = gz_inflate_run_dict(z, &io, m.hist, m.hist_len);
        if (st) break;
        if (m.rd.pos < (u64)z->rest_len + pos + 4) { st = GZ_E_DATA; break; }
        pos = m.rd.pos - z->rest_len;                 /* strictly increasing: >= 1 byte consumed */
    }
    gz_free(hist);
    *produced = m.n;
    return st;
}

static int mslz_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    gz_entry *e = &a->e[idx];
    int kind = e->method >> 8, method = e->method & 0xff;
    int r = out->open(out, idx);
    if (r) return r;
    ms_io x;
    __builtin_memset(&x, 0, sizeof x);
    x.rd.src = s;
    x.rd.pos = e->off;
    x.rd.end = s->size;
    x.rd.cancel = c->cancel;
    x.out = out;
    gz_stream_io io = { ms_read, ms_write, &x };
    int st;
    int lzh = kind == K_SZDD ? GZ_LZH_SZDD : kind == K_SZQB ? GZ_LZH_SZQB :
              method == KW_SZDD ? GZ_LZH_SZQB : method == KW_LZH ? GZ_LZH_KWAJ : 0;  /* as libmspack */
    if (lzh) {
        gz_lzh_dec *d = (gz_lzh_dec *)gz_ctx_slot(c, GZ_SLOT_MISC4, gz_lzh_slot_new, gz_lzh_slot_free);
        st = d ? gz_lzh_decode(d, &io, e->usize, lzh) : GZ_E_NOMEM;
    } else if (method == KW_MSZIP) {
        u64 n = 0;
        st = kwaj_mszip(s, e->off, e->usize, out, c, &n);
        x.n = n;
        if (!st && e->usize != GZ_SIZE_UNKNOWN && n != e->usize) st = GZ_E_DATA;
    } else {
        /* stored or XOR 0xFF */
        x.xorff = method == KW_XOR;
        u8 *buf = gz_ctx_buffer(c, 256u << 10);
        st = buf ? GZ_OK : GZ_E_NOMEM;
        u64 left = e->usize == GZ_SIZE_UNKNOWN ? e->csize : e->usize;
        if (left > e->csize) st = GZ_E_TRUNC;
        while (!st && left) {
            u32 got = 0;
            st = ms_read(&x, buf, left < (256u << 10) ? (u32)left : (256u << 10), &got);
            if (!st && !got) st = GZ_E_TRUNC;
            if (!st) st = ms_write(&x, buf, got);
            left -= got;
        }
    }
    if (!st && e->usize == GZ_SIZE_UNKNOWN) e->usize = x.n;
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static void mslz_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    static const char *const kw[5] = { "Store", "XOR", "LZSS", "LZH", "MSZIP" };
    int kind = e->method >> 8, m = e->method & 0xff;
    const char *t = kind == K_KWAJ ? (m < 5 ? kw[m] : "?") : "LZSS";
    u32 i = 0;
    for (; *t && i + 1 < cap; t++) buf[i++] = *t;
    if (cap) buf[i] = 0;
}

GZ_FORMAT(gz_fmt_mslz)
const gz_format gz_fmt_mslz = {
    "SZDD", "ex_ dl_ sy_ in_ hl_ tx_ cp_ ch_ bm_ fo_ dr_ ov_ 38_",
    0, mslz_probe, mslz_open, 0, mslz_extract, 0, 0, mslz_method, 0, 0
};
