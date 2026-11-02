/*
 * 고깃ZIP - RPM packages
 *
 * 96-byte lead, signature header (padded to 8 bytes), main header, payload.
 * Headers: magic 8E AD E8 01, 4 reserved bytes, index count and data size
 * (big endian), 16-byte index entries (tag, type, offset, count), data store.
 * The payload is a cpio archive (newc), compressed with whatever the
 * PAYLOADCOMPRESSOR tag says (gzip, bzip2, xz, lzma, zstd ...): it is decoded
 * by the registered stream format that recognises it, and its cpio entries are
 * listed directly (solid: one decoding pass per extraction).
 */
#include "cpio.h"

#define RPM_TAGS_MAX 0xffffu          /* rpm's own sanity limits (hdrchkTags / hdrchkData) */
#define RPM_DATA_MAX (256u << 20)

enum {
    TAG_NAME = 1000, TAG_VERSION = 1001, TAG_RELEASE = 1002, TAG_SUMMARY = 1004,
    TAG_ARCH = 1022, TAG_PAYLOADFORMAT = 1124, TAG_PAYLOADCOMPRESSOR = 1125
};
enum { RPM_STRING = 6, RPM_I18NSTRING = 9 };

typedef struct {
    u64 pay_off;                      /* payload start in the package */
    const gz_stream_codec *codec;     /* NULL: uncompressed cpio      */
} rpm_priv;

typedef struct {
    u8 *buf;                          /* index entries + data store */
    u32 il, dl;
} rpm_hdr;

/* read the header structure at off; *end = first byte after it */
static int read_header(gz_src *s, u64 off, rpm_hdr *h, u64 *end, int keep)
{
    u8 b[16];
    int r = gz_src_read_exact(s, off, b, 16);
    if (r) return r;
    if (b[0] != 0x8E || b[1] != 0xAD || b[2] != 0xE8 || b[3] != 0x01) return GZ_E_FORMAT;
    u32 il = rd32be(b + 8), dl = rd32be(b + 12);
    if (il > RPM_TAGS_MAX || dl > RPM_DATA_MAX) return GZ_E_LIMIT;
    u64 len = (u64)il * 16 + dl;
    if (len > s->size - off - 16) return GZ_E_TRUNC;
    *end = off + 16 + len;
    h->il = il;
    h->dl = dl;
    h->buf = 0;
    if (!keep) return GZ_OK;
    h->buf = (u8 *)gz_alloc((size_t)len + 1);
    if (!h->buf) return GZ_E_NOMEM;
    r = gz_src_read_exact(s, off + 16, h->buf, (u32)len);
    if (r) { gz_free(h->buf); h->buf = 0; }
    return r;
}

/* first string of a STRING / I18NSTRING tag, NULL if absent or malformed */
static const u8 *tag_str(const rpm_hdr *h, u32 tag, u32 *len)
{
    const u8 *store = h->buf + (size_t)h->il * 16;
    for (u32 i = 0; i < h->il; i++) {
        const u8 *ie = h->buf + (size_t)i * 16;
        if (rd32be(ie) != tag) continue;
        u32 type = rd32be(ie + 4), off = rd32be(ie + 8);
        if ((type != RPM_STRING && type != RPM_I18NSTRING) || off >= h->dl) return 0;
        u32 n = 0;
        while (off + n < h->dl && store[off + n]) n++;
        if (off + n >= h->dl) return 0;               /* not NUL terminated */
        *len = n;
        return store + off;
    }
    return 0;
}

static int str_is(const u8 *p, u32 n, const char *z)
{
    u32 i = 0;
    for (; i < n && z[i]; i++) if (p[i] != (u8)z[i]) return 0;
    return i == n && !z[i];
}

/* "name-version-release.arch\nsummary" as the archive comment */
static void set_comment(gz_archive *a, const rpm_hdr *h)
{
    u32 ln[5] = { 0 };
    const u8 *p[5];
    static const u32 tags[5] = { TAG_NAME, TAG_VERSION, TAG_RELEASE, TAG_ARCH, TAG_SUMMARY };
    static const char sep[5] = { 0, '-', '-', '.', '\n' };
    u32 total = 0;
    for (int i = 0; i < 5; i++) {
        p[i] = tag_str(h, tags[i], &ln[i]);
        if (!p[i]) ln[i] = 0;
        if (ln[i] > 4096) ln[i] = 4096;
        total += ln[i] + 1;
    }
    if (!ln[0]) return;
    u8 *c = (u8 *)gz_alloc(total + 1);
    if (!c) return;
    u32 k = 0;
    for (int i = 0; i < 5; i++) {
        if (!ln[i]) continue;
        if (sep[i]) c[k++] = (u8)sep[i];
        __builtin_memcpy(c + k, p[i], ln[i]);
        k += ln[i];
    }
    gz_free(a->comment_raw);
    a->comment_raw = c;
    a->comment_len = k;
    a->comment_enc = GZ_NE_UTF8;
}

static int rpm_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 96 + 16 || h[0] != 0xED || h[1] != 0xAB || h[2] != 0xEE || h[3] != 0xDB) return 0;
    if (h[4] < 3 || h[4] > 4) return 0;
    if (h[96] != 0x8E || h[97] != 0xAD || h[98] != 0xE8 || h[99] != 0x01) return 50;
    return 95;
}

/* source wrapper reporting read progress while a big payload is listed */
typedef struct { gz_src s; gz_src *inner; gz_ctx *c; u64 last; } prog_src;

static int prog_read(gz_src *s, u64 off, void *buf, u32 n, u32 *got)
{
    prog_src *p = (prog_src *)s;
    if (p->c->progress && (off > p->last + (4u << 20) || off < p->last)) {
        p->last = off;
        p->c->progress(p->c->progress_user, off, s->size);
    }
    return p->inner->read_at(p->inner, off, buf, n, got);
}

static gz_decode_fn decoder_of(const rpm_priv *pv)
{
    return pv->codec ? pv->codec->decode : gz_stream_copy;
}

static int rpm_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    u8 lead[96];
    int r = gz_src_read_exact(s, 0, lead, 96);
    if (r) return r;
    if (lead[0] != 0xED || lead[1] != 0xAB || lead[2] != 0xEE || lead[3] != 0xDB) return GZ_E_FORMAT;
    if (rd16be(lead + 78) != 5) return GZ_E_METHOD;        /* old (pre-header) signatures */

    rpm_hdr sig, hdr;
    u64 sig_end, hdr_end;
    if ((r = read_header(s, 96, &sig, &sig_end, 0))) return r;
    sig_end = (sig_end + 7) & ~(u64)7;
    if ((r = read_header(s, sig_end, &hdr, &hdr_end, 1))) return r;

    u32 n = 0;
    const u8 *pf = tag_str(&hdr, TAG_PAYLOADFORMAT, &n);
    if (pf && !str_is(pf, n, "cpio")) { gz_free(hdr.buf); return GZ_E_METHOD; }   /* drpm, ... */
    set_comment(a, &hdr);
    gz_free(hdr.buf);

    rpm_priv *pv = (rpm_priv *)gz_alloc(sizeof(rpm_priv));
    if (!pv) return GZ_E_NOMEM;
    a->priv = pv;
    pv->pay_off = hdr_end;
    if (hdr_end >= s->size) return GZ_E_TRUNC;

    gz_src *pay = gz_src_sub(s, hdr_end, s->size - hdr_end);
    if (!pay) return GZ_E_NOMEM;
    u8 m[6];
    r = gz_src_read_exact(pay, 0, m, pay->size < 6 ? (u32)pay->size : 6);
    if (!r && gz_cpio_magic(m, pay->size < 6 ? (u32)pay->size : 6)) pv->codec = 0;
    else if (!r && !(pv->codec = gz_stream_codec_find(pay))) r = GZ_E_METHOD;   /* codec not available */
    if (!r) {
        prog_src ps = { { prog_read, pay->size, 0, 0 }, pay, c, 0 };
        r = gz_cpio_list_stream(a, &ps.s, decoder_of(pv), c);
    }
    gz_src_free(pay);
    if (r) return r;
    a->solid = 1;
    return GZ_OK;
}

static void rpm_close(gz_archive *a)
{
    gz_free(a->priv);
    a->priv = 0;
}

static int rpm_extract_solid(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_ctx *c)
{
    const rpm_priv *pv = (const rpm_priv *)a->priv;
    if (pv->pay_off >= s->size) return GZ_E_TRUNC;
    gz_src *pay = gz_src_sub(s, pv->pay_off, s->size - pv->pay_off);
    if (!pay) return GZ_E_NOMEM;
    int r = gz_cpio_extract_stream(a, pay, decoder_of(pv), sel, out, c);
    gz_src_free(pay);
    return r;
}

static int rpm_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    u8 *sel = (u8 *)gz_alloc(a->n + 1);
    if (!sel) return GZ_E_NOMEM;
    sel[idx] = 1;
    int r = rpm_extract_solid(a, s, sel, out, c);
    gz_free(sel);
    return r;
}

static void rpm_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)e;
    const rpm_priv *pv = (const rpm_priv *)a->priv;
    const char *m = pv && pv->codec && pv->codec->method ? pv->codec->method : "Store";
    u32 i = 0;
    for (; m[i] && i + 1 < cap; i++) buf[i] = m[i];
    if (cap) buf[i] = 0;
}

GZ_FORMAT(gz_fmt_rpm)
const gz_format gz_fmt_rpm = {
    "RPM", "rpm", 0, rpm_probe, rpm_open, rpm_close, rpm_extract, rpm_extract_solid, 0, rpm_method, 0, 0
};
