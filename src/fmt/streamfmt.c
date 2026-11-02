/*
 * 고깃ZIP - shared code for single-stream compressed files and tarballs / cpio
 * archives inside them
 */
#include "streamfmt.h"
#include "tar.h"
#include "cpio.h"

typedef struct { int is_tar, is_cpio; } sfmt_priv;

static const gz_stream_codec *codec_of(const gz_archive *a)
{
    return (const gz_stream_codec *)a->fmt->impl;
}

/* source wrapper reporting read progress while a long tarball is listed */
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

typedef struct { gz_tar_parser *t; } tar_sink;

static int tar_sink_write(void *u, const u8 *p, size_t n)
{
    tar_sink *k = (tar_sink *)u;
    int r = gz_tar_feed(k->t, p, n);
    if (r) return r;
    return gz_tar_done(k->t) ? GZ_E_SKIP : GZ_OK;
}

/* does s (a file name) end with ".ext" for one of the space separated exts? returns length of match */
static size_t ext_match(const gzch *name, size_t n, const char *exts)
{
    if (!exts) return 0;
    const char *p = exts;
    while (*p) {
        while (*p == ' ') p++;
        const char *q = p;
        while (*q && *q != ' ') q++;
        size_t m = (size_t)(q - p);
        if (m && m + 1 < n && name[n - m - 1] == '.') {
            size_t k = 0;
            for (; k < m; k++) {
                gzch c = name[n - m + k];
                if (c >= 'A' && c <= 'Z') c += 32;
                if (c != (gzch)(u8)p[k]) break;
            }
            if (k == m) return m + 1;
        }
        p = q;
    }
    return 0;
}

/* entry name for a single compressed file without a stored name */
static int derive_name(gz_archive *a, const gz_open_opts *o, gz_entry **pe)
{
    const gz_stream_codec *codec = codec_of(a);
    const gzch *fn = o->file_name ? o->file_name : u"data";
    const gzch *b1 = gz_wcsrchr(fn, '\\'), *b2 = gz_wcsrchr(fn, '/');
    const gzch *base = b1 > b2 ? b1 + 1 : (b2 ? b2 + 1 : fn);
    size_t bl = gz_wcslen(base);
    int tarball = 0;
    size_t m = ext_match(base, bl, codec->tar_exts);
    if (m) { bl -= m; tarball = 1; }
    else if ((m = ext_match(base, bl, a->fmt->exts))) bl -= m;
    else {
        /* unknown extension: keep the name, add a marker so it differs from the archive */
        tarball = 2;
    }
    u8 tmp[1024];
    int tn = gz_utf16_to_utf8(base, bl > 300 ? 300 : bl, tmp);
    if (tarball == 1) { __builtin_memcpy(tmp + tn, ".tar", 4); tn += 4; }
    else if (tarball == 2) { __builtin_memcpy(tmp + tn, ".out", 4); tn += 4; }
    if (!tn) { __builtin_memcpy(tmp, "data", 4); tn = 4; }
    return gz_arc_add_named(a, tmp, (u32)tn, GZ_NE_UTF8, pe);
}

int gz_sfmt_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    const gz_stream_codec *codec = codec_of(a);
    sfmt_priv *pv = (sfmt_priv *)gz_alloc(sizeof(sfmt_priv));
    if (!pv) return GZ_E_NOMEM;
    a->priv = pv;

    /* is it a tarball? peek at the first decompressed block */
    u8 pk[512];
    gz_peek_sink peek = { pk, 512, 0 };
    int r = codec->decode(s, gz_peek_write, &peek, c);
    if (r == GZ_E_CANCEL || r == GZ_E_NOMEM) return r;
    if (r && r != GZ_E_SKIP && peek.n == 0) return r;     /* not decodable at all */

    if (peek.n == 512 && gz_tar_header_ok(pk)) {
        gz_tar_parser *t = gz_tar_parser_new(a, 0, 0, c);
        if (!t) return GZ_E_NOMEM;
        prog_src ps = { { prog_read, s->size, 0, 0 }, s, c, 0 };
        tar_sink k = { t };
        r = codec->decode(&ps.s, tar_sink_write, &k, c);
        gz_tar_parser_free(t);
        if (r == GZ_E_CANCEL || r == GZ_E_NOMEM) return r;
        if (a->n > 0) {
            pv->is_tar = 1;
            a->solid = 1;
            gz_arc_set_type(a, codec->tar_name);
            return GZ_OK;      /* tolerate a damaged tail: entries found so far */
        }
        a->n = 0;
        a->raw_len = 0;
    }

    /* a cpio archive (.cpio.gz, initramfs, macOS Payload): "CPIO.GZ" etc. */
    if (gz_cpio_magic(pk, peek.n)) {
        prog_src ps = { { prog_read, s->size, 0, 0 }, s, c, 0 };
        r = gz_cpio_list_stream(a, &ps.s, codec->decode, c);
        if (r == GZ_E_CANCEL || r == GZ_E_NOMEM) return r;
        if (!r && a->n > 0) {
            char tn[40] = "CPIO";
            const char *x = codec->tar_name ? codec->tar_name : "";
            if (x[0] == 'T' && x[1] == 'A' && x[2] == 'R') x += 3;
            for (u32 i = 4; *x && i + 1 < sizeof tn; i++) tn[i] = *x++;
            pv->is_cpio = 1;
            a->solid = 1;
            gz_arc_set_type(a, tn);
            return GZ_OK;
        }
        a->n = 0;
        a->raw_len = 0;
    }

    /* a single compressed file */
    gz_stream_info inf;
    __builtin_memset(&inf, 0, sizeof inf);
    inf.usize = GZ_SIZE_UNKNOWN;
    if (codec->info) codec->info(s, &inf, c);
    gz_entry *e;
    if (inf.name_len) r = gz_arc_add_named(a, inf.name, inf.name_len, inf.name_enc, &e);
    else r = derive_name(a, o, &e);
    if (r) return r;
    e->usize = inf.usize;
    e->csize = s->size;
    if (inf.has_mtime) { e->mtime = gz_unix_to_filetime(inf.mtime); e->mtime_kind = GZ_MT_FILETIME; }
    e->attr = 0x20;
    return GZ_OK;
}

void gz_sfmt_close(gz_archive *a)
{
    gz_free(a->priv);
    a->priv = 0;
}

typedef struct { gz_out *out; u64 n; } single_sink;

static int single_write(void *u, const u8 *p, size_t n)
{
    single_sink *k = (single_sink *)u;
    k->n += n;
    return k->out->write(k->out, p, n);
}

int gz_sfmt_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    sfmt_priv *pv = (sfmt_priv *)a->priv;
    if (pv->is_tar || pv->is_cpio) {
        /* random access is impossible: decode up to the entry */
        u8 *sel = (u8 *)gz_alloc(a->n + 1);
        if (!sel) return GZ_E_NOMEM;
        sel[idx] = 1;
        int r = gz_sfmt_extract_solid(a, s, sel, out, c);
        gz_free(sel);
        return r;
    }
    int r = out->open(out, idx);
    if (r) return r;
    single_sink k = { out, 0 };
    int st = codec_of(a)->decode(s, single_write, &k, c);
    if (st == GZ_E_SKIP) st = GZ_OK;
    if (!st && a->e[idx].usize == GZ_SIZE_UNKNOWN) a->e[idx].usize = k.n;
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

int gz_sfmt_extract_solid(gz_archive *a, gz_src *s, const u8 *sel, gz_out *out, gz_ctx *c)
{
    sfmt_priv *pv = (sfmt_priv *)a->priv;
    if (pv->is_cpio) return gz_cpio_extract_stream(a, s, codec_of(a)->decode, sel, out, c);
    if (!pv->is_tar) return sel[0] ? gz_sfmt_extract(a, s, 0, out, c) : GZ_OK;
    gz_tar_parser *t = gz_tar_parser_new(a, sel, out, c);
    if (!t) return GZ_E_NOMEM;
    tar_sink k = { t };
    int r = codec_of(a)->decode(s, tar_sink_write, &k, c);
    if (r == GZ_E_SKIP) r = GZ_OK;
    r = gz_tar_finish(t, r);
    gz_tar_parser_free(t);
    return r;
}

void gz_sfmt_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)e;
    const char *m = codec_of(a)->method;
    u32 i = 0;
    for (; m && m[i] && i + 1 < cap; i++) buf[i] = m[i];
    if (cap) buf[i] = 0;
}
