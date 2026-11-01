/*
 * 고깃ZIP - GZIP (.gz, .tgz) via the shared stream-format code
 */
#include "streamfmt.h"
#include "crc32.h"

/* parse a gzip member header at off: data offset, optional name and mtime */
static int gzip_header(gz_src *s, u64 off, u64 *data, gz_stream_info *inf)
{
    u8 h[10];
    if (gz_src_read_exact(s, off, h, 10)) return GZ_E_TRUNC;
    if (h[0] != 0x1f || h[1] != 0x8b || h[2] != 8) return GZ_E_FORMAT;
    u8 flg = h[3];
    if (flg & 0xe0) return GZ_E_FORMAT;
    if (inf && rd32(h + 4)) { inf->mtime = rd32(h + 4); inf->has_mtime = 1; }
    u64 p = off + 10;
    if (flg & 4) {
        u8 x[2];
        if (gz_src_read_exact(s, p, x, 2)) return GZ_E_TRUNC;
        p += 2 + rd16(x);
    }
    for (int k = 0; k < 2; k++) {
        u8 bit = k == 0 ? 8 : 16;
        if (!(flg & bit)) continue;
        u8 c[256];
        for (;;) {
            u32 got = 0;
            if (p >= s->size || s->read_at(s, p, c, sizeof c, &got) || !got) return GZ_E_TRUNC;
            u32 i = 0;
            while (i < got && c[i]) i++;
            if (k == 0 && inf) {
                for (u32 j = 0; j < i && inf->name_len < sizeof inf->name; j++) inf->name[inf->name_len++] = c[j];
            }
            p += i;
            if (i < got) { p++; break; }
        }
    }
    if (flg & 2) p += 2;
    *data = p;
    return GZ_OK;
}

static int gzip_decode(gz_src *s, gz_sink_fn sink, void *user, gz_ctx *c)
{
    gz_inflater *z = gz_ctx_inflater(c);
    if (!z) return GZ_E_NOMEM;
    u64 data;
    int r = gzip_header(s, 0, &data, 0);
    if (r) return r;
    for (;;) {
        gz_pipe pp = { { s, data, s->size, c->cancel }, sink, user };
        gz_stream_io io = { gz_range_read, gz_pipe_write, &pp };
        r = gz_inflate_run(z, &io, 0);
        if (r) return r;
        u64 end = pp.rd.pos - z->rest_len;
        u8 tr[8];
        if (gz_src_read_exact(s, end, tr, 8)) return GZ_E_TRUNC;
        if (rd32(tr) != z->crc) return GZ_E_CRC;
        if (rd32(tr + 4) != (u32)z->total_out) return GZ_E_DATA;
        /* concatenated members (gzip -c a >> b, pigz, bgzip) */
        u64 next = end + 8;
        u8 h[2];
        if (next + 18 > s->size) break;
        if (gz_src_read_exact(s, next, h, 2) || h[0] != 0x1f || h[1] != 0x8b) break;
        if (gzip_header(s, next, &data, 0)) break;
    }
    return GZ_OK;
}

static void gzip_info(gz_src *s, gz_stream_info *inf, gz_ctx *c)
{
    (void)c;
    u64 data;
    gzip_header(s, 0, &data, inf);
    inf->name_enc = GZ_NE_LEGACY;
    u8 isz[4];
    if (s->size >= 18 && !gz_src_read_exact(s, s->size - 4, isz, 4)) inf->usize = rd32(isz);
}

static int gzip_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 18 || h[0] != 0x1f || h[1] != 0x8b || h[2] != 8 || (h[3] & 0xe0)) return 0;
    return 90;
}

static const gz_stream_codec gzip_codec = {
    "TAR.GZ", "Deflate", "tgz taz tpz", gzip_decode, gzip_info
};

GZ_FORMAT(gz_fmt_gzip)
const gz_format gz_fmt_gzip = GZ_STREAM_FORMAT("GZIP", "gz gzip tgz taz tpz", gzip_probe, &gzip_codec);
