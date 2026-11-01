/*
 * 고깃ZIP - Unix compress (.Z, .taz) via the shared stream-format code
 */
#include "streamfmt.h"
#include "lzw.h"

static int z_decode(gz_src *s, gz_sink_fn sink, void *user, gz_ctx *c)
{
    u8 h[3];
    int r = gz_src_read_exact(s, 0, h, 3);
    if (r) return r;
    if (h[0] != 0x1f || h[1] != 0x9d) return GZ_E_FORMAT;
    gz_lzw_dec *d = (gz_lzw_dec *)gz_ctx_slot(c, GZ_SLOT_MISC3, gz_lzw_slot_new, gz_lzw_slot_free);
    if (!d) return GZ_E_NOMEM;
    gz_pipe pp = { { s, 3, s->size, c->cancel }, sink, user };
    gz_stream_io io = { gz_range_read, gz_pipe_write, &pp };
    return gz_lzw_decode(d, &io, GZ_SIZE_UNKNOWN, h[2]);
}

static int z_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 3 || h[0] != 0x1f || h[1] != 0x9d) return 0;
    u32 bits = h[2] & 0x1f;
    return bits >= 9 && bits <= 16 ? 90 : 0;
}

static const gz_stream_codec z_codec = {
    "TAR.Z", "LZW", "taz", z_decode, 0
};

GZ_FORMAT(gz_fmt_zcompress)
const gz_format gz_fmt_zcompress = GZ_STREAM_FORMAT("Z", "z taz", z_probe, &z_codec);
