/*
 * 고깃ZIP - BZIP2 (.bz2, .tbz2, .tbz) via the shared stream-format code
 */
#include "streamfmt.h"
#include "bzip2.h"

static void *bz2_create(void) { return gz_bzip2_dec_new(); }
static void bz2_destroy(void *p) { gz_bzip2_dec_free((gz_bzip2_dec *)p); }

static int bz2_decode(gz_src *s, gz_sink_fn sink, void *user, gz_ctx *c)
{
    gz_bzip2_dec *d = (gz_bzip2_dec *)gz_ctx_slot(c, GZ_SLOT_BZIP2, bz2_create, bz2_destroy);
    if (!d) return GZ_E_NOMEM;
    gz_pipe pp = { { s, 0, s->size, c->cancel }, sink, user };
    gz_stream_io io = { gz_range_read, gz_pipe_write, &pp };
    return gz_bzip2_decode(d, &io, GZ_SIZE_UNKNOWN, 1, 0);
}

/* "BZh" + block size digit + first block magic (pi) or end-of-stream magic (sqrt pi) */
static int bz2_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 14 || h[0] != 'B' || h[1] != 'Z' || h[2] != 'h' || h[3] < '1' || h[3] > '9') return 0;
    static const u8 blk[6] = { 0x31, 0x41, 0x59, 0x26, 0x53, 0x59 };
    static const u8 eos[6] = { 0x17, 0x72, 0x45, 0x38, 0x50, 0x90 };
    if (!__builtin_memcmp(h + 4, blk, 6) || !__builtin_memcmp(h + 4, eos, 6)) return 95;
    return 0;
}

static const gz_stream_codec bz2_codec = {
    "TAR.BZ2", "BZip2", "tbz2 tbz", bz2_decode, 0
};

GZ_FORMAT(gz_fmt_bzip2)
const gz_format gz_fmt_bzip2 = GZ_STREAM_FORMAT("BZIP2", "bz2 bzip2 tbz2 tbz", bz2_probe, &bz2_codec);
