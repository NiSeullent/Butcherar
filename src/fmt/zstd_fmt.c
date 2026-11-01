/*
 * 고깃ZIP - Zstandard (.zst .tzst) and LZ4 (.lz4 .tlz4) single-stream files
 * via the shared stream-format code (a tarball inside is listed entry by entry).
 */
#include "streamfmt.h"
#include "zstd.h"
#include "lz4.h"
#include "xxhash.h"

#define WALK_MAX_BLOCKS 200000u      /* give up summing content sizes after this */

static void *zdec_create(void) { return gz_zstd_dec_new(); }
static void zdec_destroy(void *p) { gz_zstd_dec_free((gz_zstd_dec *)p); }

/* skip leading skippable frames (shared by both formats): returns the offset of
 * the first real frame, or ~0 when there is none within a few frames */
static u64 skip_skippable(gz_src *s, u64 off)
{
    for (int i = 0; i < 16 && off + 8 <= s->size; i++) {
        u8 h[8];
        if (gz_src_read_exact(s, off, h, 8)) break;
        if ((rd32(h) & 0xFFFFFFF0u) != GZ_ZSTD_SKIP_MAGIC) return off;
        off += 8 + (u64)rd32(h + 4);
    }
    return ~(u64)0;
}

/* ---------------- Zstandard ---------------- */

static int zstd_decode(gz_src *s, gz_sink_fn sink, void *user, gz_ctx *c)
{
    gz_zstd_dec *own = 0, *d;
    if (c) {
        d = (gz_zstd_dec *)gz_ctx_slot(c, GZ_SLOT_ZSTD, zdec_create, zdec_destroy);
    } else {
        d = own = gz_zstd_dec_new();
    }
    if (!d) return GZ_E_NOMEM;
    gz_pipe pp = { { s, 0, s->size, c ? c->cancel : 0 }, sink, user };
    gz_stream_io io = { gz_range_read, gz_pipe_write, &pp };
    int r = gz_zstd_decode(d, &io, GZ_SIZE_UNKNOWN, 0);
    gz_zstd_dec_free(own);
    return r;
}

/* total content size: every frame must declare it (walks block headers only) */
static void zstd_info(gz_src *s, gz_stream_info *inf, gz_ctx *c)
{
    (void)c;
    u64 off = 0, total = 0;
    u32 blocks = 0;
    while (off < s->size) {
        u8 h[18];
        u32 n = s->size - off < 18 ? (u32)(s->size - off) : 18;
        if (n < 4 || gz_src_read_exact(s, off, h, n)) return;
        u32 magic = rd32(h);
        if ((magic & 0xFFFFFFF0u) == GZ_ZSTD_SKIP_MAGIC) {
            if (n < 8) return;
            off += 8 + (u64)rd32(h + 4);
            continue;
        }
        gz_zstd_frame_info fi;
        if (gz_zstd_frame_header(h, n, &fi) || fi.content_size == GZ_SIZE_UNKNOWN) return;
        total += fi.content_size;
        off += fi.header_len;
        for (;;) {
            u8 b[3];
            if (++blocks > WALK_MAX_BLOCKS || gz_src_read_exact(s, off, b, 3)) return;
            u32 bh = (u32)b[0] | (u32)b[1] << 8 | (u32)b[2] << 16, type = (bh >> 1) & 3;
            if (type == 3) return;
            off += 3 + (type == 1 ? 1 : (bh >> 3));
            if (bh & 1) break;
        }
        if (fi.has_checksum) off += 4;
    }
    if (off == s->size) inf->usize = total;
}

static int zstd_probe(gz_src *s, const u8 *h, u32 n)
{
    if (n >= 6 && rd32(h) == GZ_ZSTD_MAGIC && !(h[4] & 8)) return 90;
    if (n >= 8 && (rd32(h) & 0xFFFFFFF0u) == GZ_ZSTD_SKIP_MAGIC) {
        u64 off = skip_skippable(s, 0);
        u8 m[5];
        if (off != ~(u64)0 && !gz_src_read_exact(s, off, m, 5) && rd32(m) == GZ_ZSTD_MAGIC && !(m[4] & 8))
            return 80;
    }
    return 0;
}

static const gz_stream_codec zstd_codec = {
    "TAR.ZST", "Zstd", "tzst", zstd_decode, zstd_info
};

GZ_FORMAT(gz_fmt_zstd)
const gz_format gz_fmt_zstd = GZ_STREAM_FORMAT("ZSTD", "zst tzst zstd", zstd_probe, &zstd_codec);

/* ---------------- LZ4 ---------------- */

static int lz4_decode(gz_src *s, gz_sink_fn sink, void *user, gz_ctx *c)
{
    gz_pipe pp = { { s, 0, s->size, c ? c->cancel : 0 }, sink, user };
    gz_stream_io io = { gz_range_read, gz_pipe_write, &pp };
    return gz_lz4f_decode(&io, GZ_SIZE_UNKNOWN, 0);
}

/* content size when every frame stores it (walks block headers only) */
static void lz4_info(gz_src *s, gz_stream_info *inf, gz_ctx *c)
{
    (void)c;
    u64 off = 0, total = 0;
    u32 blocks = 0;
    while (off < s->size) {
        u8 h[19];
        u32 n = s->size - off < 19 ? (u32)(s->size - off) : 19;
        if (n < 7 || gz_src_read_exact(s, off, h, n)) return;
        u32 magic = rd32(h);
        if ((magic & 0xFFFFFFF0u) == GZ_LZ4_SKIP_MAGIC) {
            off += 8 + (u64)rd32(h + 4);
            continue;
        }
        if (magic != GZ_LZ4_MAGIC) return;
        u32 flg = h[4];
        if (!(flg & 8) || n < 15) return;
        total += rd64(h + 6);
        off += 7 + 8 + ((flg & 1) ? 4 : 0);
        for (;;) {
            u8 b[4];
            if (++blocks > WALK_MAX_BLOCKS || gz_src_read_exact(s, off, b, 4)) return;
            u32 bs = rd32(b);
            off += 4;
            if (!bs) break;
            off += (bs & 0x7FFFFFFFu) + ((flg & 0x10) ? 4 : 0);
        }
        if (flg & 4) off += 4;
    }
    if (off == s->size) inf->usize = total;
}

static int lz4_frame_ok(const u8 *h, u32 n)
{
    if (n < 7) return 0;
    u32 flg = h[4], bd = h[5];
    if ((flg >> 6) != 1 || (flg & 2) || (bd & 0x8F) || ((bd >> 4) & 7) < 4) return 0;
    u32 hl = 7 + ((flg & 8) ? 8 : 0) + ((flg & 1) ? 4 : 0);
    if (n < hl) return 1;
    return ((gz_xxh32(h + 4, hl - 5, 0) >> 8) & 0xFF) == h[hl - 1];
}

static int lz4_probe(gz_src *s, const u8 *h, u32 n)
{
    if (n >= 4 && rd32(h) == GZ_LZ4_MAGIC) return lz4_frame_ok(h, n) ? 90 : 0;
    if (n >= 8 && rd32(h) == GZ_LZ4_LEGACY_MAGIC) {
        u32 bs = rd32(h + 4);
        return bs && bs <= (8u << 20) + (8u << 20) / 255 + 16 ? 80 : 0;
    }
    if (n >= 8 && (rd32(h) & 0xFFFFFFF0u) == GZ_LZ4_SKIP_MAGIC) {
        u64 off = skip_skippable(s, 0);
        u8 m[19];
        u32 k = 0;
        if (off != ~(u64)0 && off < s->size) {
            k = s->size - off < 19 ? (u32)(s->size - off) : 19;
            if (gz_src_read_exact(s, off, m, k)) k = 0;
        }
        if (k >= 7 && rd32(m) == GZ_LZ4_MAGIC && lz4_frame_ok(m, k)) return 80;
    }
    return 0;
}

static const gz_stream_codec lz4_codec = {
    "TAR.LZ4", "LZ4", "tlz4", lz4_decode, lz4_info
};

GZ_FORMAT(gz_fmt_lz4)
const gz_format gz_fmt_lz4 = GZ_STREAM_FORMAT("LZ4", "lz4 tlz4", lz4_probe, &lz4_codec);
