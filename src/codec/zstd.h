/*
 * 고깃ZIP - Zstandard decoder (RFC 8878)
 *
 * Frames (single segment or windowed, content size, XXH64 content checksum),
 * skippable frames, raw / RLE / compressed blocks, Huffman literals
 * (1 or 4 streams, treeless), FSE sequences (predefined / RLE / FSE / repeat),
 * repeat offsets. Windows up to 2 GiB (512 MiB on 32-bit builds); frames that
 * need a dictionary return GZ_E_METHOD.
 *
 * The decoder object is reusable (cache one per thread with
 * gz_ctx_slot(c, GZ_SLOT_ZSTD, ...)); it keeps its buffers between calls and
 * releases windows larger than 16 MiB at the end of each call.
 */
#ifndef GZ_ZSTD_H
#define GZ_ZSTD_H
#include "base.h"
#include "stream.h"

#define GZ_ZSTD_MAGIC      0xFD2FB528u
#define GZ_ZSTD_SKIP_MAGIC 0x184D2A50u     /* low 4 bits free: 0x184D2A50..5F */

typedef struct gz_zstd_dec gz_zstd_dec;

gz_zstd_dec *gz_zstd_dec_new(void);
void gz_zstd_dec_free(gz_zstd_dec *d);

/* Decode every consecutive frame (zstd and skippable) until the input ends.
 * out_size: GZ_SIZE_UNKNOWN, or the number of bytes wanted: decoding stops once
 * that many bytes were written, even if input remains (the content checksum is
 * still verified when the frame ends exactly there).
 * in_used (optional): bytes of input consumed (end of the last frame decoded).
 * Errors: GZ_E_FORMAT (not zstd), GZ_E_DATA, GZ_E_CRC (XXH64), GZ_E_TRUNC,
 * GZ_E_METHOD (dictionary / legacy v0.x frame), GZ_E_LIMIT (window too large),
 * GZ_E_NOMEM, or the error returned by io->read / io->write. */
int gz_zstd_decode(gz_zstd_dec *d, const gz_stream_io *io, u64 out_size, u64 *in_used);

enum {
    GZ_ZSTD_ONE_FRAME = 1      /* stop after the first zstd frame (skippable frames before it are skipped) */
};
int gz_zstd_decode_ex(gz_zstd_dec *d, const gz_stream_io *io, u64 out_size, u32 flags, u64 *in_used);

/* Memory to memory (squashfs blocks, small ZIP entries): decode all frames of
 * src into dst. GZ_E_DATA if the output would exceed dcap. *dn = bytes written. */
int gz_zstd_decode_mem(gz_zstd_dec *d, const void *src, size_t sn, void *dst, size_t dcap, size_t *dn);

/* Frame header parser (no decoding). p points at the magic number.
 * Returns GZ_OK, GZ_E_TRUNC (n too small: need header_len bytes), GZ_E_FORMAT. */
typedef struct gz_zstd_frame_info {
    u64 content_size;          /* GZ_SIZE_UNKNOWN if not stored */
    u64 window;                /* window size the frame needs   */
    u32 header_len;            /* magic + header bytes          */
    u32 dict_id;
    u8  single_segment;
    u8  has_checksum;
} gz_zstd_frame_info;
int gz_zstd_frame_header(const u8 *p, size_t n, gz_zstd_frame_info *fi);

#endif
