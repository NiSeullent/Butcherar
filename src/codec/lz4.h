/*
 * 고깃ZIP - LZ4 decoder: raw blocks, the LZ4 frame format and legacy frames
 */
#ifndef GZ_LZ4_H
#define GZ_LZ4_H
#include "base.h"
#include "stream.h"

#define GZ_LZ4_MAGIC        0x184D2204u
#define GZ_LZ4_LEGACY_MAGIC 0x184C2102u
#define GZ_LZ4_SKIP_MAGIC   0x184D2A50u     /* 0x184D2A50..5F */

/* One raw LZ4 block (no history: squashfs, ...). GZ_E_DATA when corrupt or when
 * the output does not fit in dcap. *dn = bytes written. */
int gz_lz4_block_decode(const u8 *src, u32 sn, u8 *dst, u32 dcap, u32 *dn);

/* Same, with dict_len bytes of history directly before dst (dst[-dict_len..-1])
 * that matches may reference (linked blocks, LZ4 inside other containers). */
int gz_lz4_block_decode_ext(const u8 *src, size_t sn, u8 *dst, size_t dcap, size_t dict_len, size_t *dn);

/* Stream decoder: consecutive LZ4 frames, legacy frames and skippable frames
 * until the input ends. Verifies header, block and content checksums and the
 * stored content size. out_size / in_used as in gz_zstd_decode. A frame that
 * needs a dictionary returns GZ_E_METHOD. */
int gz_lz4f_decode(const gz_stream_io *io, u64 out_size, u64 *in_used);

#endif
