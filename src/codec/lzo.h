/*
 * 고깃ZIP - LZO1X decoder (safe, bounded). Decodes the output of lzo1x_1, lzo1x_1_11/12/15,
 * lzo1x_999 (lzop, squashfs, btrfs, UBIFS, kernel images ...).
 *
 * Output buffers: the decoders below copy in 8/16-byte steps when there is room,
 * so out[*out_n .. out_cap) may be overwritten too. Pass the exact expected size
 * as out_cap when the rest of the buffer must stay intact.
 */
#ifndef GZ_LZO_H
#define GZ_LZO_H
#include "base.h"

/* Decode one LZO1X block from in[0..in_n) into out[0..out_cap), up to and including
 * the end-of-stream marker (0x11 0x00 0x00).
 * GZ_OK: marker reached; *out_n = bytes written; *in_used (optional) = bytes consumed
 *        (callers that need the whole input used compare it with in_n).
 * GZ_E_DATA: corrupt stream, distance before the output start, or more output than
 *        out_cap. GZ_E_TRUNC: input ended before the marker. */
int gz_lzo1x_decode(const u8 *in, size_t in_n, u8 *out, size_t out_cap, size_t *out_n, size_t *in_used);

#endif
