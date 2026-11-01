/*
 * 고깃ZIP - LZW decoders
 *
 *   Unix compress (.Z): 9..16-bit codes, LSB-first, optional block mode with
 *   CLEAR (code 256); code width changes and CLEARs skip to the next group of
 *   8 codes exactly like ncompress, so its output is reproduced byte for byte.
 *
 *   ZIP Shrink (method 1): 9..13-bit codes, control code 256 followed by
 *   1 (code size + 1) or 2 (partial clear: free every leaf node). Same rules as
 *   7-Zip's decoder (orphan / self-linked nodes are rejected).
 */
#ifndef GZ_LZW_H
#define GZ_LZW_H
#include "base.h"
#include "stream.h"

typedef struct gz_lzw_dec gz_lzw_dec;     /* ~2.5 MiB, reusable */

gz_lzw_dec *gz_lzw_dec_new(void);
void gz_lzw_dec_free(gz_lzw_dec *d);

/* Unix compress data following the 3-byte header 1F 9D <flags>.
 * flags: header byte 2 (bits 0-4 max code bits 9..16, 0x80 block mode).
 * out_size: GZ_SIZE_UNKNOWN (normal: the stream ends with the input) or a limit.
 * Returns GZ_OK, GZ_E_DATA (invalid code), GZ_E_METHOD (bad max bits) or a callback error. */
int gz_lzw_decode(gz_lzw_dec *d, const gz_stream_io *io, u64 out_size, int flags);

/* ZIP Shrink. d may be NULL (a decoder is created for the call).
 * out_size: uncompressed size from the ZIP header (or GZ_SIZE_UNKNOWN: until the input ends).
 * Returns GZ_OK, GZ_E_DATA, GZ_E_TRUNC (input ended before out_size bytes) or a callback error. */
int gz_shrink_decode(gz_lzw_dec *d, const gz_stream_io *io, u64 out_size);

#endif
