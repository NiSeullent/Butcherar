/*
 * 고깃ZIP - Microsoft XPRESS decoders ([MS-XCA]): "Plain LZ77" (LZXPRESS) and
 * "LZ77+Huffman" (XPRESS Huffman: WIM, NTFS WOF system compression, hiberfil, SMB)
 */
#ifndef GZ_XPRESS_H
#define GZ_XPRESS_H
#include "base.h"

/* Plain LZ77: decodes until the input is used up or out_cap bytes are written.
 * *out_n = bytes written. GZ_OK, GZ_E_DATA (bad distance / match past out_cap),
 * GZ_E_TRUNC (input ends inside a token). */
int gz_xpress_decode(const u8 *in, size_t in_n, u8 *out, size_t out_cap, size_t *out_n);

/* LZ77+Huffman: decodes exactly out_n bytes (the size is always known: WIM/WOF chunk,
 * SMB header). A new 256-byte table of 512 4-bit code lengths starts every 64 KiB of
 * output. A trailing end-of-data symbol and padding are not required.
 * GZ_OK, GZ_E_DATA (bad code table, distance, or match past out_n), GZ_E_TRUNC. */
int gz_xpress_huff_decode(const u8 *in, size_t in_n, u8 *out, size_t out_n);

#endif
