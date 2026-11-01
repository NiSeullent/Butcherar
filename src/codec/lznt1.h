/*
 * 고깃ZIP - LZNT1 decoder (NTFS compressed attributes, RtlCompressBuffer)
 *
 * Output buffers: the decoders below copy in 8/16-byte steps when there is room,
 * so out[*out_n .. out_cap) may be overwritten too. Pass the exact expected size
 * as out_cap when the rest of the buffer must stay intact.
 */
#ifndef GZ_LZNT1_H
#define GZ_LZNT1_H
#include "base.h"

/* Decode an LZNT1 buffer (one NTFS compression unit): a sequence of chunks, each
 * a 16-bit header (bits 0-11 = data size - 1, bit 15 = compressed) followed by data
 * that expands to at most 4096 bytes. Stops at a zero header, at the end of the input
 * or when out_cap bytes are written. A chunk that expands to less than 4096 bytes is
 * zero-padded to 4096 when another chunk follows (NTFS semantics); the last chunk is
 * not padded, so NTFS callers zero-fill the rest of the unit themselves.
 * *out_n = bytes written. GZ_OK, GZ_E_DATA (bad back reference, chunk overflow),
 * GZ_E_TRUNC (chunk larger than the remaining input). */
int gz_lznt1_decode(const u8 *in, size_t in_n, u8 *out, size_t out_cap, size_t *out_n);

#endif
