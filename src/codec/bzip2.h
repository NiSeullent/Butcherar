/*
 * 고깃ZIP - BZip2 decoder
 *
 * Standard streams ("BZh1".."BZh9"): randomized blocks, block CRCs and the
 * combined stream CRC are checked (GZ_E_CRC), concatenated streams written by
 * pbzip2 / lbzip2 / "cat a.bz2 b.bz2" are decoded back to back.
 *
 * Decoding a block: table-driven Huffman (10-bit primary lookup, canonical
 * search for longer codes), MTF on 64-bit words, then an inverse BWT that walks
 * two independent chains at once (forward from origPtr with T[], backward with
 * LF[]; u32 entries carry index << 8 | byte), RLE1 and CRC over the output.
 *
 * Memory: about 9 bytes per block byte (8.1 MiB for 900k blocks) plus 1.3 MiB
 * of buffers. Decoders are reusable: cache one per thread in GZ_SLOT_BZIP2.
 */
#ifndef GZ_BZIP2_H
#define GZ_BZIP2_H
#include "base.h"
#include "stream.h"

typedef struct gz_bzip2_dec gz_bzip2_dec;

gz_bzip2_dec *gz_bzip2_dec_new(void);
void gz_bzip2_dec_free(gz_bzip2_dec *d);

/* Decode a bzip2 stream: pull input with io->read, push output with io->write.
 *  out_size     exact output size when known, else GZ_SIZE_UNKNOWN. Output stops
 *               after out_size bytes (GZ_OK); a stream that ends earlier gives
 *               GZ_E_DATA.
 *  multi_stream 1: after the end of a stream, continue while another "BZh1-9"
 *               header follows (trailing garbage is ignored, as bzip2 does);
 *               0: stop after the first stream.
 *  in_used      optional: input bytes consumed (up to the byte-aligned end of
 *               the last stream decoded), valid when GZ_OK is returned.
 * Returns GZ_OK, GZ_E_FORMAT (no "BZh" header), GZ_E_DATA, GZ_E_CRC, GZ_E_TRUNC,
 * GZ_E_NOMEM, or a sink/reader error unchanged (GZ_E_SKIP, GZ_E_CANCEL...). */
int gz_bzip2_decode(gz_bzip2_dec *d, const gz_stream_io *io, u64 out_size, int multi_stream,
                    u64 *in_used);

/* NSIS variant (installers built with "SetCompressor bzip2", see 7-Zip's
 * NsisDecode / CNsisDecoder): no "BZh" header, each block starts with ONE byte,
 * 0x31 = block, 0x17 = end of stream; no block or stream CRCs, no randomized
 * bit; then origPtr (24 bits) and the usual block body; blocks hold up to
 * 900k bytes. The stream is decoded until the 0x17 marker, or until out_size
 * bytes were produced (NSIS solid blocks are read in pieces with known sizes).
 * Same return values and in_used semantics as gz_bzip2_decode. */
int gz_bzip2_decode_nsis(gz_bzip2_dec *d, const gz_stream_io *io, u64 out_size, u64 *in_used);

/* bzip2's CRC-32 (polynomial 0x04C11DB7, MSB first). tab is filled by
 * gz_bzip2_crc_table; crc starts at 0xFFFFFFFF and is inverted at the end. */
void gz_bzip2_crc_table(u32 tab[8][256]);
u32  gz_bzip2_crc_update(const u32 tab[8][256], u32 crc, const u8 *p, size_t n);

/* countdown table of randomized blocks (bzip2 0.9.0): the byte where the count
 * starting with entry i reaches 1 is XORed with 1 */
extern const u16 gz_bzip2_rnums[512];

#endif
