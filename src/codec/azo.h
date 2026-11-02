/*
 * 고깃ZIP - AZO decoder (ESTsoft ALZip, EGG block method 3)
 *
 * AZO is an LZ77 coder with adaptive binary models and a 32-bit low/high
 * arithmetic coder (bits MSB first, E1/E2/E3 rescaling). Written from the public
 * descriptions of the decoder (kippler's xunazo, its MIT port libazo, and the
 * decompressor ESTsoft published with unegg 0.5); no code was taken from them.
 *
 * Stream: '1' (version), flags (bit 0: x86 E8/E9 filter), then blocks:
 *   blockSize u32 BE, compressSize u32 BE, check u32 BE (= blockSize ^ compressSize)
 *   compressSize bytes: stored when compressSize == blockSize, else coded (needs
 *   compressSize + 8 <= blockSize and must consume exactly compressSize bytes)
 * A header with blockSize or compressSize 0 ends the stream. Every block is coded
 * on its own (fresh models, matches only inside the block); the x86 filter is
 * undone per block with positions relative to the block start.
 *
 * Memory: about 180 KiB of models plus one input and one output block buffer
 * (blocks above GZ_AZO_MAX_BLOCK give GZ_E_LIMIT). Cache one decoder per thread.
 */
#ifndef GZ_AZO_H
#define GZ_AZO_H
#include "base.h"
#include "stream.h"

#if UINTPTR_MAX > 0xFFFFFFFFu
#  define GZ_AZO_MAX_BLOCK (256u << 20)
#else
#  define GZ_AZO_MAX_BLOCK (128u << 20)
#endif

typedef struct gz_azo_dec gz_azo_dec;

gz_azo_dec *gz_azo_dec_new(void);
void gz_azo_dec_free(gz_azo_dec *d);
/* gz_ctx_slot helpers */
void *gz_azo_slot_new(void);
void gz_azo_slot_free(void *p);

/* Decode one AZO stream: pull input with io->read, push output with io->write.
 *  out_size  exact output size when known (decoding stops there, a block that
 *            would exceed it is GZ_E_DATA, a stream ending earlier is GZ_E_DATA),
 *            else GZ_SIZE_UNKNOWN (decode until the end header).
 *  in_used   optional: input bytes consumed.
 * Returns GZ_OK, GZ_E_DATA (bad header, version, coded data), GZ_E_TRUNC,
 * GZ_E_LIMIT, GZ_E_NOMEM, or a reader/sink error unchanged. */
int gz_azo_decode(gz_azo_dec *d, const gz_stream_io *io, u64 out_size, u64 *in_used);

/* Decode one coded block in memory (exposed for tests): in[0..in_len) to
 * out[0..out_len). in must be readable for 8 bytes past in_len (zero padding is
 * not required, those bytes are never used). GZ_OK or GZ_E_DATA. */
int gz_azo_decode_block(gz_azo_dec *d, const u8 *in, u32 in_len, u8 *out, u32 out_len);

/* Undo the x86 CALL/JMP filter on one block (exposed for tests). */
void gz_azo_x86_unfilter(u8 *buf, u32 size);

#endif
