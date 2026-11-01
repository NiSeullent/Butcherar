/*
 * 고깃ZIP - streaming raw Deflate (RFC 1951) encoder
 *
 *   level 0      stored blocks only
 *   level 1-2    hash chains (3-byte table + 4-byte chains), greedy
 *   level 3-6    hash chains, lazy matching
 *   level 7-9    binary trees + near-optimal parsing (iterated cost model)
 *
 * Every level splits blocks by symbol statistics and emits each block as
 * dynamic Huffman, fixed Huffman or stored, whichever is smallest. Output is
 * byte-identical on every CPU / kernel. Memory is bounded for any input size
 * (gz_deflate_enc_memory: ~1.5 MiB level 0, ~2.2 MiB levels 1-6, ~10 MiB 7-9).
 * An encoder is not shared between threads; use one per thread (no global
 * mutable state, so any number can run concurrently).
 */
#ifndef GZ_DEFLATE_ENC_H
#define GZ_DEFLATE_ENC_H
#include "base.h"
#include "stream.h"

typedef struct gz_deflate_enc gz_deflate_enc;

/* New encoder for level 0..9 (clamped). NULL when out of memory.
 * The SIMD kernels are chosen from g_cpu (cpu.h) at this point. */
gz_deflate_enc *gz_deflate_enc_new(int level);
void gz_deflate_enc_free(gz_deflate_enc *e);

/* Bytes allocated by gz_deflate_enc_new(level) (for thread-count decisions). */
size_t gz_deflate_enc_memory(int level);

/* Compress everything io->read yields (until *got == 0) into one complete raw
 * Deflate stream pushed through io->write (chunks of up to ~512 KiB).
 * crc32_of_input (CRC-32 of the input, gz_crc32), in_bytes and out_bytes may be
 * NULL. The encoder is reusable: each call produces an independent stream.
 * Returns GZ_OK, or the first error returned by io->read / io->write unchanged
 * (GZ_E_CANCEL, GZ_E_SKIP, GZ_E_IO...). gz_crc32_init() must have run. */
int gz_deflate_encode(gz_deflate_enc *e, const gz_stream_io *io,
                      u32 *crc32_of_input, u64 *in_bytes, u64 *out_bytes);

/* Name of the selected kernels, e.g. "AVX2", "SSE2", "NEON", "x86". */
const char *gz_deflate_enc_kernel(const gz_deflate_enc *e);

#endif
