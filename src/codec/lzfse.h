/*
 * 고깃ZIP - LZFSE and LZVN decoders (Apple: DMG "ULFO", APFS, HFS+ decmpfs, .lzfse)
 *
 * An LZFSE stream is a sequence of blocks, each starting with a 4-byte magic:
 *   bvx2 / bvx1  LZFSE (FSE-coded literals + L/M/D), compressed / plain header
 *   bvxn         LZVN payload
 *   bvx-         stored bytes
 *   bvx$         end of stream
 * Matches may reach back into earlier blocks of the same stream.
 */
#ifndef GZ_LZFSE_H
#define GZ_LZFSE_H
#include "base.h"

typedef struct gz_lzfse_dec gz_lzfse_dec;     /* ~48 KiB of tables, reusable */
gz_lzfse_dec *gz_lzfse_dec_new(void);
void gz_lzfse_dec_free(gz_lzfse_dec *d);

/* Decode every block of in[0..in_n) up to and including bvx$ into out[0..out_cap).
 * GZ_OK: *out_n = bytes written, *in_used (optional) = bytes up to the end of bvx$.
 * GZ_E_DATA: corrupt stream or more output than out_cap; GZ_E_TRUNC: input ends
 * before bvx$; GZ_E_NOMEM. d may be NULL (tables are then allocated on demand, only
 * when an FSE block appears). */
int gz_lzfse_decode_ex(gz_lzfse_dec *d, const u8 *in, size_t in_n, u8 *out, size_t out_cap,
                       size_t *out_n, size_t *in_used);
int gz_lzfse_decode(const u8 *in, size_t in_n, u8 *out, size_t out_cap, size_t *out_n, size_t *in_used);

/* Sum of the decoded block sizes, read from the block headers only (to size an
 * output buffer). GZ_OK, GZ_E_DATA (bad magic), GZ_E_TRUNC. */
int gz_lzfse_size(const u8 *in, size_t in_n, u64 *raw_size, size_t *in_used);

/* Raw LZVN stream (decmpfs types 7/8, APFS LZVN, bvxn payloads) up to its end-of-stream
 * opcode (0x06 + 7 bytes). GZ_OK at the end opcode; GZ_E_DATA (bad opcode/distance, or
 * more output than out_cap); GZ_E_TRUNC (input ends first). *out_n, *in_used as above. */
int gz_lzvn_decode(const u8 *in, size_t in_n, u8 *out, size_t out_cap, size_t *out_n, size_t *in_used);

#endif
