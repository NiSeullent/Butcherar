/*
 * 고깃ZIP - BLAKE2s and BLAKE2sp (RFC 7693 / BLAKE2 spec; RAR 5.0 file hashes)
 *
 * BLAKE2sp runs 8 BLAKE2s leaves over 64-byte blocks dealt round-robin and
 * hashes the 8 leaf digests with a root node. The leaves are processed in
 * lock-step by a lane-parallel kernel (8 leaves = 8 SIMD lanes):
 *   gz_blake2sp_c (portable), _sse2, _ssse3, _avx2 (x86), _neon (AArch64).
 */
#ifndef GZ_BLAKE2_H
#define GZ_BLAKE2_H
#include "base.h"

/* ---- BLAKE2s (unkeyed, 1..32-byte digest) ---- */
typedef struct {
    u32 h[8];
    u32 t[2];          /* byte counter */
    u32 buflen, outlen;
    u8  buf[64];       /* the last block is held back until final */
} gz_blake2s;

void gz_blake2s_init(gz_blake2s *s, size_t outlen);
void gz_blake2s_update(gz_blake2s *s, const void *p, size_t n);
void gz_blake2s_final(gz_blake2s *s, u8 *out);           /* outlen bytes */
void gz_blake2s_calc(const void *p, size_t n, u8 *out, size_t outlen);

/* ---- BLAKE2sp (32-byte digest, as used by RAR 5.0) ---- */
typedef struct {
    u32 h[8][8];       /* leaf states, h[word][leaf] (lane-parallel layout) */
    u64 t;             /* bytes absorbed by each leaf in full superblocks   */
    u32 buflen;
    GZ_ALIGN(16) u8 buf[1024];
} gz_blake2sp;

void gz_blake2sp_init(gz_blake2sp *s);
void gz_blake2sp_update(gz_blake2sp *s, const void *p, size_t n);
void gz_blake2sp_final(gz_blake2sp *s, u8 out[32]);
void gz_blake2sp_calc(const void *p, size_t n, u8 out[32]);

/* Kernel: compress `nsuper` 512-byte superblocks (block i -> leaf i % 8), none of
 * them final. t = per-leaf byte count before the first one. */
typedef void (*gz_blake2sp_fn)(u32 h[8][8], u64 t, const u8 *p, size_t nsuper);
extern gz_blake2sp_fn gz_blake2sp_kernel;
void gz_blake2sp_c(u32 h[8][8], u64 t, const u8 *p, size_t nsuper);
void gz_blake2sp_sse2(u32 h[8][8], u64 t, const u8 *p, size_t nsuper);    /* x86 only */
void gz_blake2sp_ssse3(u32 h[8][8], u64 t, const u8 *p, size_t nsuper);
void gz_blake2sp_avx2(u32 h[8][8], u64 t, const u8 *p, size_t nsuper);
void gz_blake2sp_neon(u32 h[8][8], u64 t, const u8 *p, size_t nsuper);    /* AArch64 only */

#endif
