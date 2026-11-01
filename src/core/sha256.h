/*
 * 고깃ZIP - SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256
 *
 * Block kernels (selected by gz_dispatch_init):
 *   gz_sha256_blocks_c      portable C
 *   gz_sha256_blocks_shani  x86 SHA extensions (SHA-NI + SSE4.1)
 *   gz_sha256_blocks_arm    ARMv8 SHA2 instructions
 */
#ifndef GZ_SHA256_H
#define GZ_SHA256_H
#include "base.h"

/* Compress nblocks consecutive 64-byte blocks into the hash state (SHA-1: 5 words,
 * SHA-256: 8 words). Shared signature of every SHA block kernel. */
typedef void (*gz_sha_blocks_fn)(u32 *state, const u8 *p, size_t nblocks);

extern gz_sha_blocks_fn gz_sha256_kernel;
void gz_sha256_blocks_c(u32 *state, const u8 *p, size_t nblocks);
void gz_sha256_blocks_shani(u32 *state, const u8 *p, size_t nblocks);   /* x86 only    */
void gz_sha256_blocks_arm(u32 *state, const u8 *p, size_t nblocks);     /* AArch64 only */

typedef struct { u32 h[8]; u64 len; u8 buf[64]; u32 n; } gz_sha256;
void gz_sha256_init(gz_sha256 *s);
void gz_sha256_update(gz_sha256 *s, const void *p, size_t n);
void gz_sha256_final(gz_sha256 *s, u8 out[32]);       /* s must be re-initialised for reuse */
void gz_sha256_calc(const void *p, size_t n, u8 out[32]);  /* one shot */

/* HMAC-SHA256 (RFC 2104). A keyed context can be copied to MAC several messages. */
typedef struct { gz_sha256 in, out; } gz_hmac_sha256;
void gz_hmac_sha256_init(gz_hmac_sha256 *h, const void *key, size_t n);
void gz_hmac_sha256_update(gz_hmac_sha256 *h, const void *p, size_t n);
void gz_hmac_sha256_final(gz_hmac_sha256 *h, u8 out[32]);
void gz_hmac_sha256_calc(const void *key, size_t kn, const void *p, size_t n, u8 out[32]);

/* PBKDF2-HMAC-SHA256 (RFC 8018), any output length. iter >= 1 (0 is treated as 1). */
void gz_pbkdf2_sha256(const void *pw, size_t pwn, const void *salt, size_t sn,
                      u32 iter, u8 *out, size_t outn);

/* Internal helpers shared with the KDFs (crypto.c): HMAC pad states and the
 * PBKDF2 loop U(j+1) = HMAC(U(j)), F ^= U over `iter` iterations, both kept as
 * big-endian words. */
void gz_hmac_sha256_pads(const void *key, size_t n, u32 ist[8], u32 ost[8]);
void gz_pbkdf2_sha256_iterate(const u32 ist[8], const u32 ost[8], u32 u[8], u32 f[8], u32 iter);

#endif
