#ifndef GZ_CRC32_H
#define GZ_CRC32_H
#include "base.h"

/* zlib-compatible CRC-32 (start with 0, feed chunks, result is final CRC). */
typedef u32 (*gz_crc32_fn)(u32 crc, const u8 *p, size_t n);
extern gz_crc32_fn gz_crc32_kernel;

static inline u32 gz_crc32(u32 crc, const void *p, size_t n)
{
    return gz_crc32_kernel(crc, (const u8 *)p, n);
}

void gz_crc32_init(void);                      /* builds CRC-32 and CRC-64 tables, call once */
u32  gz_crc32_byte(u32 raw_state, u8 b);       /* raw (non-inverted) state  */
extern u32 gz_crc_table[8][256];

u32 gz_crc32_slice8(u32 crc, const u8 *p, size_t n);
u32 gz_crc32_pclmul(u32 crc, const u8 *p, size_t n);   /* SSE4.1 + PCLMULQDQ */
u32 gz_crc32_avx(u32 crc, const u8 *p, size_t n);      /* AVX (VEX) + PCLMULQDQ */
u32 gz_crc32_vpclmul(u32 crc, const u8 *p, size_t n);  /* AVX2 + VPCLMULQDQ ymm */
u32 gz_crc32_arm(u32 crc, const u8 *p, size_t n);      /* AArch64 CRC32 instructions */
u32 gz_crc32_pmull(u32 crc, const u8 *p, size_t n);    /* AArch64 PMULL + CRC32 */

#endif
