/*
 * 고깃ZIP - CRC-64/XZ (ECMA-182 polynomial, reflected; .xz, 7z-style checks)
 * check("123456789") = 0x995DC9BBDF1939FA
 */
#ifndef GZ_CRC64_H
#define GZ_CRC64_H
#include "base.h"

/* Same usage as gz_crc32: start with 0, feed chunks, the result is the final CRC. */
typedef u64 (*gz_crc64_fn)(u64 crc, const u8 *p, size_t n);
extern gz_crc64_fn gz_crc64_kernel;

static inline u64 gz_crc64(u64 crc, const void *p, size_t n)
{
    return gz_crc64_kernel(crc, (const u8 *)p, n);
}

void gz_crc64_init(void);          /* builds tables; called by gz_crc32_init */
extern u64 gz_crc64_table[8][256];

u64 gz_crc64_slice8(u64 crc, const u8 *p, size_t n);
u64 gz_crc64_pclmul(u64 crc, const u8 *p, size_t n);    /* SSE4.1 + PCLMULQDQ   */
u64 gz_crc64_vpclmul(u64 crc, const u8 *p, size_t n);   /* AVX2 + VPCLMULQDQ    */
u64 gz_crc64_pmull(u64 crc, const u8 *p, size_t n);     /* AArch64 PMULL        */

#endif
