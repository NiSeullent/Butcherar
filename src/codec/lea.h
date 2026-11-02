/*
 * 고깃ZIP - LEA block cipher (KS X 3246 / TTAS.KO-12.0223), encryption direction
 *
 * 128-bit blocks, 128/192/256-bit keys (24/28/32 rounds of 32-bit ARX). Used by
 * EGG archives (encryption methods 5 and 6) in counter mode; only the forward
 * cipher is needed. Portable C, little-endian words like the specification.
 */
#ifndef GZ_LEA_H
#define GZ_LEA_H
#include "base.h"

typedef struct {
    u32 rk[32][6];
    u32 rounds;
} gz_lea;

/* keylen 16, 24 or 32; returns GZ_OK or GZ_E_METHOD */
int  gz_lea_set_key(gz_lea *k, const u8 *key, u32 keylen);
void gz_lea_encrypt_block(const gz_lea *k, const u8 in[16], u8 out[16]);

/* CTR as used by EGG: 16-byte big-endian counter starting at 0, incremented
 * after every block; keystream = LEA(counter). In place, any length. */
typedef struct {
    gz_lea key;
    u8 ctr[16];
    u8 ks[16];
    u32 ks_pos;               /* bytes of ks used (16 = empty) */
} gz_lea_ctr;

void gz_lea_ctr_init(gz_lea_ctr *c, const u8 *key, u32 keylen);
void gz_lea_ctr_crypt(gz_lea_ctr *c, u8 *buf, size_t n);

#endif
