/*
 * 고깃ZIP - decryption primitives for ZIP archives
 *   - traditional PKWARE "ZipCrypto"
 *   - WinZip AES (AE-1/AE-2): AES-CTR + HMAC-SHA1 + PBKDF2-HMAC-SHA1
 */
#ifndef GZ_CRYPTO_H
#define GZ_CRYPTO_H
#include "base.h"

/* ---- ZipCrypto ---- */
typedef struct { u32 k0, k1, k2; } gz_zipcrypto;
void gz_zc_init(gz_zipcrypto *c, const u8 *pw, size_t n);
void gz_zc_decrypt(gz_zipcrypto *c, u8 *buf, size_t n);

/* ---- SHA-1 / HMAC / PBKDF2 ---- */
typedef struct { u32 h[5]; u64 len; u8 buf[64]; u32 n; } gz_sha1;
void gz_sha1_init(gz_sha1 *s);
void gz_sha1_update(gz_sha1 *s, const u8 *p, size_t n);
void gz_sha1_final(gz_sha1 *s, u8 out[20]);

typedef struct { gz_sha1 in, out; } gz_hmac_sha1;
void gz_hmac_init(gz_hmac_sha1 *h, const u8 *key, size_t n);
void gz_hmac_update(gz_hmac_sha1 *h, const u8 *p, size_t n);
void gz_hmac_final(gz_hmac_sha1 *h, u8 out[20]);
void gz_pbkdf2_sha1(const u8 *pw, size_t pwn, const u8 *salt, size_t sn,
                    u32 iter, u8 *out, size_t outn);

/* ---- AES-CTR (WinZip flavour: little-endian 128-bit counter from 1) ---- */
typedef struct {
    GZ_ALIGN(16) u8 rk[16 * 15];   /* expanded round keys, FIPS-197 byte order */
    int rounds;
    GZ_ALIGN(16) u8 ctr[16];
    GZ_ALIGN(16) u8 ks[16];        /* current key-stream block               */
    u32 ks_pos;                    /* bytes of ks already used (16 = empty)  */
} gz_aes_ctr;

void gz_aes_init(void);            /* build T-tables, call once */
void gz_aes_ctr_setup(gz_aes_ctr *a, const u8 *key, int keylen);

typedef void (*gz_aes_ctr_fn)(gz_aes_ctr *a, u8 *buf, size_t n);  /* in-place */
extern gz_aes_ctr_fn gz_aes_ctr_kernel;
void gz_aes_ctr_soft(gz_aes_ctr *a, u8 *buf, size_t n);
void gz_aes_ctr_aesni(gz_aes_ctr *a, u8 *buf, size_t n);
void gz_aes_ctr_aesni_avx(gz_aes_ctr *a, u8 *buf, size_t n);

#endif
