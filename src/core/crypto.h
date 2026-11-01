/*
 * 고깃ZIP - cryptographic primitives
 *
 *   ZipCrypto (PKWARE traditional)
 *   SHA-1, HMAC-SHA1, PBKDF2-HMAC-SHA1           (sha1.c)    WinZip AES, RAR 3.x
 *   SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256     (sha256.h)  7z AES, RAR 5.0
 *   AES-128/192/256: ECB, CBC, WinZip CTR        (aes.c)     ZIP, 7z, RAR
 *   Key derivation: 7z AES-256, RAR 3.x, RAR 5.0 (crypto.c)
 *   BLAKE2s/BLAKE2sp (blake2.h), CRC-64 (crc64.h)
 *
 * Every primitive has a portable C path; faster kernels (SHA-NI, AES-NI, VAES,
 * ARMv8 SHA/AES) are selected by gz_dispatch_init (cpu.c).
 */
#ifndef GZ_CRYPTO_H
#define GZ_CRYPTO_H
#include "base.h"
#include "sha256.h"
#include "blake2.h"
#include "crc64.h"

/* ---- ZipCrypto ---- */
typedef struct { u32 k0, k1, k2; } gz_zipcrypto;
void gz_zc_init(gz_zipcrypto *c, const u8 *pw, size_t n);
void gz_zc_decrypt(gz_zipcrypto *c, u8 *buf, size_t n);
void gz_zc_encrypt(gz_zipcrypto *c, u8 *buf, size_t n);

/* ---- SHA-1 / HMAC-SHA1 / PBKDF2-HMAC-SHA1 ---- */
extern gz_sha_blocks_fn gz_sha1_kernel;
void gz_sha1_blocks_c(u32 *state, const u8 *p, size_t nblocks);
void gz_sha1_blocks_shani(u32 *state, const u8 *p, size_t nblocks);   /* x86 only     */
void gz_sha1_blocks_arm(u32 *state, const u8 *p, size_t nblocks);     /* AArch64 only */

typedef struct { u32 h[5]; u64 len; u8 buf[64]; u32 n; } gz_sha1;
void gz_sha1_init(gz_sha1 *s);
void gz_sha1_update(gz_sha1 *s, const void *p, size_t n);
void gz_sha1_final(gz_sha1 *s, u8 out[20]);
void gz_sha1_calc(const void *p, size_t n, u8 out[20]);

typedef struct { gz_sha1 in, out; } gz_hmac_sha1;
void gz_hmac_init(gz_hmac_sha1 *h, const void *key, size_t n);
void gz_hmac_update(gz_hmac_sha1 *h, const void *p, size_t n);
void gz_hmac_final(gz_hmac_sha1 *h, u8 out[20]);
void gz_hmac_sha1_calc(const void *key, size_t kn, const void *p, size_t n, u8 out[20]);
void gz_pbkdf2_sha1(const void *pw, size_t pwn, const void *salt, size_t sn,
                    u32 iter, u8 *out, size_t outn);

/* ---- AES (FIPS-197) ----
 * A gz_aes holds either an encryption or a decryption key schedule (the
 * decryption one is the "equivalent inverse cipher" form shared by the T-table,
 * AES-NI and ARMv8 kernels). Buffers are processed in place; lengths of the
 * ECB/CBC calls are in bytes and must be multiples of 16. */
typedef struct {
    GZ_ALIGN(16) u8 rk[16 * 15];   /* round keys, FIPS-197 byte order */
    int rounds;                    /* 10 / 12 / 14 */
} gz_aes;

void gz_aes_init(void);            /* build T-tables, call once at start-up */
/* keylen in bytes: 16, 24 or 32. Returns GZ_OK or GZ_E_METHOD. */
int  gz_aes_set_encrypt_key(gz_aes *a, const u8 *key, int keylen);
int  gz_aes_set_decrypt_key(gz_aes *a, const u8 *key, int keylen);
void gz_aes_encrypt_block(const gz_aes *a, const u8 in[16], u8 out[16]);   /* encrypt key */
void gz_aes_decrypt_block(const gz_aes *a, const u8 in[16], u8 out[16]);   /* decrypt key */

typedef void (*gz_aes_ecb_fn)(const gz_aes *a, u8 *buf, size_t nblocks);
typedef void (*gz_aes_cbc_fn)(const gz_aes *a, u8 iv[16], u8 *buf, size_t nblocks);
extern gz_aes_ecb_fn gz_aes_ecb_enc_kernel, gz_aes_ecb_dec_kernel;
extern gz_aes_cbc_fn gz_aes_cbc_enc_kernel, gz_aes_cbc_dec_kernel;

static inline void gz_aes_ecb_encrypt(const gz_aes *a, u8 *buf, size_t n) { gz_aes_ecb_enc_kernel(a, buf, n >> 4); }
static inline void gz_aes_ecb_decrypt(const gz_aes *a, u8 *buf, size_t n) { gz_aes_ecb_dec_kernel(a, buf, n >> 4); }
/* CBC: iv is updated to the last ciphertext block, so a stream can be processed in
 * chunks. cbc_decrypt needs a decryption key, cbc_encrypt an encryption key. */
static inline void gz_aes_cbc_encrypt(const gz_aes *a, u8 iv[16], u8 *buf, size_t n) { gz_aes_cbc_enc_kernel(a, iv, buf, n >> 4); }
static inline void gz_aes_cbc_decrypt(const gz_aes *a, u8 iv[16], u8 *buf, size_t n) { gz_aes_cbc_dec_kernel(a, iv, buf, n >> 4); }

/* kernels (all exported so tests and benchmarks can call each one directly) */
void gz_aes_ecb_enc_soft(const gz_aes *a, u8 *buf, size_t nblocks);
void gz_aes_ecb_dec_soft(const gz_aes *a, u8 *buf, size_t nblocks);
void gz_aes_cbc_enc_soft(const gz_aes *a, u8 iv[16], u8 *buf, size_t nblocks);
void gz_aes_cbc_dec_soft(const gz_aes *a, u8 iv[16], u8 *buf, size_t nblocks);
void gz_aes_ecb_enc_aesni(const gz_aes *a, u8 *buf, size_t nblocks);       /* SSE4.1 + AES-NI */
void gz_aes_ecb_dec_aesni(const gz_aes *a, u8 *buf, size_t nblocks);
void gz_aes_cbc_enc_aesni(const gz_aes *a, u8 iv[16], u8 *buf, size_t nblocks);
void gz_aes_cbc_dec_aesni(const gz_aes *a, u8 iv[16], u8 *buf, size_t nblocks);
void gz_aes_ecb_enc_avx(const gz_aes *a, u8 *buf, size_t nblocks);         /* AVX (VEX) + AES-NI */
void gz_aes_ecb_dec_avx(const gz_aes *a, u8 *buf, size_t nblocks);
void gz_aes_cbc_enc_avx(const gz_aes *a, u8 iv[16], u8 *buf, size_t nblocks);
void gz_aes_cbc_dec_avx(const gz_aes *a, u8 iv[16], u8 *buf, size_t nblocks);
void gz_aes_cbc_dec_vaes(const gz_aes *a, u8 iv[16], u8 *buf, size_t nblocks);  /* AVX2 + VAES */
void gz_aes_ecb_enc_arm(const gz_aes *a, u8 *buf, size_t nblocks);         /* ARMv8 AES */
void gz_aes_ecb_dec_arm(const gz_aes *a, u8 *buf, size_t nblocks);
void gz_aes_cbc_enc_arm(const gz_aes *a, u8 iv[16], u8 *buf, size_t nblocks);
void gz_aes_cbc_dec_arm(const gz_aes *a, u8 iv[16], u8 *buf, size_t nblocks);

/* ---- AES-CTR, WinZip flavour: little-endian 128-bit counter starting at 1 ---- */
typedef struct {
    GZ_ALIGN(16) u8 rk[16 * 15];   /* encryption round keys */
    int rounds;
    GZ_ALIGN(16) u8 ctr[16];
    GZ_ALIGN(16) u8 ks[16];        /* current key-stream block               */
    u32 ks_pos;                    /* bytes of ks already used (16 = empty)  */
} gz_aes_ctr;

void gz_aes_ctr_setup(gz_aes_ctr *a, const u8 *key, int keylen);

typedef void (*gz_aes_ctr_fn)(gz_aes_ctr *a, u8 *buf, size_t n);  /* in place, any n; encrypt = decrypt */
extern gz_aes_ctr_fn gz_aes_ctr_kernel;
void gz_aes_ctr_soft(gz_aes_ctr *a, u8 *buf, size_t n);
void gz_aes_ctr_aesni(gz_aes_ctr *a, u8 *buf, size_t n);
void gz_aes_ctr_aesni_avx(gz_aes_ctr *a, u8 *buf, size_t n);
void gz_aes_ctr_vaes(gz_aes_ctr *a, u8 *buf, size_t n);
void gz_aes_ctr_arm(gz_aes_ctr *a, u8 *buf, size_t n);

/* ---- archive key derivation ---- */

/* 7z AES-256: key = SHA-256 over 2^power repetitions of (salt || password ||
 * 8-byte LE round counter). pw is the UTF-16LE password (no terminator).
 * power 0x3F: no hashing, key = salt || password, zero padded to 32 bytes.
 * power > 24 (beyond what 7-Zip accepts) returns GZ_E_LIMIT. */
int gz_7z_kdf(const u8 *salt, size_t saltlen, const u8 *pw, size_t pwlen,
              unsigned power, u8 key[32]);

/* RAR 3.x (RAR 2.9 / 4.x format) AES-128: exactly unrar's SetKey30, including the
 * in-place block rewrite of unrar's SHA-1 for passwords of 29+ characters.
 * pw: UTF-16LE password (truncated to 127 characters like RAR), salt: 8 bytes or NULL. */
void gz_rar3_kdf(const u8 *pw, size_t pwlen, const u8 *salt, u8 key[16], u8 iv[16]);

/* RAR 5.0 AES-256: key = PBKDF2-HMAC-SHA256(pw, salt, 2^lg2), hash_key and the
 * password check continue the same PBKDF2 chain for 16 and 32 more iterations;
 * psw_check is the 8-byte XOR fold of the latter. pw: UTF-8, salt: normally 16
 * bytes (<= 64). hash_key / psw_check may be NULL. lg2 > 24 returns GZ_E_LIMIT. */
int gz_rar5_kdf(const u8 *pw, size_t pwlen, const u8 *salt, size_t saltlen, unsigned lg2,
                u8 key[32], u8 hash_key[32], u8 psw_check[8]);

#endif
