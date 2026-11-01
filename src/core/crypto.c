/*
 * 고깃ZIP - ZipCrypto and archive key derivation (7z AES-256, RAR 3.x, RAR 5.0)
 *
 * SHA-1 lives in sha1.c, SHA-256 in sha256.c, AES in aes.c.
 */
#include "crypto.h"
#include "crc32.h"

/* ======================= ZipCrypto ======================= */

#define ZC_UPDATE(c, b) do {                                                   \
        (c)->k0 = gz_crc32_byte((c)->k0, (u8)(b));                             \
        (c)->k1 = ((c)->k1 + ((c)->k0 & 0xff)) * 134775813u + 1;               \
        (c)->k2 = gz_crc32_byte((c)->k2, (u8)((c)->k1 >> 24));                 \
    } while (0)

void gz_zc_init(gz_zipcrypto *c, const u8 *pw, size_t n)
{
    c->k0 = 0x12345678u;
    c->k1 = 0x23456789u;
    c->k2 = 0x34567890u;
    for (size_t i = 0; i < n; i++) ZC_UPDATE(c, pw[i]);
}

void gz_zc_decrypt(gz_zipcrypto *c, u8 *buf, size_t n)
{
    gz_zipcrypto k = *c;
    for (size_t i = 0; i < n; i++) {
        u32 t = (k.k2 | 2) & 0xffff;
        u8 d = buf[i] ^ (u8)((t * (t ^ 1)) >> 8);
        ZC_UPDATE(&k, d);
        buf[i] = d;
    }
    *c = k;
}

void gz_zc_encrypt(gz_zipcrypto *c, u8 *buf, size_t n)
{
    gz_zipcrypto k = *c;
    for (size_t i = 0; i < n; i++) {
        u32 t = (k.k2 | 2) & 0xffff;
        u8 p = buf[i];
        buf[i] = p ^ (u8)((t * (t ^ 1)) >> 8);
        ZC_UPDATE(&k, p);
    }
    *c = k;
}

/* ======================= 7z AES-256 ======================= */

/* Rounds are hashed 64 at a time from a buffer holding 64 copies of the unit
 * (salt || password || counter): 64 units are exactly `unit` SHA blocks, so the
 * block kernel runs without per-round overhead; only the counters change. */
int gz_7z_kdf(const u8 *salt, size_t saltlen, const u8 *pw, size_t pwlen,
              unsigned power, u8 key[32])
{
    if (power == 0x3F) {
        size_t pos = 0;
        for (size_t i = 0; i < saltlen && pos < 32; i++) key[pos++] = salt[i];
        for (size_t i = 0; i < pwlen && pos < 32; i++) key[pos++] = pw[i];
        while (pos < 32) key[pos++] = 0;
        return GZ_OK;
    }
    if (power > 24) return GZ_E_LIMIT;

    gz_sha256 s;
    gz_sha256_init(&s);
    u64 rounds = (u64)1 << power, done = 0;
    size_t unit = saltlen + pwlen + 8;
    u8 *buf = (power >= 6 && unit <= 4096) ? (u8 *)gz_alloc(unit * 64) : 0;
    if (buf) {
        gz_sha_blocks_fn blocks = gz_sha256_kernel;
        for (u32 k = 0; k < 64; k++) {
            u8 *u = buf + k * unit;
            if (saltlen) __builtin_memcpy(u, salt, saltlen);
            if (pwlen) __builtin_memcpy(u + saltlen, pw, pwlen);
        }
        u8 *ctr = buf + saltlen + pwlen;
        for (; done < rounds; done += 64) {
            for (u32 k = 0; k < 64; k++) wr64(ctr + k * unit, done + k);
            blocks(s.h, buf, unit);
        }
        s.len = (u64)rounds * unit;     /* a multiple of 64: nothing buffered */
        gz_free(buf);
    }
    for (; done < rounds; done++) {
        u8 c[8];
        wr64(c, done);
        gz_sha256_update(&s, salt, saltlen);
        gz_sha256_update(&s, pw, pwlen);
        gz_sha256_update(&s, c, 8);
    }
    gz_sha256_final(&s, key);
    return GZ_OK;
}

/* ======================= RAR 3.x ======================= */

#define RAR3_ROUNDS 0x40000u

static inline u32 rol1(u32 x) { return (x << 1) | (x >> 31); }

/* unrar's SHA-1 (sha1_process_rar29) overwrites each block it hashes straight
 * from the caller's buffer with the last 16 expanded message words W[64..79]
 * (little-endian). Blocks completed through the context buffer are not. */
static void rar29_update(gz_sha1 *s, u8 *data, size_t len)
{
    size_t i = 0, j = s->n;
    s->len += len;
    if (j + len > 63) {
        i = 64 - j;
        __builtin_memcpy(s->buf + j, data, i);
        gz_sha1_kernel(s->h, s->buf, 1);
        for (; i + 63 < len; i += 64) {
            u32 w[16];
            u8 *b = data + i;
            gz_sha1_kernel(s->h, b, 1);
            for (int k = 0; k < 16; k++) w[k] = rd32be(b + 4 * k);
            for (int k = 16; k < 80; k++)
                w[k & 15] = rol1(w[(k + 13) & 15] ^ w[(k + 8) & 15] ^ w[(k + 2) & 15] ^ w[k & 15]);
            for (int k = 0; k < 16; k++) wr32(b + 4 * k, w[k]);
        }
        j = 0;
    }
    if (len > i) __builtin_memcpy(s->buf + j, data + i, len - i);
    s->n = (u32)(s->len & 63);
}

static void sha1_peek(const gz_sha1 *s, u8 out[20])
{
    gz_sha1 t = *s;
    gz_sha1_final(&t, out);
}

void gz_rar3_kdf(const u8 *pw, size_t pwlen, const u8 *salt, u8 key[16], u8 iv[16])
{
    u8 raw[254 + 8], d[20];
    gz_sha1 s;
    if (pwlen > 254) pwlen = 254;               /* RAR keeps 127 characters */
    pwlen &= ~(size_t)1;
    size_t rawlen = pwlen;
    if (pwlen) __builtin_memcpy(raw, pw, pwlen);
    if (salt) { __builtin_memcpy(raw + rawlen, salt, 8); rawlen += 8; }
    gz_sha1_init(&s);

    if (rawlen <= 64) {
        /* No block can be hashed straight from the password buffer, so the
         * rewrite never happens: hash 64 rounds per kernel call. */
        u8 buf[67 * 64];
        size_t unit = rawlen + 3, q = unit >> 6;
        gz_sha_blocks_fn blocks = gz_sha1_kernel;
        for (u32 k = 0; k < 64; k++)
            if (rawlen) __builtin_memcpy(buf + k * unit, raw, rawlen);
        for (u32 r = 0; r < RAR3_ROUNDS; r += 64) {
            for (u32 k = 0; k < 64; k++) {
                u8 *c = buf + k * unit + rawlen;
                u32 n = r + k;
                c[0] = (u8)n; c[1] = (u8)(n >> 8); c[2] = (u8)(n >> 16);
            }
            if (r % (RAR3_ROUNDS / 16) == 0) {
                /* IV byte from the digest after the first round of this batch */
                blocks(s.h, buf, q);
                gz_sha1 t;
                for (int i = 0; i < 5; i++) t.h[i] = s.h[i];
                t.len = (u64)r * unit + unit;
                t.n = (u32)(unit & 63);
                __builtin_memcpy(t.buf, buf + (q << 6), t.n);
                gz_sha1_final(&t, d);
                iv[r / (RAR3_ROUNDS / 16)] = d[19];
                blocks(s.h, buf + (q << 6), unit - q);
            } else {
                blocks(s.h, buf, unit);
            }
        }
        s.len = (u64)RAR3_ROUNDS * unit;
        s.n = 0;
    } else {
        for (u32 r = 0; r < RAR3_ROUNDS; r++) {
            u8 c[3] = { (u8)r, (u8)(r >> 8), (u8)(r >> 16) };
            rar29_update(&s, raw, rawlen);
            gz_sha1_update(&s, c, 3);
            if (r % (RAR3_ROUNDS / 16) == 0) {
                sha1_peek(&s, d);
                iv[r / (RAR3_ROUNDS / 16)] = d[19];
            }
        }
    }
    gz_sha1_final(&s, d);
    for (int i = 0; i < 4; i++)                 /* unrar stores the words little-endian */
        for (int j = 0; j < 4; j++) key[i * 4 + j] = d[i * 4 + 3 - j];
}

/* ======================= RAR 5.0 ======================= */

int gz_rar5_kdf(const u8 *pw, size_t pwlen, const u8 *salt, size_t saltlen, unsigned lg2,
                u8 key[32], u8 hash_key[32], u8 psw_check[8])
{
    u32 ist[8], ost[8], u[8], f[8];
    u8 t[32], be[4] = { 0, 0, 0, 1 };
    if (lg2 > 24 || saltlen > 64) return GZ_E_LIMIT;
    gz_hmac_sha256_pads(pw, pwlen, ist, ost);

    gz_hmac_sha256 h;
    for (int i = 0; i < 8; i++) { h.in.h[i] = ist[i]; h.out.h[i] = ost[i]; }
    h.in.len = h.out.len = 64;
    h.in.n = h.out.n = 0;
    gz_hmac_sha256_update(&h, salt, saltlen);
    gz_hmac_sha256_update(&h, be, 4);
    gz_hmac_sha256_final(&h, t);
    for (int i = 0; i < 8; i++) f[i] = u[i] = rd32be(t + 4 * i);

    gz_pbkdf2_sha256_iterate(ist, ost, u, f, (1u << lg2) - 1);
    for (int i = 0; i < 8; i++) wr32be(key + 4 * i, f[i]);
    gz_pbkdf2_sha256_iterate(ist, ost, u, f, 16);
    if (hash_key)
        for (int i = 0; i < 8; i++) wr32be(hash_key + 4 * i, f[i]);
    if (psw_check) {
        gz_pbkdf2_sha256_iterate(ist, ost, u, f, 16);
        for (int i = 0; i < 8; i++) wr32be(t + 4 * i, f[i]);
        for (int i = 0; i < 8; i++) psw_check[i] = 0;
        for (int i = 0; i < 32; i++) psw_check[i & 7] ^= t[i];
    }
    return GZ_OK;
}
