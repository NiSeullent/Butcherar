/*
 * 고깃ZIP - LEA block cipher (see lea.h)
 */
#include "lea.h"

/* key schedule constants: hex digits of sqrt(766995) ("LEA" in ASCII) */
static const u32 lea_delta[8] = {
    0xc3efe9dbu, 0x44626b02u, 0x79e27c8au, 0x78df30ecu, 0x715ea49eu, 0xc785da0au, 0xe04ef22au, 0xe5c40957u
};

GZ_INLINE u32 rol(u32 x, u32 n) { n &= 31; return n ? (x << n) | (x >> (32 - n)) : x; }
GZ_INLINE u32 ror(u32 x, u32 n) { n &= 31; return n ? (x >> n) | (x << (32 - n)) : x; }

int gz_lea_set_key(gz_lea *k, const u8 *key, u32 keylen)
{
    u32 t[8];
    if (keylen != 16 && keylen != 24 && keylen != 32) return GZ_E_METHOD;
    u32 nk = keylen / 4;
    for (u32 i = 0; i < nk; i++) t[i] = rd32(key + 4 * i);
    if (keylen == 16) {
        k->rounds = 24;
        for (u32 i = 0; i < 24; i++) {
            u32 d = lea_delta[i & 3];
            t[0] = rol(t[0] + rol(d, i), 1);
            t[1] = rol(t[1] + rol(d, i + 1), 3);
            t[2] = rol(t[2] + rol(d, i + 2), 6);
            t[3] = rol(t[3] + rol(d, i + 3), 11);
            u32 *r = k->rk[i];
            r[0] = t[0]; r[1] = t[1]; r[2] = t[2]; r[3] = t[1]; r[4] = t[3]; r[5] = t[1];
        }
    } else if (keylen == 24) {
        k->rounds = 28;
        static const u8 sh[6] = { 1, 3, 6, 11, 13, 17 };
        for (u32 i = 0; i < 28; i++) {
            u32 d = lea_delta[i % 6];
            for (u32 j = 0; j < 6; j++) {
                t[j] = rol(t[j] + rol(d, i + j), sh[j]);
                k->rk[i][j] = t[j];
            }
        }
    } else {
        k->rounds = 32;
        static const u8 sh[6] = { 1, 3, 6, 11, 13, 17 };
        for (u32 i = 0; i < 32; i++) {
            u32 d = lea_delta[i & 7];
            for (u32 j = 0; j < 6; j++) {
                u32 x = (6 * i + j) & 7;
                t[x] = rol(t[x] + rol(d, i + j), sh[j]);
                k->rk[i][j] = t[x];
            }
        }
    }
    return GZ_OK;
}

void gz_lea_encrypt_block(const gz_lea *k, const u8 in[16], u8 out[16])
{
    u32 x0 = rd32(in), x1 = rd32(in + 4), x2 = rd32(in + 8), x3 = rd32(in + 12);
    for (u32 i = 0; i < k->rounds; i++) {
        const u32 *r = k->rk[i];
        u32 n0 = rol((x0 ^ r[0]) + (x1 ^ r[1]), 9);
        u32 n1 = ror((x1 ^ r[2]) + (x2 ^ r[3]), 5);
        u32 n2 = ror((x2 ^ r[4]) + (x3 ^ r[5]), 3);
        x3 = x0;
        x0 = n0; x1 = n1; x2 = n2;
    }
    wr32(out, x0); wr32(out + 4, x1); wr32(out + 8, x2); wr32(out + 12, x3);
}

void gz_lea_ctr_init(gz_lea_ctr *c, const u8 *key, u32 keylen)
{
    gz_lea_set_key(&c->key, key, keylen);
    __builtin_memset(c->ctr, 0, 16);
    c->ks_pos = 16;
}

void gz_lea_ctr_crypt(gz_lea_ctr *c, u8 *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (c->ks_pos == 16) {
            gz_lea_encrypt_block(&c->key, c->ctr, c->ks);
            for (int j = 15; j >= 0 && !++c->ctr[j]; j--) {}
            c->ks_pos = 0;
        }
        buf[i] ^= c->ks[c->ks_pos++];
    }
}
