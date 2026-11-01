/*
 * 고깃ZIP - xxHash32 / xxHash64
 *
 * Straight implementation of the reference algorithm: four independent lanes
 * (16 / 32 bytes per round) so the multiplies pipeline well, then a merge and an
 * avalanche over the tail. Little-endian loads via rd32/rd64.
 */
#include "xxhash.h"

#define P32_1 0x9E3779B1u
#define P32_2 0x85EBCA77u
#define P32_3 0xC2B2AE3Du
#define P32_4 0x27D4EB2Fu
#define P32_5 0x165667B1u

#define P64_1 0x9E3779B185EBCA87ull
#define P64_2 0xC2B2AE3D27D4EB4Full
#define P64_3 0x165667B19E3779F9ull
#define P64_4 0x85EBCA77C2B2AE63ull
#define P64_5 0x27D4EB2F165667C5ull

GZ_INLINE u32 rotl32(u32 x, int r) { return (x << r) | (x >> (32 - r)); }
GZ_INLINE u64 rotl64(u64 x, int r) { return (x << r) | (x >> (64 - r)); }

/* ---------------- XXH32 ---------------- */

GZ_INLINE u32 r32(u32 acc, u32 in)
{
    acc += in * P32_2;
    acc = rotl32(acc, 13);
    acc *= P32_1;
    /* keep the four lanes scalar: GCC/clang otherwise vectorize them into a much
     * slower SIMD multiply emulation (SSE2 has no 32-bit multiply) */
    __asm__("" : "+r"(acc));
    return acc;
}

/* consume whole 16-byte stripes; returns the pointer after the last one */
static const u8 *xxh32_stripes(u32 v[4], const u8 *p, const u8 *end)
{
    u32 a = v[0], b = v[1], c = v[2], d = v[3];
    while ((size_t)(end - p) >= 16) {
        a = r32(a, rd32(p));
        b = r32(b, rd32(p + 4));
        c = r32(c, rd32(p + 8));
        d = r32(d, rd32(p + 12));
        p += 16;
    }
    v[0] = a; v[1] = b; v[2] = c; v[3] = d;
    return p;
}

static u32 xxh32_finish(u32 h, const u8 *p, size_t n)
{
    while (n >= 4) {
        h += rd32(p) * P32_3;
        h = rotl32(h, 17) * P32_4;
        p += 4;
        n -= 4;
    }
    while (n--) {
        h += (*p++) * P32_5;
        h = rotl32(h, 11) * P32_1;
    }
    h ^= h >> 15;
    h *= P32_2;
    h ^= h >> 13;
    h *= P32_3;
    h ^= h >> 16;
    return h;
}

static void xxh32_lanes(u32 v[4], u32 seed)
{
    v[0] = seed + P32_1 + P32_2;
    v[1] = seed + P32_2;
    v[2] = seed;
    v[3] = seed - P32_1;
}

u32 gz_xxh32(const void *data, size_t n, u32 seed)
{
    const u8 *p = (const u8 *)data, *end = p + n;
    u32 h;
    if (n >= 16) {
        u32 v[4];
        xxh32_lanes(v, seed);
        p = xxh32_stripes(v, p, end);
        h = rotl32(v[0], 1) + rotl32(v[1], 7) + rotl32(v[2], 12) + rotl32(v[3], 18);
    } else {
        h = seed + P32_5;
    }
    h += (u32)n;
    return xxh32_finish(h, p, (size_t)(end - p));
}

void gz_xxh32_init(gz_xxh32_state *s, u32 seed)
{
    __builtin_memset(s, 0, sizeof *s);
    s->seed = seed;
    xxh32_lanes(s->v, seed);
}

void gz_xxh32_update(gz_xxh32_state *s, const void *data, size_t n)
{
    const u8 *p = (const u8 *)data, *end = p + n;
    s->total += (u32)n;
    if (n >= 16 || s->total >= 16) s->large = 1;
    if (s->nbuf + n < 16) {
        __builtin_memcpy(s->buf + s->nbuf, p, n);
        s->nbuf += (u32)n;
        return;
    }
    if (s->nbuf) {
        u32 k = 16 - s->nbuf;
        __builtin_memcpy(s->buf + s->nbuf, p, k);
        xxh32_stripes(s->v, s->buf, s->buf + 16);
        p += k;
        s->nbuf = 0;
    }
    p = xxh32_stripes(s->v, p, end);
    s->nbuf = (u32)(end - p);
    __builtin_memcpy(s->buf, p, s->nbuf);
}

u32 gz_xxh32_digest(const gz_xxh32_state *s)
{
    u32 h;
    if (s->large)
        h = rotl32(s->v[0], 1) + rotl32(s->v[1], 7) + rotl32(s->v[2], 12) + rotl32(s->v[3], 18);
    else
        h = s->seed + P32_5;
    h += s->total;
    return xxh32_finish(h, s->buf, s->nbuf);
}

/* ---------------- XXH64 ---------------- */

GZ_INLINE u64 r64(u64 acc, u64 in)
{
    acc += in * P64_2;
    acc = rotl64(acc, 31);
    return acc * P64_1;
}

GZ_INLINE u64 merge64(u64 h, u64 v)
{
    h ^= r64(0, v);
    return h * P64_1 + P64_4;
}

static const u8 *xxh64_stripes(u64 v[4], const u8 *p, const u8 *end)
{
    u64 a = v[0], b = v[1], c = v[2], d = v[3];
    while ((size_t)(end - p) >= 32) {
        a = r64(a, rd64(p));
        b = r64(b, rd64(p + 8));
        c = r64(c, rd64(p + 16));
        d = r64(d, rd64(p + 24));
        p += 32;
    }
    v[0] = a; v[1] = b; v[2] = c; v[3] = d;
    return p;
}

static u64 xxh64_converge(const u64 v[4])
{
    u64 h = rotl64(v[0], 1) + rotl64(v[1], 7) + rotl64(v[2], 12) + rotl64(v[3], 18);
    h = merge64(h, v[0]);
    h = merge64(h, v[1]);
    h = merge64(h, v[2]);
    return merge64(h, v[3]);
}

static u64 xxh64_finish(u64 h, const u8 *p, size_t n)
{
    while (n >= 8) {
        h ^= r64(0, rd64(p));
        h = rotl64(h, 27) * P64_1 + P64_4;
        p += 8;
        n -= 8;
    }
    if (n >= 4) {
        h ^= (u64)rd32(p) * P64_1;
        h = rotl64(h, 23) * P64_2 + P64_3;
        p += 4;
        n -= 4;
    }
    while (n--) {
        h ^= (*p++) * P64_5;
        h = rotl64(h, 11) * P64_1;
    }
    h ^= h >> 33;
    h *= P64_2;
    h ^= h >> 29;
    h *= P64_3;
    h ^= h >> 32;
    return h;
}

static void xxh64_lanes(u64 v[4], u64 seed)
{
    v[0] = seed + P64_1 + P64_2;
    v[1] = seed + P64_2;
    v[2] = seed;
    v[3] = seed - P64_1;
}

u64 gz_xxh64(const void *data, size_t n, u64 seed)
{
    const u8 *p = (const u8 *)data, *end = p + n;
    u64 h;
    if (n >= 32) {
        u64 v[4];
        xxh64_lanes(v, seed);
        p = xxh64_stripes(v, p, end);
        h = xxh64_converge(v);
    } else {
        h = seed + P64_5;
    }
    h += (u64)n;
    return xxh64_finish(h, p, (size_t)(end - p));
}

void gz_xxh64_init(gz_xxh64_state *s, u64 seed)
{
    __builtin_memset(s, 0, sizeof *s);
    s->seed = seed;
    xxh64_lanes(s->v, seed);
}

void gz_xxh64_update(gz_xxh64_state *s, const void *data, size_t n)
{
    const u8 *p = (const u8 *)data, *end = p + n;
    s->total += n;
    if (s->nbuf + n < 32) {
        __builtin_memcpy(s->buf + s->nbuf, p, n);
        s->nbuf += (u32)n;
        return;
    }
    if (s->nbuf) {
        u32 k = 32 - s->nbuf;
        __builtin_memcpy(s->buf + s->nbuf, p, k);
        xxh64_stripes(s->v, s->buf, s->buf + 32);
        p += k;
        s->nbuf = 0;
    }
    p = xxh64_stripes(s->v, p, end);
    s->nbuf = (u32)(end - p);
    __builtin_memcpy(s->buf, p, s->nbuf);
}

u64 gz_xxh64_digest(const gz_xxh64_state *s)
{
    u64 h = s->total >= 32 ? xxh64_converge(s->v) : s->seed + P64_5;
    h += s->total;
    return xxh64_finish(h, s->buf, s->nbuf);
}
