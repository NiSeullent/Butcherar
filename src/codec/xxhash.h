/*
 * 고깃ZIP - xxHash32 / xxHash64 (portable, one-shot and streaming)
 *
 * Used by Zstandard (content checksum = low 32 bits of XXH64, seed 0) and the
 * LZ4 frame format (header / block / content checksums = XXH32, seed 0).
 */
#ifndef GZ_XXHASH_H
#define GZ_XXHASH_H
#include "base.h"

u32 gz_xxh32(const void *p, size_t n, u32 seed);
u64 gz_xxh64(const void *p, size_t n, u64 seed);

typedef struct gz_xxh32_state {
    u32 v[4];
    u32 total;          /* low 32 bits of the length (all XXH32 needs) */
    u32 large;          /* total >= 16 at some point                   */
    u32 nbuf;
    u8  buf[16];
    u32 seed;
} gz_xxh32_state;

typedef struct gz_xxh64_state {
    u64 v[4];
    u64 total;
    u64 seed;
    u32 nbuf;
    u8  buf[32];
} gz_xxh64_state;

void gz_xxh32_init(gz_xxh32_state *s, u32 seed);
void gz_xxh32_update(gz_xxh32_state *s, const void *p, size_t n);
u32  gz_xxh32_digest(const gz_xxh32_state *s);

void gz_xxh64_init(gz_xxh64_state *s, u64 seed);
void gz_xxh64_update(gz_xxh64_state *s, const void *p, size_t n);
u64  gz_xxh64_digest(const gz_xxh64_state *s);

#endif
