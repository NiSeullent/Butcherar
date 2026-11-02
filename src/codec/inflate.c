/*
 * 고깃ZIP - streaming Deflate / Deflate64 decoder (shared part)
 *
 * The hot decode loop lives in inflate_impl.h and is compiled several times
 * with different instruction-set targets:
 *
 *   gz_inflate_x86   i586 integer code, 4-byte copies      (32-bit build)
 *   gz_inflate_mmx   MMX 8-byte copies                      (32-bit build)
 *   gz_inflate_sse   SSE 16-byte copies                     (32-bit build)
 *   gz_inflate_sse2  SSE2 16-byte copies
 *   gz_inflate_avx   AVX 32-byte copies (VEX)
 *   gz_inflate_avx2  AVX2 32-byte copies + BMI2 bit extraction
 */
#include "inflate.h"
#include "crc32.h"

#if defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#elif defined(__aarch64__)
#include <arm_neon.h>
#endif

#if defined(__x86_64__)
gz_inflate_fn gz_inflate_kernel = gz_inflate_sse2;
#elif defined(__aarch64__)
gz_inflate_fn gz_inflate_kernel = gz_inflate_neon;
#else
gz_inflate_fn gz_inflate_kernel = gz_inflate_x86;
#endif

u32 gz_lit_templ[288], gz_lit_templ64[288];
u32 gz_dist_templ[32], gz_dist_templ64[32], gz_pre_templ[19];

static const u16 k_len_base[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
};
static const u8 k_len_extra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};
static const u16 k_dist_base[32] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193,
    12289, 16385, 24577, 32769, 49153
};
static const u8 k_dist_extra[32] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14
};

#define ENT(val, extra) (((u32)(val) << 16) | ((u32)(extra) << 8))

void gz_inflate_init(void)
{
    for (u32 i = 0; i < 256; i++) gz_lit_templ[i] = GZE_LIT | ENT(i, 0);
    gz_lit_templ[256] = GZE_EXC | ENT(0, 0);
    for (u32 i = 0; i < 29; i++) gz_lit_templ[257 + i] = ENT(k_len_base[i], k_len_extra[i]);
    gz_lit_templ[286] = gz_lit_templ[287] = GZE_EXC | ENT(1, 0);
    for (u32 i = 0; i < 288; i++) gz_lit_templ64[i] = gz_lit_templ[i];
    gz_lit_templ64[285] = ENT(3, 16);              /* Deflate64: 3 + 16 extra bits */

    for (u32 i = 0; i < 32; i++) gz_dist_templ64[i] = ENT(k_dist_base[i], k_dist_extra[i]);
    for (u32 i = 0; i < 30; i++) gz_dist_templ[i] = gz_dist_templ64[i];
    gz_dist_templ[30] = gz_dist_templ[31] = GZE_EXC | ENT(1, 0);

    for (u32 i = 0; i < 19; i++) gz_pre_templ[i] = ENT(i, 0);
}

static u32 bitrev(u32 v, u32 n)
{
    u32 r = 0;
    while (n--) { r = (r << 1) | (v & 1); v >>= 1; }
    return r;
}

/*
 * Build a canonical Huffman decode table (LSB-first bit order).
 * Primary table of 2^tbits entries, codes longer than tbits go to subtables
 * sized like zlib's inflate_table(). Returns 0 or -1 on an invalid code.
 */
int gz_build_table(u32 *table, u32 tbits, u32 tsize, const u8 *lens, u32 nsym,
                   const u32 *templ, int allow_incomplete)
{
    u16 count[16], offs[16], sorted[320];
    u32 remaining[16];
    u32 i, len, maxlen;
    const u32 tmask = (1u << tbits) - 1;

    for (i = 0; i < 16; i++) count[i] = 0;
    for (i = 0; i < nsym; i++) count[lens[i]]++;
    count[0] = 0;
    for (maxlen = 15; maxlen > 0 && !count[maxlen]; maxlen--) {}

    if (maxlen == 0) {                 /* no codes at all: everything invalid */
        for (i = 0; i <= tmask; i++) table[i] = GZE_EXC | ENT(1, 0) | 1;
        return 0;
    }

    int left = 1;
    for (len = 1; len <= 15; len++) {
        left <<= 1;
        left -= count[len];
        if (left < 0) return -1;       /* over-subscribed */
    }
    if (left > 0) {
        if (!allow_incomplete || maxlen != 1) return -1;   /* incomplete */
        for (i = 0; i <= tmask; i++) table[i] = GZE_EXC | ENT(1, 0) | 1;
    }

    offs[1] = 0;
    for (len = 1; len < 15; len++) offs[len + 1] = (u16)(offs[len] + count[len]);
    for (i = 0; i < nsym; i++)
        if (lens[i]) sorted[offs[lens[i]]++] = (u16)i;
    for (i = 0; i < 16; i++) remaining[i] = count[i];

    u32 code = 0, si = 0;
    u32 next_free = 1u << tbits;
    u32 cur_prefix = 0xffffffffu, sub_off = 0, sub_bits = 0;

    for (len = 1; len <= maxlen; len++) {
        for (u32 k = 0; k < count[len]; k++, si++) {
            u32 sym = sorted[si];
            u32 rev = bitrev(code, len);
            if (len <= tbits) {
                u32 e = templ[sym] | len;
                for (u32 j = rev; j <= tmask; j += 1u << len) table[j] = e;
            } else {
                u32 prefix = rev & tmask;
                if (prefix != cur_prefix) {
                    u32 sb = len - tbits;
                    int lf = 1 << sb;
                    while (sb + tbits < maxlen) {
                        lf -= (int)remaining[sb + tbits];
                        if (lf <= 0) break;
                        sb++;
                        lf <<= 1;
                    }
                    if (next_free + (1u << sb) > tsize) return -1;
                    cur_prefix = prefix;
                    sub_off = next_free;
                    sub_bits = sb;
                    table[prefix] = GZE_SUB | ENT(sub_off, sb) | tbits;
                    next_free += 1u << sb;
                }
                u32 e = templ[sym] | (len - tbits);
                for (u32 j = rev >> tbits; j < (1u << sub_bits); j += 1u << (len - tbits))
                    table[sub_off + j] = e;
            }
            remaining[len]--;
            code++;
        }
        code <<= 1;
    }
    return 0;
}

/* ---- buffer management ------------------------------------------------ */

gz_inflater *gz_inflater_new(void)
{
    size_t isz = GZ_ILOOKBEHIND + GZ_ICAP + GZ_IPAD;
    size_t osz = GZ_WSIZE + GZ_OCHUNK + GZ_OMARGIN;
    size_t total = sizeof(gz_inflater) + 64 + isz + 64 + osz + 64;
    u8 *mem = (u8 *)gz_alloc_big(total);
    if (!mem) return 0;
    gz_inflater *z = (gz_inflater *)mem;
    u8 *p = mem + ((sizeof(gz_inflater) + 63) & ~(size_t)63);
    z->ibuf = p;
    p += (isz + 63) & ~(size_t)63;
    z->obuf = p;
    z->mem = mem;
    z->mem_size = total;
    return z;
}

void gz_inflater_free(gz_inflater *z)
{
    if (z) gz_free_big(z->mem, z->mem_size);
}

int gz_in_refill(gz_inflater *z, const gz_stream_io *io, const u8 *in, const u8 **new_in)
{
    if (z->in_eof) return GZ_E_TRUNC;
    u8 *base = z->ibuf + GZ_ILOOKBEHIND;
    size_t rem = (size_t)(z->in_end - in);
    /* keep 8 bytes of look-behind for the bit buffer (stored-block rewind) */
    __builtin_memmove(base - 8, in - 8, rem + 8);
    size_t fill = rem;
    while (fill < 512) {
        u32 got = 0;
        int r = io->read(io->ctx, base + fill, (u32)(GZ_ICAP - fill), &got);
        if (r) return r;
        if (!got) { z->in_eof = 1; break; }
        fill += got;
    }
    z->in_end = base + fill;
    __builtin_memset(base + fill, 0, GZ_IPAD);
    z->in_fast_end = z->in_eof ? z->in_end + 32 : z->in_end - 64;
    *new_in = base;
    return GZ_OK;
}

int gz_out_flush(gz_inflater *z, const gz_stream_io *io, u8 *out, u8 **new_out)
{
    size_t n = (size_t)(out - z->flushed);
    if (n) {
        z->crc = gz_crc32(z->crc, z->flushed, n);
        z->total_out += n;
        int r = io->write(io->ctx, z->flushed, n);
        if (r) return r;
    }
    size_t have = (size_t)(out - z->obuf);
    size_t keep = have < GZ_WSIZE ? have : GZ_WSIZE;
    if (have > keep) __builtin_memmove(z->obuf, out - keep, keep);
    *new_out = z->obuf + keep;
    z->flushed = *new_out;
    return GZ_OK;
}

static int inflate_start(gz_inflater *z, const gz_stream_io *io, int deflate64, int nsis, const u8 *ord)
{
    u8 *base = z->ibuf + GZ_ILOOKBEHIND;
    __builtin_memset(z->ibuf, 0, GZ_ILOOKBEHIND);
    z->deflate64 = deflate64;
    z->nsis = nsis;
    z->crc = 0;
    z->total_out = 0;
    z->in_eof = 0;
    z->in_end = base;
    z->in_fast_end = base;       /* forces a refill on the first symbol */
    z->flushed = z->obuf;
    z->rest = 0;
    z->rest_len = 0;
    z->pre_ord = ord;
    int r = gz_inflate_kernel(z, io);
    z->pre_ord = 0;
    return r;
}

int gz_inflate_run(gz_inflater *z, const gz_stream_io *io, int deflate64)
{
    return inflate_start(z, io, deflate64, 0, 0);
}

int gz_inflate_run_nsis(gz_inflater *z, const gz_stream_io *io)
{
    return inflate_start(z, io, 0, 1, 0);
}

int gz_inflate_run_order(gz_inflater *z, const gz_stream_io *io, const u8 ord[19])
{
    return inflate_start(z, io, 0, 0, ord);
}

int gz_inflate_run_dict(gz_inflater *z, const gz_stream_io *io, const u8 *dict, u32 dict_len)
{
    if (dict_len > GZ_INFLATE_DICT_MAX) {          /* only the last 32 KiB can be referenced */
        dict += dict_len - GZ_INFLATE_DICT_MAX;
        dict_len = GZ_INFLATE_DICT_MAX;
    }
    u8 *base = z->ibuf + GZ_ILOOKBEHIND;
    __builtin_memset(z->ibuf, 0, GZ_ILOOKBEHIND);
    z->deflate64 = 0;
    z->nsis = 0;
    z->pre_ord = 0;
    z->crc = 0;
    z->total_out = 0;
    z->in_eof = 0;
    z->in_end = base;
    z->in_fast_end = base;
    if (dict_len) __builtin_memmove(z->obuf, dict, dict_len);   /* dict may live in obuf */
    z->flushed = z->obuf + dict_len;   /* the kernel starts writing here */
    z->rest = 0;
    z->rest_len = 0;
    return gz_inflate_kernel(z, io);
}

int gz_store_run(gz_inflater *z, const gz_stream_io *io)
{
    z->crc = 0;
    z->total_out = 0;
    for (;;) {
        u32 got = 0;
        int r = io->read(io->ctx, z->obuf, GZ_OCHUNK, &got);
        if (r) return r;
        if (!got) return GZ_OK;
        z->crc = gz_crc32(z->crc, z->obuf, got);
        z->total_out += got;
        r = io->write(io->ctx, z->obuf, got);
        if (r) return r;
    }
}

/* ---- kernel instantiations --------------------------------------------- */

#if defined(__i386__)
#  define GZV_FN   gz_inflate_x86
#  define GZV_KIND 0
#  include "inflate_impl.h"

#  define GZV_ATTR __attribute__((target("mmx")))
#  define GZV_FN   gz_inflate_mmx
#  define GZV_KIND 1
#  include "inflate_impl.h"

#  define GZV_ATTR __attribute__((target("sse")))
#  define GZV_FN   gz_inflate_sse
#  define GZV_KIND 2
#  include "inflate_impl.h"
#elif defined(__x86_64__)
int gz_inflate_x86(gz_inflater *z, const gz_stream_io *io) { return gz_inflate_sse2(z, io); }
int gz_inflate_mmx(gz_inflater *z, const gz_stream_io *io) { return gz_inflate_sse2(z, io); }
int gz_inflate_sse(gz_inflater *z, const gz_stream_io *io) { return gz_inflate_sse2(z, io); }
#endif

#if defined(__i386__) || defined(__x86_64__)
/* per-function target attributes (GCC and clang); the binary itself needs only i586 / x86-64 */
#define GZV_ATTR __attribute__((target("sse2")))
#define GZV_FN   gz_inflate_sse2
#define GZV_KIND 3
#include "inflate_impl.h"

#define GZV_ATTR __attribute__((target("avx")))
#define GZV_FN   gz_inflate_avx
#define GZV_KIND 4
#include "inflate_impl.h"

#define GZV_ATTR __attribute__((target("avx2,bmi,bmi2")))
#define GZV_FN   gz_inflate_avx2
#define GZV_KIND 5
#include "inflate_impl.h"

#elif defined(__aarch64__)
/* AArch64: Advanced SIMD (NEON) is part of the base architecture */
#define GZV_FN   gz_inflate_neon
#define GZV_KIND 6
#include "inflate_impl.h"
int gz_inflate_x86(gz_inflater *z, const gz_stream_io *io) { return gz_inflate_neon(z, io); }
int gz_inflate_mmx(gz_inflater *z, const gz_stream_io *io) { return gz_inflate_neon(z, io); }
int gz_inflate_sse(gz_inflater *z, const gz_stream_io *io) { return gz_inflate_neon(z, io); }
int gz_inflate_sse2(gz_inflater *z, const gz_stream_io *io) { return gz_inflate_neon(z, io); }
int gz_inflate_avx(gz_inflater *z, const gz_stream_io *io) { return gz_inflate_neon(z, io); }
int gz_inflate_avx2(gz_inflater *z, const gz_stream_io *io) { return gz_inflate_neon(z, io); }

#else
/* other targets: portable C kernel */
#define GZV_FN   gz_inflate_x86
#define GZV_KIND 0
#include "inflate_impl.h"
int gz_inflate_mmx(gz_inflater *z, const gz_stream_io *io) { return gz_inflate_x86(z, io); }
int gz_inflate_sse(gz_inflater *z, const gz_stream_io *io) { return gz_inflate_x86(z, io); }
int gz_inflate_sse2(gz_inflater *z, const gz_stream_io *io) { return gz_inflate_x86(z, io); }
int gz_inflate_avx(gz_inflater *z, const gz_stream_io *io) { return gz_inflate_x86(z, io); }
int gz_inflate_avx2(gz_inflater *z, const gz_stream_io *io) { return gz_inflate_x86(z, io); }
#endif
