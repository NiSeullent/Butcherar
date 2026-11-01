/*
 * 고깃ZIP - Deflate decode kernel template.
 *
 * Included from inflate.c with:
 *   GZV_ATTR  target attribute for the kernel (e.g. __attribute__((target("avx2"))))
 *   GZV_FN    exported function name
 *   GZV_KIND  0 = x86 int, 1 = MMX, 2 = SSE, 3 = SSE2, 4 = AVX, 5 = AVX2+BMI2, 6 = NEON
 *
 * Streaming design: input is pulled through gz_in_refill() whenever the read
 * pointer passes in_fast_end; output is pushed through gz_out_flush() whenever
 * the write pointer passes out_fast_end. Both buffers have enough slack that
 * the inner loop never needs per-byte bounds checks.
 */

#define GZV_CAT2(a, b) a##b
#define GZV_CAT(a, b) GZV_CAT2(a, b)
#define GZV_COPY_MATCH GZV_CAT(GZV_FN, _copy_match)

#if GZV_KIND == 0
#  define GZV_W 4
#elif GZV_KIND == 1
#  define GZV_W 8
#elif GZV_KIND <= 3 || GZV_KIND == 6
#  define GZV_W 16
#else
#  define GZV_W 32
#endif

#ifndef GZV_ATTR
#  define GZV_ATTR
#endif

GZV_ATTR GZ_INLINE u8 *GZV_COPY_MATCH(u8 *out, u32 dist, u32 len)
{
    const u8 *src = out - dist;
    u8 *end = out + len;

    if (GZ_LIKELY(dist >= GZV_W)) {
        do {
#if GZV_KIND == 0
            wr32(out, rd32(src));
#elif GZV_KIND == 1
            __asm__ volatile("movq (%1), %%mm0\n\tmovq %%mm0, (%0)" : : "r"(out), "r"(src) : "memory");
#elif GZV_KIND == 2
            _mm_storeu_ps((float *)out, _mm_loadu_ps((const float *)src));
#elif GZV_KIND == 3
            _mm_storeu_si128((__m128i *)out, _mm_loadu_si128((const __m128i *)src));
#elif GZV_KIND == 6
            vst1q_u8(out, vld1q_u8(src));
#else
            _mm256_storeu_si256((__m256i *)out, _mm256_loadu_si256((const __m256i *)src));
#endif
            out += GZV_W; src += GZV_W;
        } while (out < end);
        return end;
    }
    if (dist == 1) {                     /* run of a single byte */
        u8 b = *src;
#if GZV_KIND == 0 || GZV_KIND == 1 || GZV_KIND == 2
        u32 v = b * 0x01010101u;
        do { wr32(out, v); wr32(out + 4, v); out += 8; } while (out < end);
#elif GZV_KIND == 3
        __m128i v = _mm_set1_epi8((char)b);
        do { _mm_storeu_si128((__m128i *)out, v); out += 16; } while (out < end);
#elif GZV_KIND == 6
        uint8x16_t v = vdupq_n_u8(b);
        do { vst1q_u8(out, v); out += 16; } while (out < end);
#else
        __m256i v = _mm256_set1_epi8((char)b);
        do { _mm256_storeu_si256((__m256i *)out, v); out += 32; } while (out < end);
#endif
        return end;
    }
#if GZV_W > 8
    if (dist >= 8) {
        do { wr64(out, rd64(src)); out += 8; src += 8; } while (out < end);
        return end;
    }
#endif
    if (dist >= 4) {
        do { wr32(out, rd32(src)); out += 4; src += 4; } while (out < end);
        return end;
    }
    do {                                  /* dist 2 or 3: sequential bytes */
        out[0] = src[0];
        out[1] = src[1];
        out[2] = src[2];
        out += 3; src += 3;
    } while (out < end);
    return end;
}

GZV_ATTR int GZV_FN(gz_inflater *z, const gz_stream_io *io)
{
    size_t bitbuf = 0;
    u32 bitcnt = 0;
    const u8 *in = z->ibuf + GZ_ILOOKBEHIND;
    const u8 *in_fast_end = z->in_fast_end;
    u8 *const obuf = z->obuf;
    u8 *out = z->flushed;    /* obuf, or after a preset dictionary (gz_inflate_run_dict) */
    u8 *const out_fast_end = obuf + GZ_WSIZE + GZ_OCHUNK;
    const int d64 = z->deflate64;
    const u32 *ltempl = d64 ? gz_lit_templ64 : gz_lit_templ;
    const u32 *dtempl = d64 ? gz_dist_templ64 : gz_dist_templ;
    u32 *const lt = z->lit;
    u32 *const dt = z->dist;
    int tables = 0;          /* 0 none, 1 fixed, 2 dynamic */
    u32 final;
    int err = GZ_OK;

#if defined(__x86_64__) || defined(__aarch64__)
#  define REFILL_FAST() do {                                   \
        bitbuf |= (size_t)rd64(in) << bitcnt;                   \
        in += (63 - bitcnt) >> 3;                               \
        bitcnt |= 56;                                           \
    } while (0)
#  define BB_WIDE 1
#else
#  define REFILL_FAST() do {                                   \
        bitbuf |= (size_t)rd32(in) << bitcnt;                   \
        in += (31 - bitcnt) >> 3;                               \
        bitcnt |= 24;                                           \
    } while (0)
#  define BB_WIDE 0
#endif
#define REFILL_IN() do {                                        \
        const u8 *ni_;                                          \
        err = gz_in_refill(z, io, in, &ni_);                    \
        if (err) goto fail;                                     \
        in = ni_;                                               \
        in_fast_end = z->in_fast_end;                           \
    } while (0)
#define NEED(n) do {                                            \
        if (bitcnt < (u32)(n)) {                                \
            if (in >= in_fast_end) REFILL_IN();                 \
            REFILL_FAST();                                      \
        }                                                       \
    } while (0)
#define BITS(n) ((u32)bitbuf & ((1u << (n)) - 1))
#define DROP(n) do { bitbuf >>= (n); bitcnt -= (n); } while (0)
#define FLUSH() do {                                            \
        u8 *no_;                                                \
        err = gz_out_flush(z, io, out, &no_);                   \
        if (err) goto fail;                                     \
        out = no_;                                              \
    } while (0)
#define FAIL(code) do { err = (code); goto fail; } while (0)

    do {
        NEED(3);
        final = BITS(1);
        u32 type = (u32)(bitbuf >> 1) & 3;
        DROP(3);

        if (type == 0) {
            /* ---- stored block ---- */
            DROP(bitcnt & 7);
            in -= bitcnt >> 3;               /* give whole bytes back */
            bitbuf = 0;
            bitcnt = 0;
            while (z->in_end - in < 4) {
                if (z->in_eof) FAIL(GZ_E_TRUNC);
                REFILL_IN();
            }
            u32 len = rd16(in), nlen = rd16(in + 2);
            in += 4;
            if ((len ^ 0xffffu) != nlen) FAIL(GZ_E_DATA);
            while (len) {
                size_t avail = (size_t)(z->in_end - in);
                if (!avail) {
                    if (z->in_eof) FAIL(GZ_E_TRUNC);
                    REFILL_IN();
                    continue;
                }
                if (out >= out_fast_end) FLUSH();
                size_t room = (size_t)(out_fast_end - out);
                size_t n = len;
                if (n > avail) n = avail;
                if (n > room) n = room;
                __builtin_memcpy(out, in, n);
                out += n; in += n; len -= (u32)n;
            }
            continue;
        }

        if (type == 1) {
            /* ---- fixed Huffman ---- */
            if (tables != 1) {
                u8 *l = z->lens;
                u32 i;
                for (i = 0; i < 144; i++) l[i] = 8;
                for (; i < 256; i++) l[i] = 9;
                for (; i < 280; i++) l[i] = 7;
                for (; i < 288; i++) l[i] = 8;
                for (i = 0; i < 32; i++) l[288 + i] = 5;
                if (gz_build_table(lt, GZ_LIT_TBITS, GZ_LIT_TSIZE, l, 288, ltempl, 0) ||
                    gz_build_table(dt, GZ_DIST_TBITS, GZ_DIST_TSIZE, l + 288, 32, dtempl, 0))
                    FAIL(GZ_E_DATA);
                tables = 1;
            }
        } else if (type == 2) {
            /* ---- dynamic Huffman ---- */
            static const u8 ord[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
            u8 pl[19];
            u8 *l = z->lens;
            u32 i;
            NEED(14);
            u32 hlit = BITS(5) + 257; DROP(5);
            u32 hdist = BITS(5) + 1;  DROP(5);
            u32 hclen = BITS(4) + 4;  DROP(4);
            if (hlit > 286 || hdist > (d64 ? 32u : 30u)) FAIL(GZ_E_DATA);
            for (i = 0; i < 19; i++) pl[i] = 0;
            for (i = 0; i < hclen; i++) {
                NEED(3);
                pl[ord[i]] = (u8)BITS(3);
                DROP(3);
            }
            if (gz_build_table(z->pre, 7, 128, pl, 19, gz_pre_templ, 0)) FAIL(GZ_E_DATA);

            u32 n = 0, total = hlit + hdist;
            while (n < total) {
                NEED(14);
                u32 e = z->pre[BITS(7)];
                if (e & GZE_EXC) FAIL(GZ_E_DATA);
                DROP(e & 0xff);
                u32 sym = e >> 16;
                if (sym < 16) {
                    l[n++] = (u8)sym;
                } else {
                    u32 rep;
                    u8 val = 0;
                    if (sym == 16) {
                        if (!n) FAIL(GZ_E_DATA);
                        val = l[n - 1];
                        rep = 3 + BITS(2); DROP(2);
                    } else if (sym == 17) {
                        rep = 3 + BITS(3); DROP(3);
                    } else {
                        rep = 11 + BITS(7); DROP(7);
                    }
                    if (n + rep > total) FAIL(GZ_E_DATA);
                    while (rep--) l[n++] = val;
                }
            }
            if (!l[256]) FAIL(GZ_E_DATA);       /* no end-of-block code */
            if (gz_build_table(lt, GZ_LIT_TBITS, GZ_LIT_TSIZE, l, hlit, ltempl, 1) ||
                gz_build_table(dt, GZ_DIST_TBITS, GZ_DIST_TSIZE, l + hlit, hdist, dtempl, 1))
                FAIL(GZ_E_DATA);
            tables = 2;
        } else {
            FAIL(GZ_E_DATA);
        }

        /* ---- Huffman block decode loop ---- */
        for (;;) {
            if (GZ_UNLIKELY(in >= in_fast_end)) REFILL_IN();
            if (GZ_UNLIKELY(out >= out_fast_end)) FLUSH();
            REFILL_FAST();

            u32 e = lt[BITS(GZ_LIT_TBITS)];
            if (GZ_UNLIKELY(e & GZE_SUB)) {
                DROP(GZ_LIT_TBITS);
                e = lt[(e >> 16) + BITS((e >> 8) & 0x1f)];
            }
            DROP(e & 0xff);

            if (e & GZE_LIT) {
                *out++ = (u8)(e >> 16);
#if BB_WIDE
                /* >= 41 bits left: two more primary-table literals fit */
                e = lt[BITS(GZ_LIT_TBITS)];
                if (e & GZE_LIT) {
                    DROP(e & 0xff);
                    *out++ = (u8)(e >> 16);
                    e = lt[BITS(GZ_LIT_TBITS)];
                    if (e & GZE_LIT) {
                        DROP(e & 0xff);
                        *out++ = (u8)(e >> 16);
                    }
                }
#else
                if (bitcnt >= GZ_LIT_TBITS) {
                    e = lt[BITS(GZ_LIT_TBITS)];
                    if (e & GZE_LIT) {
                        DROP(e & 0xff);
                        *out++ = (u8)(e >> 16);
                    }
                }
#endif
                continue;
            }
            if (GZ_UNLIKELY(e & GZE_EXC)) {
                if ((e >> 16) == 0) break;      /* end of block */
                FAIL(GZ_E_DATA);
            }

            u32 length = e >> 16;
            u32 ex = (e >> 8) & 0x1f;
            if (ex) {
#if !BB_WIDE
                if (bitcnt < ex) REFILL_FAST();
#endif
                length += BITS(ex);
                DROP(ex);
            }

#if !BB_WIDE
            if (bitcnt < 15) REFILL_FAST();
#endif
            e = dt[BITS(GZ_DIST_TBITS)];
            if (GZ_UNLIKELY(e & GZE_SUB)) {
                DROP(GZ_DIST_TBITS);
                e = dt[(e >> 16) + BITS((e >> 8) & 0x1f)];
            }
            DROP(e & 0xff);
            if (GZ_UNLIKELY(e & GZE_EXC)) FAIL(GZ_E_DATA);
            u32 dist = e >> 16;
            ex = (e >> 8) & 0x1f;
            if (ex) {
                if (bitcnt < ex) REFILL_FAST();
                dist += BITS(ex);
                DROP(ex);
            }
            if (GZ_UNLIKELY(dist > (size_t)(out - obuf))) FAIL(GZ_E_DATA);
            out = GZV_COPY_MATCH(out, dist, length);
        }
    } while (!final);

    /* ---- end of stream ---- */
    DROP(bitcnt & 7);
    {
        const u8 *rest = in - (bitcnt >> 3);
        if (rest > z->in_end) FAIL(GZ_E_TRUNC);
        FLUSH();
        z->rest = rest;
        z->rest_len = (u32)(z->in_end - rest);
    }
#if GZV_KIND == 1
    __asm__ volatile("emms");
#endif
    return GZ_OK;

fail:
#if GZV_KIND == 1
    __asm__ volatile("emms");
#endif
    return err;

#undef REFILL_FAST
#undef BB_WIDE
#undef REFILL_IN
#undef NEED
#undef BITS
#undef DROP
#undef FLUSH
#undef FAIL
}

#undef GZV_FN
#undef GZV_KIND
#undef GZV_W
#undef GZV_COPY_MATCH
#undef GZV_ATTR
