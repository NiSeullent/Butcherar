/*
 * 고깃ZIP - PPMd shared definitions (var.H "Ppmd7" and var.I rev.1 "Ppmd8")
 *
 * Both models follow Igor Pavlov's public-domain 7-Zip implementation (C/Ppmd7*.c,
 * C/Ppmd8*.c of 7-Zip 23.01), which is based on Dmitry Shkarin's public-domain
 * PPMd var.H (2001) / var.I (2002) and Dmitry Subbotin's carry-less range coder.
 * Output is byte-identical with 7-Zip.
 */
#ifndef GZ_PPMD_H
#define GZ_PPMD_H
#include "base.h"
#include "stream.h"

/* Symbol decoder results (besides 0..255). */
#define GZ_PPMD_SYM_END   (-1)     /* end-of-stream marker (escape out of the order -1 context) */
#define GZ_PPMD_SYM_ERROR (-2)     /* corrupt data                                              */

/* Byte reader used by the range decoders.
 * The decoder takes bytes from [cur, end). When cur == end it calls refill(), which must
 * either make [cur, end) non-empty and return GZ_OK, or return GZ_OK with cur == end at
 * end of input, or return an error. Past the end of input (or after an error) the decoder
 * reads zero bytes and counts them in `extra`; the first refill error is kept in `err`.
 * A stream that needs bytes past its end is truncated or corrupt: callers check
 * `extra`/`err` after each symbol (the 7z and ZIP entry points below do it for you). */
typedef struct gz_ppmd_in {
    const u8 *cur, *end;
    int (*refill)(struct gz_ppmd_in *in);
    void *user;                    /* for refill */
    u32 extra;                     /* bytes requested past the end of input */
    int err;                       /* first refill error (GZ_E_IO, GZ_E_CANCEL...) */
} gz_ppmd_in;

GZ_NOINLINE u32 gz_ppmd_in_slow(gz_ppmd_in *in);

GZ_INLINE u32 gz_ppmd_in_byte(gz_ppmd_in *in)
{
    if (GZ_LIKELY(in->cur != in->end)) return *in->cur++;
    return gz_ppmd_in_slow(in);
}

/* Memory caps for the model block: 2 GiB on 64-bit hosts, 1 GiB on 32-bit. */
#define GZ_PPMD_MEM_CAP ((sizeof(void *) >= 8) ? 0x80000000u : 0x40000000u)

/* Per-thread cache holding one Ppmd7 and one Ppmd8 coder (created on demand), so that
 * 7z, ZIP and RAR readers can share the GZ_SLOT_PPMD slot of gz_ctx:
 *   gz_ppmd_cache *pc = gz_ctx_slot(c, GZ_SLOT_PPMD, gz_ppmd_cache_new, gz_ppmd_cache_free);
 *   gz_ppmd7 *p7 = gz_ppmd_cache_7(pc);    (NULL when out of memory)
 * The model memory stays allocated between calls and is reused when the size matches. */
typedef struct gz_ppmd7 gz_ppmd7;
typedef struct gz_ppmd8 gz_ppmd8;
typedef struct gz_ppmd_cache { gz_ppmd7 *p7; gz_ppmd8 *p8; } gz_ppmd_cache;
void *gz_ppmd_cache_new(void);
void  gz_ppmd_cache_free(void *cache);
gz_ppmd7 *gz_ppmd_cache_7(gz_ppmd_cache *pc);
gz_ppmd8 *gz_ppmd_cache_8(gz_ppmd_cache *pc);

/* ---- internal: shared model building blocks (used by ppmd7.c / ppmd8.c) ---- */

#define GZ_PPMD_INT_BITS    7
#define GZ_PPMD_PERIOD_BITS 7
#define GZ_PPMD_BIN_SCALE   (1 << (GZ_PPMD_INT_BITS + GZ_PPMD_PERIOD_BITS))
#define GZ_PPMD_GET_MEAN(summ) (((summ) + (1 << (GZ_PPMD_PERIOD_BITS - 2))) >> GZ_PPMD_PERIOD_BITS)
#define GZ_PPMD_UPDATE_PROB_1(prob) ((prob) - GZ_PPMD_GET_MEAN(prob))
#define GZ_PPMD_NUM_INDEXES 38          /* 4 + 4 + 4 + 26 unit-size classes */
#define GZ_PPMD_UNIT_SIZE   12

/* All model records live in one block and refer to each other by 32-bit offsets from
 * its base. Units are reused as states, contexts and free-list nodes, and a binary
 * context keeps its state inside the context record: states, free-list nodes and raw
 * words are may_alias, so every access that overlays another record type is ordered
 * (context records themselves stay plain: their u16/u32 stores then do not force
 * reloads of unrelated model fields). */
typedef struct __attribute__((may_alias)) gz_ppmd_state {
    u8 Symbol, Freq;
    u16 Successor_0, Successor_1;     /* 32-bit successor reference, low half first */
} gz_ppmd_state;

typedef struct gz_ppmd_see {
    u16 Summ;                         /* escape frequency estimate                  */
    u8 Shift;                         /* speed of adaptation                        */
    u8 Count;                         /* count to next change of Shift              */
} gz_ppmd_see;

typedef u32 __attribute__((may_alias)) gz_ppmd_u32a;

GZ_INLINE u32 gz_ppmd_succ(const gz_ppmd_state *s)
{
    return (u32)s->Successor_0 | ((u32)s->Successor_1 << 16);
}
GZ_INLINE void gz_ppmd_set_succ(gz_ppmd_state *s, u32 v)
{
    s->Successor_0 = (u16)v;
    s->Successor_1 = (u16)(v >> 16);
}

#define GZ_PPMD_SEE_UPDATE(see) \
    { if ((see)->Shift < GZ_PPMD_PERIOD_BITS && --(see)->Count == 0) { \
        (see)->Summ = (u16)((see)->Summ << 1); \
        (see)->Count = (u8)(3 << (see)->Shift++); } }

/* Fill a 256-byte symbol mask with 0xFF. */
GZ_INLINE void gz_ppmd_mask_all(u8 *m) { __builtin_memset(m, 0xFF, 256); }

#endif
