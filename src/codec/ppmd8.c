/*
 * 고깃ZIP - PPMd var.I rev.1 (Ppmd8): model, decoder and encoder for ZIP method 98
 *
 * A port of 7-Zip 23.01 C/Ppmd8.c, Ppmd8Dec.c and Ppmd8Enc.c (Igor Pavlov, public
 * domain; based on Dmitry Shkarin's PPMd var.I and Dmitry Subbotin's carry-less range
 * coder), including the FREEZE restore method that 7-Zip compiles out
 * (PPMD8_FREEZE_SUPPORT). In FREEZE mode we follow var.I rev.1, i.e. without the later
 * Refresh() scale fix that made rev.2 / 7-Zip incompatible with rev.1 files; RESTART and
 * CUT_OFF match 7-Zip 23.01 exactly.
 *
 * As with Ppmd7, input only selects among valid symbol intervals, so hostile data can
 * not corrupt the model; reads past the end of the data are counted and stop decoding.
 */
#include "ppmd8.h"

#define MAX_FREQ 124
#define UNIT_SIZE GZ_PPMD_UNIT_SIZE
#define NUM_INDEXES GZ_PPMD_NUM_INDEXES
#define U2B(nu) ((u32)(nu) * UNIT_SIZE)
#define U2I(nu) (p->Units2Indx[(size_t)(nu) - 1])
#define I2U(indx) ((unsigned)p->Indx2Units[indx])

#define RC_TOP (1u << 24)
#define RC_BOT (1u << 15)

#define IBUF_SIZE (64u << 10)
#define OBUF_SIZE (256u << 10)
#define EIN_SIZE  (256u << 10)
#define EOUT_SIZE (64u << 10)
#define BUF_SIZE  (IBUF_SIZE + OBUF_SIZE)

#define FROZEN (GZ_PPMD8_FREEZE + 1)     /* RestoreMethod after the model froze */

typedef gz_ppmd_state STATE;
typedef gz_ppmd_see SEE;

/* Context record: NumStats = number of states - 1 (0: binary context, whose state
 * overlays SummFreq/Stats). Flags: 0x04 rescaled, 0x08 a state symbol >= 0x40,
 * 0x10 the previous symbol >= 0x40. */
typedef struct CTX8 {
    u8 NumStats;
    u8 Flags;
    u16 SummFreq;
    u32 Stats;
    u32 Suffix;
} CTX8;

typedef struct __attribute__((may_alias)) NODE8 {
    u32 Stamp;                        /* EMPTY_NODE for free blocks, 0 for the guard */
    u32 Next;
    u32 NU;
} NODE8;

#define EMPTY_NODE 0xFFFFFFFFu

struct gz_ppmd8 {
    CTX8 *MinContext, *MaxContext;
    STATE *FoundState;
    unsigned OrderFall, InitEsc, PrevSuccess, MaxOrder, RestoreMethod;
    u32 RunLength, InitRL;

    u32 Size, GlueCount, AlignOffset;
    u8 *Base, *LoUnit, *HiUnit, *Text, *UnitsStart;
    size_t block;

    u32 Range, Code, Low;
    gz_ppmd_in *in;

    u8 *op, *oend, *obuf;
    const gz_stream_io *oio;
    int oerr;
    u64 out_total;

    u8 *buf;

    u8 Indx2Units[NUM_INDEXES + 2];
    u8 Units2Indx[128];
    u32 FreeList[NUM_INDEXES];
    u32 Stamps[NUM_INDEXES];
    u8 NS2BSIndx[256], NS2Indx[260];
    u8 ExpEscape[16];
    SEE DummySee, See[24][32];
    u16 BinSumm[25][64];
};

static const u8 kExpEscape[16] = { 25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2 };
static const u16 kInitBinEsc[8] = { 0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051 };

#define REF(ptr)   ((u32)((const u8 *)(ptr) - p->Base))
#define PTR(ref)   ((void *)(p->Base + (ref)))
#define CTX(ref)   ((CTX8 *)PTR(ref))
#define STATS(ctx) ((STATE *)PTR((ctx)->Stats))
#define ONE_STATE(ctx) ((STATE *)(void *)&(ctx)->SummFreq)
#define SUFFIX(ctx) CTX((ctx)->Suffix)
#define NODE(ref)  ((NODE8 *)PTR(ref))
#define SUCC(s)    gz_ppmd_succ(s)
#define SET_SUCC(s, v) gz_ppmd_set_succ(s, v)

#define FLAG_RESCALED  (1 << 2)
#define FLAG_PREV_HIGH (1 << 4)
#define HIBITS_PREP(sym) ((unsigned)(sym) + 0xC0)
#define HIBITS_CONV3(f) (((f) >> (8 - 3)) & (1 << 3))
#define HIBITS3(sym) HIBITS_CONV3(HIBITS_PREP(sym))
#define HIBITS4(sym) ((HIBITS_PREP(sym) >> (8 - 4)) & (1 << 4))

/* ---------------- construction / memory ---------------- */

gz_ppmd8 *gz_ppmd8_new(void)
{
    gz_ppmd8 *p = (gz_ppmd8 *)gz_alloc(sizeof(gz_ppmd8));
    unsigned i, k, m;
    if (!p) return 0;
    for (i = 0, k = 0; i < NUM_INDEXES; i++) {
        unsigned step = (i >= 12 ? 4 : (i >> 2) + 1);
        do { p->Units2Indx[k++] = (u8)i; } while (--step);
        p->Indx2Units[i] = (u8)k;
    }
    p->NS2BSIndx[0] = (0 << 1);
    p->NS2BSIndx[1] = (1 << 1);
    __builtin_memset(p->NS2BSIndx + 2, (2 << 1), 9);
    __builtin_memset(p->NS2BSIndx + 11, (3 << 1), 256 - 11);
    for (i = 0; i < 5; i++) p->NS2Indx[i] = (u8)i;
    for (m = i, k = 1; i < 260; i++) {
        p->NS2Indx[i] = (u8)m;
        if (--k == 0) k = (++m) - 4;
    }
    __builtin_memcpy(p->ExpEscape, kExpEscape, 16);
    return p;
}

static void p8_free_block(gz_ppmd8 *p)
{
    if (p->Base) gz_free_big(p->Base, p->block);
    p->Base = 0;
    p->Size = 0;
    p->block = 0;
}

void gz_ppmd8_free(gz_ppmd8 *p)
{
    if (!p) return;
    p8_free_block(p);
    gz_free(p->buf);
    gz_free(p);
}

static int p8_alloc(gz_ppmd8 *p, u32 size)
{
    if (p->Base && p->Size == size) return GZ_OK;
    p8_free_block(p);
    {
        u32 align = (4 - size) & 3;
        size_t n = (size_t)align + size;
        p->Base = (u8 *)gz_alloc_big(n);
        if (!p->Base) return GZ_E_NOMEM;
        p->AlignOffset = align;
        p->Size = size;
        p->block = n;
    }
    return GZ_OK;
}

static int p8_buffers(gz_ppmd8 *p)
{
    if (!p->buf) p->buf = (u8 *)gz_alloc(BUF_SIZE);
    return p->buf ? GZ_OK : GZ_E_NOMEM;
}

/* ---------------- per-thread cache (shared with Ppmd7) ---------------- */

#include "ppmd7.h"

void *gz_ppmd_cache_new(void)
{
    return gz_alloc(sizeof(gz_ppmd_cache));
}

void gz_ppmd_cache_free(void *cache)
{
    gz_ppmd_cache *pc = (gz_ppmd_cache *)cache;
    if (!pc) return;
    gz_ppmd7_free(pc->p7);
    gz_ppmd8_free(pc->p8);
    gz_free(pc);
}

gz_ppmd7 *gz_ppmd_cache_7(gz_ppmd_cache *pc)
{
    if (!pc) return 0;
    if (!pc->p7) pc->p7 = gz_ppmd7_new();
    return pc->p7;
}

gz_ppmd8 *gz_ppmd_cache_8(gz_ppmd_cache *pc)
{
    if (!pc) return 0;
    if (!pc->p8) pc->p8 = gz_ppmd8_new();
    return pc->p8;
}

/* ---------------- sub-allocator ---------------- */

static void insert_node(gz_ppmd8 *p, void *node, unsigned indx)
{
    ((NODE8 *)node)->Stamp = EMPTY_NODE;
    ((NODE8 *)node)->Next = p->FreeList[indx];
    ((NODE8 *)node)->NU = I2U(indx);
    p->FreeList[indx] = REF(node);
    p->Stamps[indx]++;
}

static void *remove_node(gz_ppmd8 *p, unsigned indx)
{
    NODE8 *node = NODE(p->FreeList[indx]);
    p->FreeList[indx] = node->Next;
    p->Stamps[indx]--;
    return node;
}

static void split_block(gz_ppmd8 *p, void *ptr, unsigned oldIndx, unsigned newIndx)
{
    unsigned i, nu = I2U(oldIndx) - I2U(newIndx);
    ptr = (u8 *)ptr + U2B(I2U(newIndx));
    if (I2U(i = U2I(nu)) != nu) {
        unsigned k = I2U(--i);
        insert_node(p, ((u8 *)ptr) + U2B(k), nu - k - 1);
    }
    insert_node(p, ptr, i);
}

static void glue_free_blocks(gz_ppmd8 *p)
{
    /* First u32 of a unit: State/Context data (never 0xFFFFFFFF), free node
     * (EMPTY_NODE) or the guard at LoUnit (0). The last unit is the root context. */
    u32 n;
    unsigned i;
    p->GlueCount = 1 << 13;
    __builtin_memset(p->Stamps, 0, sizeof(p->Stamps));
    if (p->LoUnit != p->HiUnit) ((NODE8 *)(void *)p->LoUnit)->Stamp = 0;
    {
        gz_ppmd_u32a *prev = &n;
        for (i = 0; i < NUM_INDEXES; i++) {
            u32 next = p->FreeList[i];
            p->FreeList[i] = 0;
            while (next != 0) {
                NODE8 *node = NODE(next);
                u32 nu = node->NU;
                *prev = next;
                next = node->Next;
                if (nu != 0) {
                    NODE8 *node2;
                    prev = &node->Next;
                    while ((node2 = node + nu)->Stamp == EMPTY_NODE) {
                        nu += node2->NU;
                        node2->NU = 0;
                        node->NU = nu;
                    }
                }
            }
        }
        *prev = 0;
    }
    while (n != 0) {
        NODE8 *node = NODE(n);
        u32 nu = node->NU;
        n = node->Next;
        if (nu == 0) continue;
        for (; nu > 128; nu -= 128, node += 128) insert_node(p, node, NUM_INDEXES - 1);
        if (I2U(i = U2I(nu)) != nu) {
            unsigned k = I2U(--i);
            insert_node(p, node + k, (unsigned)nu - k - 1);
        }
        insert_node(p, node, i);
    }
}

static GZ_NOINLINE void *alloc_units_rare(gz_ppmd8 *p, unsigned indx)
{
    unsigned i;
    if (p->GlueCount == 0) {
        glue_free_blocks(p);
        if (p->FreeList[indx] != 0) return remove_node(p, indx);
    }
    i = indx;
    do {
        if (++i == NUM_INDEXES) {
            u32 numBytes = U2B(I2U(indx));
            u8 *us = p->UnitsStart;
            p->GlueCount--;
            return ((u32)(us - p->Text) > numBytes) ? (p->UnitsStart = us - numBytes) : 0;
        }
    } while (p->FreeList[i] == 0);
    {
        void *block = remove_node(p, i);
        split_block(p, block, i, indx);
        return block;
    }
}

static void *alloc_units(gz_ppmd8 *p, unsigned indx)
{
    if (p->FreeList[indx] != 0) return remove_node(p, indx);
    {
        u32 numBytes = U2B(I2U(indx));
        u8 *lo = p->LoUnit;
        if ((u32)(p->HiUnit - lo) >= numBytes) {
            p->LoUnit = lo + numBytes;
            return lo;
        }
    }
    return alloc_units_rare(p, indx);
}

/* Copy num 12-byte units (4-aligned) as 32-bit words. */
GZ_INLINE void copy_units(void *dest, const void *src, unsigned num)
{
    gz_ppmd_u32a *d = (gz_ppmd_u32a *)dest;
    const gz_ppmd_u32a *s = (const gz_ppmd_u32a *)src;
    do { d[0] = s[0]; d[1] = s[1]; d[2] = s[2]; d += 3; s += 3; } while (--num);
}

static void *shrink_units(gz_ppmd8 *p, void *oldPtr, unsigned oldNU, unsigned newNU)
{
    unsigned i0 = U2I(oldNU);
    unsigned i1 = U2I(newNU);
    if (i0 == i1) return oldPtr;
    if (p->FreeList[i1] != 0) {
        void *ptr = remove_node(p, i1);
        copy_units(ptr, oldPtr, newNU);
        insert_node(p, oldPtr, i0);
        return ptr;
    }
    split_block(p, oldPtr, i0, i1);
    return oldPtr;
}

static void free_units(gz_ppmd8 *p, void *ptr, unsigned nu)
{
    insert_node(p, ptr, U2I(nu));
}

static void special_free_unit(gz_ppmd8 *p, void *ptr)
{
    if ((u8 *)ptr != p->UnitsStart)
        insert_node(p, ptr, 0);
    else {
        /* mark it for the Flags == 0xFF test of remove_bin_contexts() (FREEZE only) */
        if (p->RestoreMethod >= GZ_PPMD8_FREEZE) *(gz_ppmd_u32a *)ptr = EMPTY_NODE;
        p->UnitsStart += UNIT_SIZE;
    }
}

static void expand_text_area(gz_ppmd8 *p)
{
    u32 count[NUM_INDEXES];
    unsigned i;
    __builtin_memset(count, 0, sizeof(count));
    if (p->LoUnit != p->HiUnit) ((NODE8 *)(void *)p->LoUnit)->Stamp = 0;
    {
        NODE8 *node = (NODE8 *)(void *)p->UnitsStart;
        while (node->Stamp == EMPTY_NODE) {
            u32 nu = node->NU;
            node->Stamp = 0;
            count[U2I(nu)]++;
            node += nu;
        }
        p->UnitsStart = (u8 *)node;
    }
    for (i = 0; i < NUM_INDEXES; i++) {
        u32 cnt = count[i];
        if (cnt == 0) continue;
        {
            gz_ppmd_u32a *prev = &p->FreeList[i];
            u32 n = *prev;
            p->Stamps[i] -= cnt;
            for (;;) {
                NODE8 *node = NODE(n);
                n = node->Next;
                if (node->Stamp != 0) {
                    prev = &node->Next;
                    continue;
                }
                *prev = n;
                if (--cnt == 0) break;
            }
        }
    }
}

/* ---------------- model ---------------- */

#define RESET_TEXT(offs) { p->Text = p->Base + p->AlignOffset + (offs); }

static GZ_NOINLINE void restart_model(gz_ppmd8 *p)
{
    unsigned i, k, m;
    __builtin_memset(p->FreeList, 0, sizeof(p->FreeList));
    __builtin_memset(p->Stamps, 0, sizeof(p->Stamps));
    RESET_TEXT(0)
    p->HiUnit = p->Text + p->Size;
    p->LoUnit = p->UnitsStart = p->HiUnit - p->Size / 8 / UNIT_SIZE * 7 * UNIT_SIZE;
    p->GlueCount = 0;

    p->OrderFall = p->MaxOrder;
    p->RunLength = p->InitRL = (u32)(-(i32)((p->MaxOrder < 12) ? p->MaxOrder : 12) - 1);
    p->PrevSuccess = 0;
    {
        CTX8 *mc = (CTX8 *)(void *)(p->HiUnit -= UNIT_SIZE);
        STATE *s = (STATE *)(void *)p->LoUnit;
        p->LoUnit += U2B(256 / 2);
        p->MaxContext = p->MinContext = mc;
        p->FoundState = s;
        mc->Flags = 0;
        mc->NumStats = 256 - 1;
        mc->SummFreq = 256 + 1;
        mc->Stats = REF(s);
        mc->Suffix = 0;
        for (i = 0; i < 256; i++, s++) {
            s->Symbol = (u8)i;
            s->Freq = 1;
            SET_SUCC(s, 0);
        }
    }
    for (i = m = 0; m < 25; m++) {
        while (p->NS2Indx[i] == m) i++;
        for (k = 0; k < 8; k++) {
            unsigned r;
            u16 *dest = p->BinSumm[m] + k;
            const u16 val = (u16)(GZ_PPMD_BIN_SCALE - kInitBinEsc[k] / (i + 1));
            for (r = 0; r < 64; r += 8) dest[r] = val;
        }
    }
    for (i = m = 0; m < 24; m++) {
        unsigned summ;
        SEE *s;
        while (p->NS2Indx[(size_t)i + 3] == m + 3) i++;
        s = p->See[m];
        summ = ((2 * i + 5) << (GZ_PPMD_PERIOD_BITS - 4));
        for (k = 0; k < 32; k++, s++) {
            s->Summ = (u16)summ;
            s->Shift = (GZ_PPMD_PERIOD_BITS - 4);
            s->Count = 7;
        }
    }
    p->DummySee.Summ = 0;
    p->DummySee.Shift = GZ_PPMD_PERIOD_BITS;
    p->DummySee.Count = 64;
}

static void p8_init(gz_ppmd8 *p, unsigned maxOrder, unsigned restoreMethod)
{
    p->MaxOrder = maxOrder;
    p->RestoreMethod = restoreMethod;
    restart_model(p);
}

/* Called when symbols were removed from ctx: shrink its states, rescale by `scale`
 * bits and recompute flags. */
static void refresh(gz_ppmd8 *p, CTX8 *ctx, unsigned oldNU, unsigned scale)
{
    unsigned i = ctx->NumStats, escFreq, sumFreq, flags;
    STATE *s = (STATE *)shrink_units(p, STATS(ctx), oldNU, (i + 2) >> 1);
    ctx->Stats = REF(s);
    /* 7-Zip / rev.2 fix (SummFreq overflow in FREEZE mode); rev.1 FREEZE files need
     * the original behaviour */
    if (p->RestoreMethod < GZ_PPMD8_FREEZE)
        scale |= (ctx->SummFreq >= ((u32)1 << 15));
    flags = HIBITS_PREP(s->Symbol);
    {
        unsigned freq = s->Freq;
        escFreq = ctx->SummFreq - freq;
        freq = (freq + scale) >> scale;
        sumFreq = freq;
        s->Freq = (u8)freq;
    }
    do {
        unsigned freq = (++s)->Freq;
        escFreq -= freq;
        freq = (freq + scale) >> scale;
        sumFreq += freq;
        s->Freq = (u8)freq;
        flags |= HIBITS_PREP(s->Symbol);
    } while (--i);
    ctx->SummFreq = (u16)(sumFreq + ((escFreq + scale) >> scale));
    ctx->Flags = (u8)((ctx->Flags & (FLAG_PREV_HIGH + FLAG_RESCALED * scale)) + HIBITS_CONV3(flags));
}

static void swap_states(STATE *t1, STATE *t2)
{
    STATE tmp = *t1;
    *t1 = *t2;
    *t2 = tmp;
}

/* CUT_OFF: drop raw successors and successor-less contexts (order > 0), recursively.
 * Recursion depth <= MaxOrder (16). */
static u32 cut_off(gz_ppmd8 *p, CTX8 *ctx, unsigned order)
{
    int ns = ctx->NumStats;
    unsigned nu;
    STATE *stats;

    if (ns == 0) {
        STATE *s = ONE_STATE(ctx);
        u32 successor = SUCC(s);
        if ((u8 *)PTR(successor) >= p->UnitsStart) {
            if (order < p->MaxOrder) successor = cut_off(p, CTX(successor), order + 1);
            else successor = 0;
            SET_SUCC(s, successor);
            if (successor || order <= 9) return REF(ctx);
        }
        special_free_unit(p, ctx);
        return 0;
    }

    nu = ((unsigned)ns + 2) >> 1;
    {
        /* move the states up when they are close to UnitsStart */
        unsigned indx = U2I(nu);
        stats = STATS(ctx);
        if ((u32)((u8 *)stats - p->UnitsStart) <= (1 << 14) && ctx->Stats <= p->FreeList[indx]) {
            void *ptr = remove_node(p, indx);
            ctx->Stats = REF(ptr);
            copy_units(ptr, stats, nu);
            if ((u8 *)stats != p->UnitsStart) insert_node(p, stats, indx);
            else p->UnitsStart += U2B(I2U(indx));
            stats = (STATE *)ptr;
        }
    }
    {
        STATE *s = stats + (unsigned)ns;
        do {
            u32 successor = SUCC(s);
            if ((u8 *)PTR(successor) < p->UnitsStart) {
                STATE *s2 = stats + (unsigned)(ns--);
                if (order) {
                    if (s != s2) *s = *s2;
                } else {
                    swap_states(s, s2);
                    SET_SUCC(s2, 0);
                }
            } else {
                if (order < p->MaxOrder) SET_SUCC(s, cut_off(p, CTX(successor), order + 1));
                else SET_SUCC(s, 0);
            }
        } while (--s >= stats);
    }
    if (ns != ctx->NumStats && order) {
        if (ns < 0) {
            free_units(p, stats, nu);
            special_free_unit(p, ctx);
            return 0;
        }
        ctx->NumStats = (u8)ns;
        if (ns == 0) {
            const u8 sym = stats->Symbol;
            ctx->Flags = (u8)((ctx->Flags & FLAG_PREV_HIGH) + HIBITS3(sym));
            ONE_STATE(ctx)->Symbol = sym;
            ONE_STATE(ctx)->Freq = (u8)(((unsigned)stats->Freq + 11) >> 3);
            ONE_STATE(ctx)->Successor_0 = stats->Successor_0;
            ONE_STATE(ctx)->Successor_1 = stats->Successor_1;
            free_units(p, stats, nu);
        } else
            refresh(p, ctx, nu, ctx->SummFreq > 16 * (unsigned)ns);
    }
    return REF(ctx);
}

/* FREEZE: turn successors into NULL successors and drop binary contexts without
 * successors whose suffix is binary too. Recursion depth <= MaxOrder. */
static u32 remove_bin_contexts(gz_ppmd8 *p, CTX8 *ctx, unsigned order)
{
    if (!ctx->NumStats) {
        STATE *s = ONE_STATE(ctx);
        u32 successor = SUCC(s);
        if ((u8 *)PTR(successor) >= p->UnitsStart && order < p->MaxOrder)
            successor = remove_bin_contexts(p, CTX(successor), order + 1);
        else
            successor = 0;
        SET_SUCC(s, successor);
        /* the suffix may already be freed (several successors can share it):
         * a freed unit reads Flags == 0xFF */
        if (!successor && (!SUFFIX(ctx)->NumStats || SUFFIX(ctx)->Flags == 0xFF)) {
            free_units(p, ctx, 1);
            return 0;
        }
    } else {
        STATE *s = STATS(ctx) + ctx->NumStats;
        do {
            u32 successor = SUCC(s);
            if ((u8 *)PTR(successor) >= p->UnitsStart && order < p->MaxOrder)
                SET_SUCC(s, remove_bin_contexts(p, CTX(successor), order + 1));
            else
                SET_SUCC(s, 0);
        } while (--s >= STATS(ctx));
    }
    return REF(ctx);
}

static u32 get_used_memory(const gz_ppmd8 *p)
{
    u32 v = 0;
    unsigned i;
    for (i = 0; i < NUM_INDEXES; i++) v += p->Stamps[i] * I2U(i);
    return p->Size - (u32)(p->HiUnit - p->LoUnit) - (u32)(p->UnitsStart - p->Text) - U2B(v);
}

/* Out of memory while updating: undo the partial update of [MaxContext .. ctxError),
 * then restart, cut off or freeze the model. */
static GZ_NOINLINE void restore_model(gz_ppmd8 *p, CTX8 *ctxError, u32 fSuccessor)
{
    CTX8 *c;
    STATE *s;
    RESET_TEXT(0)
    for (c = p->MaxContext; c != ctxError; c = SUFFIX(c))
        if (--(c->NumStats) == 0) {
            s = STATS(c);
            c->Flags = (u8)((c->Flags & FLAG_PREV_HIGH) + HIBITS3(s->Symbol));
            ONE_STATE(c)->Symbol = s->Symbol;
            ONE_STATE(c)->Freq = (u8)(((unsigned)s->Freq + 11) >> 3);
            ONE_STATE(c)->Successor_0 = s->Successor_0;
            ONE_STATE(c)->Successor_1 = s->Successor_1;
            special_free_unit(p, s);
        } else
            refresh(p, c, ((unsigned)c->NumStats + 3) >> 1, 0);

    for (; c != p->MinContext; c = SUFFIX(c))
        if (c->NumStats == 0)
            ONE_STATE(c)->Freq = (u8)(((unsigned)ONE_STATE(c)->Freq + 1) >> 1);
        else if ((c->SummFreq = (u16)(c->SummFreq + 4)) > 128 + 4 * c->NumStats)
            refresh(p, c, ((unsigned)c->NumStats + 2) >> 1, 1);

    if (p->RestoreMethod > GZ_PPMD8_FREEZE) {
        /* frozen: continue in the successor context (the original code would use a
         * NULL successor here; take the root instead) */
        if (fSuccessor) p->MaxContext = CTX(fSuccessor);
        else while (p->MaxContext->Suffix) p->MaxContext = SUFFIX(p->MaxContext);
        p->GlueCount += !(p->Stamps[1] & 1);
    } else if (p->RestoreMethod == GZ_PPMD8_FREEZE) {
        while (p->MaxContext->Suffix) p->MaxContext = SUFFIX(p->MaxContext);
        remove_bin_contexts(p, p->MaxContext, 0);
        p->RestoreMethod = FROZEN;
        p->GlueCount = 0;
        p->OrderFall = p->MaxOrder;
    } else if (p->RestoreMethod == GZ_PPMD8_RESTART || get_used_memory(p) < (p->Size >> 1))
        restart_model(p);
    else {
        while (p->MaxContext->Suffix) p->MaxContext = SUFFIX(p->MaxContext);
        do {
            cut_off(p, p->MaxContext, 0);
            expand_text_area(p);
        } while (get_used_memory(p) > 3 * (p->Size >> 2));
        p->GlueCount = 0;
        p->OrderFall = p->MaxOrder;
    }
    p->MinContext = p->MaxContext;
}

static GZ_NOINLINE CTX8 *create_successors(gz_ppmd8 *p, int skip, STATE *s1, CTX8 *c)
{
    u32 upBranch = SUCC(p->FoundState);
    u8 newSym, newFreq, flags;
    unsigned numPs = 0;
    STATE *ps[GZ_PPMD8_MAX_ORDER + 2];

    if (!skip) ps[numPs++] = p->FoundState;
    while (c->Suffix) {
        u32 successor;
        STATE *s;
        c = SUFFIX(c);
        if (s1) { s = s1; s1 = 0; }
        else if (c->NumStats != 0) {
            u8 sym = p->FoundState->Symbol;
            for (s = STATS(c); s->Symbol != sym; s++) ;
            if (s->Freq < MAX_FREQ - 9) { s->Freq++; c->SummFreq++; }
        } else {
            s = ONE_STATE(c);
            s->Freq = (u8)(s->Freq + (!SUFFIX(c)->NumStats & (s->Freq < 24)));
        }
        successor = SUCC(s);
        if (successor != upBranch) {
            c = CTX(successor);
            if (numPs == 0) return c;
            break;
        }
        if (GZ_UNLIKELY(numPs >= GZ_COUNTOF(ps))) return 0;   /* cannot happen */
        ps[numPs++] = s;
    }

    newSym = *(const u8 *)PTR(upBranch);
    upBranch++;
    flags = (u8)(HIBITS4(p->FoundState->Symbol) + HIBITS3(newSym));
    if (c->NumStats == 0)
        newFreq = ONE_STATE(c)->Freq;
    else {
        u32 cf, s0;
        STATE *s;
        for (s = STATS(c); s->Symbol != newSym; s++) ;
        cf = (u32)s->Freq - 1;
        s0 = (u32)c->SummFreq - c->NumStats - cf;
        newFreq = (u8)(1 + ((2 * cf <= s0) ? (5 * cf > s0) : ((cf + 2 * s0 - 3) / s0)));
    }

    do {
        CTX8 *c1;
        if (p->HiUnit != p->LoUnit)
            c1 = (CTX8 *)(void *)(p->HiUnit -= UNIT_SIZE);
        else if (p->FreeList[0] != 0)
            c1 = (CTX8 *)remove_node(p, 0);
        else {
            c1 = (CTX8 *)alloc_units_rare(p, 0);
            if (!c1) return 0;
        }
        c1->Flags = flags;
        c1->NumStats = 0;
        ONE_STATE(c1)->Symbol = newSym;
        ONE_STATE(c1)->Freq = newFreq;
        SET_SUCC(ONE_STATE(c1), upBranch);
        c1->Suffix = REF(c);
        SET_SUCC(ps[--numPs], REF(c1));
        c = c1;
    } while (numPs != 0);
    return c;
}

static CTX8 *reduce_order(gz_ppmd8 *p, STATE *s1, CTX8 *c)
{
    STATE *s = 0;
    CTX8 *c1 = c;
    u32 upBranch = REF(p->Text);
    STATE *ps[GZ_PPMD8_MAX_ORDER + 2];
    unsigned numPs = 0;
    ps[numPs++] = p->FoundState;

    SET_SUCC(p->FoundState, upBranch);
    p->OrderFall++;
    for (;;) {
        if (s1) {
            c = SUFFIX(c);
            s = s1;
            s1 = 0;
        } else {
            if (!c->Suffix) {
                if (p->RestoreMethod > GZ_PPMD8_FREEZE) {
                    do { SET_SUCC(ps[--numPs], REF(c)); } while (numPs);
                    RESET_TEXT(1)
                    p->OrderFall = 1;
                }
                return c;
            }
            c = SUFFIX(c);
            if (c->NumStats) {
                if ((s = STATS(c))->Symbol != p->FoundState->Symbol)
                    do { s++; } while (s->Symbol != p->FoundState->Symbol);
                if (s->Freq < MAX_FREQ - 9) {
                    s->Freq = (u8)(s->Freq + 2);
                    c->SummFreq = (u16)(c->SummFreq + 2);
                }
            } else {
                s = ONE_STATE(c);
                s->Freq = (u8)(s->Freq + (s->Freq < 32));
            }
        }
        if (SUCC(s)) break;
        if (numPs < GZ_COUNTOF(ps)) ps[numPs++] = s;
        SET_SUCC(s, upBranch);
        p->OrderFall++;
    }

    if (p->RestoreMethod > GZ_PPMD8_FREEZE) {
        c = CTX(SUCC(s));
        do { SET_SUCC(ps[--numPs], REF(c)); } while (numPs);
        RESET_TEXT(1)
        p->OrderFall = 1;
        return c;
    } else if (SUCC(s) <= upBranch) {
        CTX8 *successor;
        STATE *s2 = p->FoundState;
        p->FoundState = s;
        successor = create_successors(p, 0, 0, c);
        if (!successor) SET_SUCC(s, 0);
        else SET_SUCC(s, REF(successor));
        p->FoundState = s2;
    }
    {
        u32 successor = SUCC(s);
        if (p->OrderFall == 1 && c1 == p->MaxContext) {
            SET_SUCC(p->FoundState, successor);
            p->Text--;
        }
        if (successor == 0) return 0;
        return CTX(successor);
    }
}

static GZ_NOINLINE void update_model(gz_ppmd8 *p)
{
    u32 maxSuccessor, minSuccessor = SUCC(p->FoundState);
    CTX8 *c;
    unsigned s0, ns, fFreq = p->FoundState->Freq;
    u8 flag, fSymbol = p->FoundState->Symbol;
    {
        STATE *s = 0;
        if (p->FoundState->Freq < MAX_FREQ / 4 && p->MinContext->Suffix != 0) {
            /* update the symbol's frequency in the suffix context */
            c = SUFFIX(p->MinContext);
            if (c->NumStats == 0) {
                s = ONE_STATE(c);
                if (s->Freq < 32) s->Freq++;
            } else {
                u8 sym = p->FoundState->Symbol;
                s = STATS(c);
                if (s->Symbol != sym) {
                    do { s++; } while (s->Symbol != sym);
                    if (s[0].Freq >= s[-1].Freq) {
                        swap_states(&s[0], &s[-1]);
                        s--;
                    }
                }
                if (s->Freq < MAX_FREQ - 9) {
                    s->Freq = (u8)(s->Freq + 2);
                    c->SummFreq = (u16)(c->SummFreq + 2);
                }
            }
        }

        c = p->MaxContext;
        if (p->OrderFall == 0 && minSuccessor) {
            CTX8 *cs = create_successors(p, 1, s, p->MinContext);
            if (!cs) {
                SET_SUCC(p->FoundState, 0);
                restore_model(p, c, minSuccessor);
                return;
            }
            SET_SUCC(p->FoundState, REF(cs));
            p->MinContext = p->MaxContext = cs;
            return;
        }

        {
            u8 *text = p->Text;
            *text++ = p->FoundState->Symbol;
            p->Text = text;
            if (text >= p->UnitsStart) {
                restore_model(p, c, minSuccessor);
                return;
            }
            maxSuccessor = REF(text);
        }

        if (!minSuccessor) {
            CTX8 *cs = reduce_order(p, s, p->MinContext);
            if (!cs) {
                restore_model(p, c, 0);
                return;
            }
            minSuccessor = REF(cs);
        } else if ((u8 *)PTR(minSuccessor) < p->UnitsStart) {
            CTX8 *cs = create_successors(p, 0, s, p->MinContext);
            if (!cs) {
                restore_model(p, c, 0);
                return;
            }
            minSuccessor = REF(cs);
        }

        if (--p->OrderFall == 0) {
            maxSuccessor = minSuccessor;
            p->Text -= (p->MaxContext != p->MinContext);
        } else if (p->RestoreMethod > GZ_PPMD8_FREEZE) {
            maxSuccessor = minSuccessor;
            RESET_TEXT(0)
            p->OrderFall = 0;
        }
    }

    flag = (u8)HIBITS3(fSymbol);
    s0 = p->MinContext->SummFreq - (ns = p->MinContext->NumStats) - fFreq;

    for (; c != p->MinContext; c = SUFFIX(c)) {
        unsigned ns1;
        u32 sum;
        if ((ns1 = c->NumStats) != 0) {
            if ((ns1 & 1) != 0) {
                /* grow the state vector by one unit */
                unsigned oldNU = (ns1 + 1) >> 1;
                unsigned i = U2I(oldNU);
                if (i != U2I((size_t)oldNU + 1)) {
                    void *ptr = alloc_units(p, i + 1);
                    void *oldPtr;
                    if (!ptr) {
                        restore_model(p, c, minSuccessor);
                        return;
                    }
                    oldPtr = STATS(c);
                    copy_units(ptr, oldPtr, oldNU);
                    insert_node(p, oldPtr, i);
                    c->Stats = REF(ptr);
                }
            }
            sum = c->SummFreq;
            sum += (3 * ns1 + 1 < ns);
        } else {
            STATE *s = (STATE *)alloc_units(p, 0);
            if (!s) {
                restore_model(p, c, minSuccessor);
                return;
            }
            {
                unsigned freq = ONE_STATE(c)->Freq;
                s->Symbol = ONE_STATE(c)->Symbol;
                s->Successor_0 = ONE_STATE(c)->Successor_0;
                s->Successor_1 = ONE_STATE(c)->Successor_1;
                c->Stats = REF(s);
                if (freq < MAX_FREQ / 4 - 1) freq <<= 1;
                else freq = MAX_FREQ - 4;
                s->Freq = (u8)freq;
                sum = freq + p->InitEsc + (ns > 2);
            }
        }
        {
            STATE *s = STATS(c) + ns1 + 1;
            u32 cf = 2 * (sum + 6) * (u32)fFreq;
            u32 sf = (u32)s0 + sum;
            s->Symbol = fSymbol;
            c->NumStats = (u8)(ns1 + 1);
            SET_SUCC(s, maxSuccessor);
            c->Flags |= flag;
            if (cf < 6 * sf) {
                cf = (unsigned)1 + (cf > sf) + (cf >= 4 * sf);
                sum += 4;
            } else {
                cf = (unsigned)4 + (cf > 9 * sf) + (cf > 12 * sf) + (cf > 15 * sf);
                sum += cf;
            }
            c->SummFreq = (u16)sum;
            s->Freq = (u8)cf;
        }
    }
    p->MaxContext = p->MinContext = CTX(minSuccessor);
}

static GZ_NOINLINE void rescale(gz_ppmd8 *p)
{
    unsigned i, adder, sumFreq, escFreq;
    STATE *stats = STATS(p->MinContext);
    STATE *s = p->FoundState;
    if (s != stats) {
        STATE tmp = *s;
        do s[0] = s[-1]; while (--s != stats);
        *s = tmp;
    }
    sumFreq = s->Freq;
    escFreq = p->MinContext->SummFreq - sumFreq;
    adder = (p->OrderFall != 0) | (p->RestoreMethod > GZ_PPMD8_FREEZE);
    sumFreq = (sumFreq + 4 + adder) >> 1;
    i = p->MinContext->NumStats;
    s->Freq = (u8)sumFreq;
    do {
        unsigned freq = (++s)->Freq;
        escFreq -= freq;
        freq = (freq + adder) >> 1;
        sumFreq += freq;
        s->Freq = (u8)freq;
        if (freq > s[-1].Freq) {
            STATE tmp = *s;
            STATE *s1 = s;
            do s1[0] = s1[-1]; while (--s1 != stats && freq > s1[-1].Freq);
            *s1 = tmp;
        }
    } while (--i);

    if (s->Freq == 0) {
        CTX8 *mc;
        unsigned numStats, numStatsNew, n0, n1;
        i = 0;
        do { i++; } while ((--s)->Freq == 0);
        escFreq += i;
        mc = p->MinContext;
        numStats = mc->NumStats;
        numStatsNew = numStats - i;
        mc->NumStats = (u8)numStatsNew;
        n0 = (numStats + 2) >> 1;
        if (numStatsNew == 0) {
            unsigned freq = (2 * (unsigned)stats->Freq + escFreq - 1) / escFreq;
            if (freq > MAX_FREQ / 3) freq = MAX_FREQ / 3;
            mc->Flags = (u8)((mc->Flags & FLAG_PREV_HIGH) + HIBITS3(stats->Symbol));
            s = ONE_STATE(mc);
            *s = *stats;
            s->Freq = (u8)freq;
            p->FoundState = s;
            insert_node(p, stats, U2I(n0));
            return;
        }
        n1 = (numStatsNew + 2) >> 1;
        if (n0 != n1) mc->Stats = REF(shrink_units(p, stats, n0, n1));
    }
    {
        CTX8 *mc = p->MinContext;
        mc->SummFreq = (u16)(sumFreq + escFreq - (escFreq >> 1));
        mc->Flags |= FLAG_RESCALED;
        p->FoundState = STATS(mc);
    }
}

static SEE *make_esc_freq(gz_ppmd8 *p, unsigned numMasked1, u32 *escFreq)
{
    SEE *see;
    const CTX8 *mc = p->MinContext;
    unsigned numStats = mc->NumStats;
    if (numStats != 0xFF) {
        see = p->See[(size_t)(unsigned)p->NS2Indx[(size_t)numStats + 2] - 3]
            + (mc->SummFreq > 11 * (numStats + 1))
            + 2 * (unsigned)(2 * numStats < ((unsigned)SUFFIX(mc)->NumStats + numMasked1))
            + mc->Flags;
        {
            unsigned summ = (u16)see->Summ;
            unsigned r = (summ >> see->Shift);
            see->Summ = (u16)(summ - r);
            *escFreq = r + (r == 0);
        }
    } else {
        see = &p->DummySee;
        *escFreq = 1;
    }
    return see;
}

GZ_INLINE void next_context(gz_ppmd8 *p)
{
    CTX8 *c = CTX(SUCC(p->FoundState));
    if (p->OrderFall == 0 && (const u8 *)c >= p->UnitsStart)
        p->MaxContext = p->MinContext = c;
    else
        update_model(p);
}

static void update1(gz_ppmd8 *p)
{
    STATE *s = p->FoundState;
    unsigned freq = s->Freq;
    freq += 4;
    p->MinContext->SummFreq = (u16)(p->MinContext->SummFreq + 4);
    s->Freq = (u8)freq;
    if (freq > s[-1].Freq) {
        swap_states(s, &s[-1]);
        p->FoundState = --s;
        if (freq > MAX_FREQ) rescale(p);
    }
    next_context(p);
}

static void update1_0(gz_ppmd8 *p)
{
    STATE *s = p->FoundState;
    CTX8 *mc = p->MinContext;
    unsigned freq = s->Freq;
    unsigned summFreq = mc->SummFreq;
    p->PrevSuccess = (2 * freq >= summFreq);
    p->RunLength += p->PrevSuccess;
    mc->SummFreq = (u16)(summFreq + 4);
    freq += 4;
    s->Freq = (u8)freq;
    if (freq > MAX_FREQ) rescale(p);
    next_context(p);
}

static void update2(gz_ppmd8 *p)
{
    STATE *s = p->FoundState;
    unsigned freq = s->Freq;
    freq += 4;
    p->RunLength = p->InitRL;
    p->MinContext->SummFreq = (u16)(p->MinContext->SummFreq + 4);
    s->Freq = (u8)freq;
    if (freq > MAX_FREQ) rescale(p);
    update_model(p);
}

GZ_INLINE u16 *bin_summ(gz_ppmd8 *p)
{
    const STATE *one = ONE_STATE(p->MinContext);
    return &p->BinSumm[p->NS2Indx[(size_t)one->Freq - 1]]
        [p->PrevSuccess + ((p->RunLength >> 26) & 0x20)
         + p->NS2BSIndx[SUFFIX(p->MinContext)->NumStats] + p->MinContext->Flags];
}

/* 20.01 fix: frequency sums above Range would divide by zero in the original code */
#define CORRECT_SUM_RANGE(sum) if ((sum) > p->Range) (sum) = p->Range;

/* ---------------- decoder ---------------- */

#define IN_BYTE() gz_ppmd_in_byte(p->in)

GZ_INLINE void rc_norm(gz_ppmd8 *p)
{
    while ((p->Low ^ (p->Low + p->Range)) < RC_TOP
           || (p->Range < RC_BOT && ((p->Range = (0 - p->Low) & (RC_BOT - 1)), 1))) {
        p->Code = (p->Code << 8) | IN_BYTE();
        p->Range <<= 8;
        p->Low <<= 8;
    }
}

GZ_INLINE void rc_decode(gz_ppmd8 *p, u32 start, u32 size)
{
    start *= p->Range;
    p->Low += start;
    p->Code -= start;
    p->Range *= size;
}

GZ_INLINE u32 rc_threshold(gz_ppmd8 *p, u32 total)
{
    return p->Code / (p->Range /= total);
}

static int p8_decode(gz_ppmd8 *p)
{
    size_t maskw[256 / sizeof(size_t)];
    u8 *mask = (u8 *)maskw;

    if (p->MinContext->NumStats != 0) {
        STATE *s = STATS(p->MinContext);
        unsigned i;
        u32 count, hiCnt;
        u32 summFreq = p->MinContext->SummFreq;
        CORRECT_SUM_RANGE(summFreq)
        count = rc_threshold(p, summFreq);
        hiCnt = count;
        if ((i32)(count -= s->Freq) < 0) {
            u8 sym;
            rc_decode(p, 0, s->Freq);
            rc_norm(p);
            p->FoundState = s;
            sym = s->Symbol;
            update1_0(p);
            return sym;
        }
        p->PrevSuccess = 0;
        i = p->MinContext->NumStats;
        do {
            if ((i32)(count -= (++s)->Freq) < 0) {
                u8 sym;
                rc_decode(p, (hiCnt - count) - s->Freq, s->Freq);
                rc_norm(p);
                p->FoundState = s;
                sym = s->Symbol;
                update1(p);
                return sym;
            }
        } while (--i);
        if (hiCnt >= summFreq) return GZ_PPMD_SYM_ERROR;
        hiCnt -= count;
        rc_decode(p, hiCnt, summFreq - hiCnt);
        gz_ppmd_mask_all(mask);
        {
            STATE *s2 = STATS(p->MinContext);
            mask[s->Symbol] = 0;
            do {
                unsigned sym0 = s2[0].Symbol;
                unsigned sym1 = s2[1].Symbol;
                s2 += 2;
                mask[sym0] = 0;
                mask[sym1] = 0;
            } while (s2 < s);
        }
    } else {
        STATE *s = ONE_STATE(p->MinContext);
        u16 *prob = bin_summ(p);
        u32 pr = *prob;
        u32 size0 = (p->Range >> 14) * pr;
        pr = GZ_PPMD_UPDATE_PROB_1(pr);
        if (p->Code < size0) {
            u8 sym;
            *prob = (u16)(pr + (1 << GZ_PPMD_INT_BITS));
            p->Range = size0;
            rc_norm(p);
            {
                unsigned freq = s->Freq;
                CTX8 *c = CTX(SUCC(s));
                sym = s->Symbol;
                p->FoundState = s;
                p->PrevSuccess = 1;
                p->RunLength++;
                s->Freq = (u8)(freq + (freq < 196));
                if (p->OrderFall == 0 && (const u8 *)c >= p->UnitsStart)
                    p->MaxContext = p->MinContext = c;
                else
                    update_model(p);
            }
            return sym;
        }
        *prob = (u16)pr;
        p->InitEsc = p->ExpEscape[pr >> 10];
        p->Low += size0;
        p->Code -= size0;
        p->Range = (p->Range & ~((u32)GZ_PPMD_BIN_SCALE - 1)) - size0;
        gz_ppmd_mask_all(mask);
        mask[ONE_STATE(p->MinContext)->Symbol] = 0;
        p->PrevSuccess = 0;
    }

    for (;;) {
        STATE *s, *s2;
        u32 freqSum, count, hiCnt, freqSum2;
        SEE *see;
        CTX8 *mc;
        unsigned numMasked;
        rc_norm(p);
        mc = p->MinContext;
        numMasked = mc->NumStats;
        do {
            p->OrderFall++;
            if (!mc->Suffix) return GZ_PPMD_SYM_END;
            mc = CTX(mc->Suffix);
        } while (mc->NumStats == numMasked);

        s = STATS(mc);
        {
            unsigned num = (unsigned)mc->NumStats + 1;
            unsigned num2 = num / 2;
            num &= 1;
            hiCnt = (s->Freq & (unsigned)mask[s->Symbol]) & (0 - (u32)num);
            s += num;
            p->MinContext = mc;
            do {
                unsigned sym0 = s[0].Symbol;
                unsigned sym1 = s[1].Symbol;
                s += 2;
                hiCnt += (s[-2].Freq & (unsigned)mask[sym0]);
                hiCnt += (s[-1].Freq & (unsigned)mask[sym1]);
            } while (--num2);
        }

        see = make_esc_freq(p, numMasked, &freqSum);
        freqSum += hiCnt;
        freqSum2 = freqSum;
        CORRECT_SUM_RANGE(freqSum2)
        count = rc_threshold(p, freqSum2);

        if (count < hiCnt) {
            u8 sym;
            s = STATS(p->MinContext);
            hiCnt = count;
            for (;;) {
                count -= s->Freq & (unsigned)mask[s->Symbol];
                s++;
                if ((i32)count < 0) break;
            }
            s--;
            rc_decode(p, (hiCnt - count) - s->Freq, s->Freq);
            rc_norm(p);
            GZ_PPMD_SEE_UPDATE(see);
            p->FoundState = s;
            sym = s->Symbol;
            update2(p);
            return sym;
        }
        if (count >= freqSum2) return GZ_PPMD_SYM_ERROR;
        rc_decode(p, hiCnt, freqSum2 - hiCnt);
        see->Summ = (u16)(see->Summ + freqSum);

        s = STATS(p->MinContext);
        s2 = s + p->MinContext->NumStats + 1;
        do {
            mask[s->Symbol] = 0;
            s++;
        } while (s != s2);
    }
}

typedef struct {
    gz_ppmd_in in;                    /* must stay first */
    const gz_stream_io *io;
    u8 *buf;
    u64 total;
} p8_reader;

static int p8_refill(gz_ppmd_in *in)
{
    p8_reader *r = (p8_reader *)in;
    u32 got = 0;
    int e = r->io->read(r->io->ctx, r->buf, IBUF_SIZE, &got);
    if (e) return e;
    r->total += got;
    in->cur = r->buf;
    in->end = r->buf + got;
    return GZ_OK;
}

int gz_ppmd8_zip_decode_ex(gz_ppmd8 *p, const gz_stream_io *io, u64 out_size, u64 *in_used)
{
    p8_reader rd;
    u8 *obuf;
    u64 left = out_size;
    int sym = 0, r, i;
    u32 v, order, mem, restore;
    if (in_used) *in_used = 0;
    if ((r = p8_buffers(p)) != GZ_OK) return r;

    __builtin_memset(&rd, 0, sizeof(rd));
    rd.in.refill = p8_refill;
    rd.io = io;
    rd.buf = p->buf;
    obuf = p->buf + IBUF_SIZE;
    p->in = &rd.in;

    v = IN_BYTE();
    v |= IN_BYTE() << 8;
    if (rd.in.extra) { r = rd.in.err ? rd.in.err : GZ_E_TRUNC; goto done; }
    order = (v & 0xF) + 1;
    mem = ((v >> 4) & 0xFF) + 1;
    restore = v >> 12;
    if (order < GZ_PPMD8_MIN_ORDER) { r = GZ_E_DATA; goto done; }
    if (restore > GZ_PPMD8_FREEZE) { r = GZ_E_METHOD; goto done; }
    if ((r = p8_alloc(p, mem << 20)) != GZ_OK) goto done;

    p->Code = 0;
    p->Range = 0xFFFFFFFF;
    p->Low = 0;
    for (i = 0; i < 4; i++) p->Code = (p->Code << 8) | IN_BYTE();
    if (rd.in.extra) { r = rd.in.err ? rd.in.err : GZ_E_TRUNC; goto done; }
    if (p->Code == 0xFFFFFFFF) { r = GZ_E_DATA; goto done; }
    p8_init(p, order, restore);

    r = GZ_OK;
    while (left) {
        u32 n = left < OBUF_SIZE ? (u32)left : OBUF_SIZE, k;
        for (k = 0; k < n; k++) {
            sym = p8_decode(p);
            if (sym < 0 || rd.in.extra) break;
            obuf[k] = (u8)sym;
        }
        if (k && (r = io->write(io->ctx, obuf, k)) != GZ_OK) goto done;
        if (out_size != GZ_SIZE_UNKNOWN) left -= k;
        if (rd.in.extra) { r = rd.in.err ? rd.in.err : GZ_E_TRUNC; goto done; }
        if (sym < 0) break;
    }
    if (sym >= 0) sym = p8_decode(p);        /* the end marker must follow */
    if (rd.in.extra) r = rd.in.err ? rd.in.err : GZ_E_TRUNC;
    else if (sym != GZ_PPMD_SYM_END || p->Code != 0 || (out_size != GZ_SIZE_UNKNOWN && left))
        r = GZ_E_DATA;
done:
    if (in_used) *in_used = rd.total - (u64)(rd.in.end - rd.in.cur);
    p->in = 0;
    return r;
}

int gz_ppmd8_zip_decode(gz_ppmd8 *p, const gz_stream_io *io, u64 out_size)
{
    return gz_ppmd8_zip_decode_ex(p, io, out_size, 0);
}

/* ---------------- encoder ---------------- */

static GZ_NOINLINE void enc_flush(gz_ppmd8 *p)
{
    size_t n = (size_t)(p->op - p->obuf);
    p->op = p->obuf;
    if (n && !p->oerr) {
        int r = p->oio->write(p->oio->ctx, p->obuf, n);
        if (r) p->oerr = r;
        p->out_total += n;
    }
}

GZ_INLINE void enc_byte(gz_ppmd8 *p, u8 b)
{
    if (GZ_UNLIKELY(p->op == p->oend)) enc_flush(p);
    *p->op++ = b;
}

GZ_INLINE void rce_norm(gz_ppmd8 *p)
{
    while ((p->Low ^ (p->Low + p->Range)) < RC_TOP
           || (p->Range < RC_BOT && ((p->Range = (0 - p->Low) & (RC_BOT - 1)), 1))) {
        enc_byte(p, (u8)(p->Low >> 24));
        p->Range <<= 8;
        p->Low <<= 8;
    }
}

GZ_INLINE void rce_encode(gz_ppmd8 *p, u32 start, u32 size, u32 total)
{
    p->Low += start * (p->Range /= total);
    p->Range *= size;
}

static void p8_encode(gz_ppmd8 *p, int symbol)
{
    size_t maskw[256 / sizeof(size_t)];
    u8 *mask = (u8 *)maskw;

    if (p->MinContext->NumStats != 0) {
        STATE *s = STATS(p->MinContext);
        u32 sum;
        unsigned i;
        u32 summFreq = p->MinContext->SummFreq;
        CORRECT_SUM_RANGE(summFreq)
        if (s->Symbol == symbol) {
            rce_encode(p, 0, s->Freq, summFreq);
            rce_norm(p);
            p->FoundState = s;
            update1_0(p);
            return;
        }
        p->PrevSuccess = 0;
        sum = s->Freq;
        i = p->MinContext->NumStats;
        do {
            if ((++s)->Symbol == symbol) {
                rce_encode(p, sum, s->Freq, summFreq);
                rce_norm(p);
                p->FoundState = s;
                update1(p);
                return;
            }
            sum += s->Freq;
        } while (--i);
        rce_encode(p, sum, summFreq - sum, summFreq);
        gz_ppmd_mask_all(mask);
        {
            STATE *s2 = STATS(p->MinContext);
            mask[s->Symbol] = 0;
            do {
                unsigned sym0 = s2[0].Symbol;
                unsigned sym1 = s2[1].Symbol;
                s2 += 2;
                mask[sym0] = 0;
                mask[sym1] = 0;
            } while (s2 < s);
        }
    } else {
        u16 *prob = bin_summ(p);
        STATE *s = ONE_STATE(p->MinContext);
        u32 pr = *prob;
        const u32 bound = (p->Range >> 14) * pr;
        pr = GZ_PPMD_UPDATE_PROB_1(pr);
        if (s->Symbol == symbol) {
            *prob = (u16)(pr + (1 << GZ_PPMD_INT_BITS));
            p->Range = bound;
            rce_norm(p);
            {
                const unsigned freq = s->Freq;
                CTX8 *c = CTX(SUCC(s));
                p->FoundState = s;
                p->PrevSuccess = 1;
                p->RunLength++;
                s->Freq = (u8)(freq + (freq < 196));
                if (p->OrderFall == 0 && (const u8 *)c >= p->UnitsStart)
                    p->MaxContext = p->MinContext = c;
                else
                    update_model(p);
            }
            return;
        }
        *prob = (u16)pr;
        p->InitEsc = p->ExpEscape[pr >> 10];
        p->Low += bound;
        p->Range = (p->Range & ~((u32)GZ_PPMD_BIN_SCALE - 1)) - bound;
        gz_ppmd_mask_all(mask);
        mask[s->Symbol] = 0;
        p->PrevSuccess = 0;
    }

    for (;;) {
        SEE *see;
        STATE *s;
        u32 sum, escFreq;
        CTX8 *mc;
        unsigned i, numMasked;
        rce_norm(p);
        mc = p->MinContext;
        numMasked = mc->NumStats;
        do {
            p->OrderFall++;
            if (!mc->Suffix) return;          /* end marker (symbol -1) */
            mc = CTX(mc->Suffix);
        } while (mc->NumStats == numMasked);
        p->MinContext = mc;
        see = make_esc_freq(p, numMasked, &escFreq);

        s = STATS(p->MinContext);
        sum = 0;
        i = (unsigned)p->MinContext->NumStats + 1;
        do {
            const unsigned cur = s->Symbol;
            if ((int)cur == symbol) {
                const u32 low = sum;
                const u32 freq = s->Freq;
                unsigned num2;
                GZ_PPMD_SEE_UPDATE(see);
                p->FoundState = s;
                sum += escFreq;
                num2 = i / 2;
                i &= 1;
                sum += freq & (0 - (u32)i);
                if (num2 != 0) {
                    s += i;
                    for (;;) {
                        unsigned sym0 = s[0].Symbol;
                        unsigned sym1 = s[1].Symbol;
                        s += 2;
                        sum += (s[-2].Freq & (unsigned)mask[sym0]);
                        sum += (s[-1].Freq & (unsigned)mask[sym1]);
                        if (--num2 == 0) break;
                    }
                }
                CORRECT_SUM_RANGE(sum)
                rce_encode(p, low, freq, sum);
                rce_norm(p);
                update2(p);
                return;
            }
            sum += (s->Freq & (unsigned)mask[cur]);
            s++;
        } while (--i);
        {
            u32 total = sum + escFreq;
            see->Summ = (u16)(see->Summ + total);
            CORRECT_SUM_RANGE(total)
            rce_encode(p, sum, total - sum, total);
        }
        {
            const STATE *s2 = STATS(p->MinContext);
            s--;
            mask[s->Symbol] = 0;
            do {
                const unsigned sym0 = s2[0].Symbol;
                const unsigned sym1 = s2[1].Symbol;
                s2 += 2;
                mask[sym0] = 0;
                mask[sym1] = 0;
            } while (s2 < s);
        }
    }
}

void gz_ppmd8_zip_level(int level, u64 size, u32 *order, u32 *mem_mb, u32 *restore)
{
    u32 m, mem;
    if (level < 0) level = 5;
    if (level == 0) level = 1;
    if (level > 9) level = 9;
    mem = 1u << (level - 1);
    for (m = 1; m < mem; m <<= 1)
        if (size <= (u64)((m << 20) / 16)) { mem = m; break; }
    *mem_mb = mem;
    *order = 3 + (u32)level;
    *restore = level < 7 ? GZ_PPMD8_RESTART : GZ_PPMD8_CUT_OFF;
}

int gz_ppmd8_zip_encode_ex(gz_ppmd8 *p, u32 order, u32 mem_mb, u32 restore, const gz_stream_io *io,
                           u64 *in_size, u64 *out_size)
{
    u8 *ibuf;
    u64 total = 0;
    int r, i;
    u32 v;
    if (in_size) *in_size = 0;
    if (out_size) *out_size = 0;
    if (order < GZ_PPMD8_MIN_ORDER || order > GZ_PPMD8_MAX_ORDER || mem_mb < 1 || mem_mb > 256 ||
        restore > GZ_PPMD8_FREEZE)
        return GZ_E_METHOD;
    if ((r = p8_alloc(p, mem_mb << 20)) != GZ_OK || (r = p8_buffers(p)) != GZ_OK) return r;
    ibuf = p->buf;
    p->obuf = p->op = p->buf + EIN_SIZE;
    p->oend = p->obuf + EOUT_SIZE;
    p->oio = io;
    p->oerr = 0;
    p->out_total = 0;

    v = (order - 1) | ((mem_mb - 1) << 4) | (restore << 12);
    enc_byte(p, (u8)v);
    enc_byte(p, (u8)(v >> 8));
    p->Low = 0;
    p->Range = 0xFFFFFFFF;
    p8_init(p, order, restore);

    for (;;) {
        u32 got = 0, k;
        if ((r = io->read(io->ctx, ibuf, EIN_SIZE, &got)) != GZ_OK) return r;
        if (!got) break;
        for (k = 0; k < got; k++) p8_encode(p, ibuf[k]);
        if (p->oerr) return p->oerr;
        total += got;
    }
    p8_encode(p, -1);
    for (i = 0; i < 4; i++, p->Low <<= 8) enc_byte(p, (u8)(p->Low >> 24));
    enc_flush(p);
    if (in_size) *in_size = total;
    if (out_size) *out_size = p->out_total;
    return p->oerr;
}

int gz_ppmd8_zip_encode(gz_ppmd8 *p, u32 order, u32 mem_mb, u32 restore, const gz_stream_io *io)
{
    return gz_ppmd8_zip_encode_ex(p, order, mem_mb, restore, io, 0, 0);
}
