/*
 * 고깃ZIP - PPMd var.H (Ppmd7): model, 7z / RAR range decoders, 7z encoder
 *
 * A port of 7-Zip 23.01 C/Ppmd7.c, Ppmd7Dec.c, Ppmd7aDec.c and Ppmd7Enc.c (Igor Pavlov,
 * public domain; based on Dmitry Shkarin's PPMd var.H). Records refer to each other with
 * 32-bit offsets from the model block on every host, as 7-Zip does on 64-bit ones.
 *
 * Hostile input cannot break the model: the range decoder only picks among valid
 * symbol intervals (out-of-range counts are reported as errors before any update), so
 * any input is equivalent to encoding some byte sequence. Reads past the end of the
 * packed data are fed as zeros and counted (gz_ppmd_in.extra); every entry point stops
 * there.
 */
#include "ppmd7.h"

#define MAX_FREQ 124
#define UNIT_SIZE GZ_PPMD_UNIT_SIZE
#define NUM_INDEXES GZ_PPMD_NUM_INDEXES
#define U2B(nu) ((u32)(nu) * UNIT_SIZE)
#define U2I(nu) (p->Units2Indx[(size_t)(nu) - 1])
#define I2U(indx) ((unsigned)p->Indx2Units[indx])

#define RC_TOP (1u << 24)
#define RC_BOT (1u << 15)

#define IBUF_SIZE (64u << 10)        /* decoder input chunk  */
#define OBUF_SIZE (256u << 10)       /* decoder output chunk */
#define EIN_SIZE  (256u << 10)       /* encoder input chunk  */
#define EOUT_SIZE (64u << 10)        /* encoder output chunk */
#define BUF_SIZE  (IBUF_SIZE + OBUF_SIZE)

typedef gz_ppmd_state STATE;
typedef gz_ppmd_see SEE;

/* Context record (12 bytes). A binary context (NumStats == 1) keeps its only state in
 * place: Symbol/Freq overlay SummFreq, the successor overlays Stats (ONE_STATE). */
typedef struct CTX7 {
    u16 NumStats;
    u16 SummFreq;
    u32 Stats;
    u32 Suffix;
} CTX7;

/* Free-list node used while gluing free blocks (Stamp overlays NumStats / Symbol+Freq). */
typedef struct __attribute__((may_alias)) NODE7 {
    u16 Stamp;                       /* 0: free, 1: guard at LoUnit */
    u16 NU;
    u32 Next;
    u32 Prev;
} NODE7;

struct gz_ppmd7 {
    CTX7 *MinContext, *MaxContext;
    STATE *FoundState;
    unsigned OrderFall, InitEsc, PrevSuccess, MaxOrder, HiBitsFlag;
    u32 RunLength, InitRL;           /* signed in 7-Zip; only the sign bit is used */

    u32 Size, GlueCount, AlignOffset;
    u8 *Base, *LoUnit, *HiUnit, *Text, *UnitsStart;
    size_t block;                    /* bytes allocated at Base */

    /* range decoder (7z: Low unused; RAR: Code is relative to Low) */
    u32 Range, Code, Low;
    gz_ppmd_in *in;
    int rar;                         /* RAR model: 0 none, 1 ready, 2 failed */

    /* 7z range encoder */
    u64 eLow, CacheSize;
    u8 Cache;
    u8 *op, *oend, *obuf;
    const gz_stream_io *oio;
    int oerr;
    u64 out_total;

    u8 *buf;                         /* stream buffers, BUF_SIZE */

    u8 Indx2Units[NUM_INDEXES + 2];
    u8 Units2Indx[128];
    u32 FreeList[NUM_INDEXES];
    u8 NS2BSIndx[256], NS2Indx[256];
    u8 ExpEscape[16];
    SEE DummySee, See[25][16];
    u16 BinSumm[128][64];
};

static const u8 kExpEscape[16] = { 25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2 };
static const u16 kInitBinEsc[8] = { 0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051 };

#define REF(ptr)   ((u32)((const u8 *)(ptr) - p->Base))
#define PTR(ref)   ((void *)(p->Base + (ref)))
#define CTX(ref)   ((CTX7 *)PTR(ref))
#define STATS(ctx) ((STATE *)PTR((ctx)->Stats))
#define ONE_STATE(ctx) ((STATE *)(void *)&(ctx)->SummFreq)
#define SUFFIX(ctx) CTX((ctx)->Suffix)
#define NODE(ref)  ((NODE7 *)PTR(ref))
#define SUCC(s)    gz_ppmd_succ(s)
#define SET_SUCC(s, v) gz_ppmd_set_succ(s, v)

#define HIBITS3(sym) ((((unsigned)(sym) + 0xC0) >> (8 - 3)) & (1 << 3))
#define HIBITS4(sym) ((((unsigned)(sym) + 0xC0) >> (8 - 4)) & (1 << 4))

/* ---------------- byte reader ---------------- */

u32 gz_ppmd_in_slow(gz_ppmd_in *in)
{
    if (!in->err && !in->extra && in->refill) {
        int r = in->refill(in);
        if (r) in->err = r;
        else if (in->cur != in->end) return *in->cur++;
    }
    if (in->extra != 0xFFFFFFFFu) in->extra++;
    return 0;
}

/* ---------------- construction / memory ---------------- */

gz_ppmd7 *gz_ppmd7_new(void)
{
    gz_ppmd7 *p = (gz_ppmd7 *)gz_alloc(sizeof(gz_ppmd7));
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
    for (i = 0; i < 3; i++) p->NS2Indx[i] = (u8)i;
    for (m = i, k = 1; i < 256; i++) {
        p->NS2Indx[i] = (u8)m;
        if (--k == 0) k = (++m) - 2;
    }
    __builtin_memcpy(p->ExpEscape, kExpEscape, 16);
    return p;
}

static void p7_free_block(gz_ppmd7 *p)
{
    if (p->Base) gz_free_big(p->Base, p->block);
    p->Base = 0;
    p->Size = 0;
    p->block = 0;
    p->rar = 0;
}

void gz_ppmd7_free(gz_ppmd7 *p)
{
    if (!p) return;
    p7_free_block(p);
    gz_free(p->buf);
    gz_free(p);
}

/* Allocate the model block; keep the current one when the size is unchanged. */
static int p7_alloc(gz_ppmd7 *p, u32 size)
{
    if (p->Base && p->Size == size) return GZ_OK;
    p7_free_block(p);
    {
        u32 align = (4 - size) & 3;      /* makes the unit area end 4-aligned */
        size_t n = (size_t)align + size;
        p->Base = (u8 *)gz_alloc_big(n);
        if (!p->Base) return GZ_E_NOMEM;
        p->AlignOffset = align;
        p->Size = size;
        p->block = n;
    }
    return GZ_OK;
}

static int p7_buffers(gz_ppmd7 *p)
{
    if (!p->buf) p->buf = (u8 *)gz_alloc(BUF_SIZE);
    return p->buf ? GZ_OK : GZ_E_NOMEM;
}

/* ---------------- sub-allocator ---------------- */

GZ_INLINE void insert_node(gz_ppmd7 *p, void *node, unsigned indx)
{
    *(gz_ppmd_u32a *)node = p->FreeList[indx];
    p->FreeList[indx] = REF(node);
}

GZ_INLINE void *remove_node(gz_ppmd7 *p, unsigned indx)
{
    gz_ppmd_u32a *node = (gz_ppmd_u32a *)PTR(p->FreeList[indx]);
    p->FreeList[indx] = *node;
    return node;
}

static void split_block(gz_ppmd7 *p, void *ptr, unsigned oldIndx, unsigned newIndx)
{
    unsigned i, nu = I2U(oldIndx) - I2U(newIndx);
    ptr = (u8 *)ptr + U2B(I2U(newIndx));
    if (I2U(i = U2I(nu)) != nu) {
        unsigned k = I2U(--i);
        insert_node(p, ((u8 *)ptr) + U2B(k), nu - k - 1);
    }
    insert_node(p, ptr, i);
}

static void glue_free_blocks(gz_ppmd7 *p)
{
    /* The first u16 of a unit tells records apart: State.Symbol+Freq (Freq != 0),
     * Context.NumStats (!= 0), free node (0), guard at LoUnit (1). The last unit is
     * always the order-0 context, so walking right from a free block stays inside. */
    u32 head, n = 0;
    unsigned i;
    p->GlueCount = 255;
    if (p->LoUnit != p->HiUnit) ((NODE7 *)(void *)p->LoUnit)->Stamp = 1;

    /* one list of all free blocks */
    for (i = 0; i < NUM_INDEXES; i++) {
        const u16 nu = (u16)I2U(i);
        u32 next = p->FreeList[i];
        p->FreeList[i] = 0;
        while (next != 0) {
            NODE7 *un = NODE(next);
            const u32 tmp = next;
            next = *(gz_ppmd_u32a *)un;          /* read the link before overwriting */
            un->Stamp = 0;
            un->NU = nu;
            un->Next = n;
            n = tmp;
        }
    }
    head = n;

    /* glue adjacent free blocks (glue and fill walk the list in the same direction) */
    {
        gz_ppmd_u32a *prev = &head;
        while (n) {
            NODE7 *node = NODE(n);
            u32 nu = node->NU;
            n = node->Next;
            if (nu == 0) { *prev = n; continue; }
            prev = &node->Next;
            for (;;) {
                NODE7 *node2 = node + nu;
                nu += node2->NU;
                if (node2->Stamp != 0 || nu >= 0x10000) break;
                node->NU = (u16)nu;
                node2->NU = 0;
            }
        }
    }

    /* refill the free lists */
    for (n = head; n != 0;) {
        NODE7 *node = NODE(n);
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

static GZ_NOINLINE void *alloc_units_rare(gz_ppmd7 *p, unsigned indx)
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

static void *alloc_units(gz_ppmd7 *p, unsigned indx)
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

/* ---------------- model ---------------- */

static GZ_NOINLINE void restart_model(gz_ppmd7 *p)
{
    unsigned i, k;
    __builtin_memset(p->FreeList, 0, sizeof(p->FreeList));
    p->Text = p->Base + p->AlignOffset;
    p->HiUnit = p->Text + p->Size;
    p->LoUnit = p->UnitsStart = p->HiUnit - p->Size / 8 / UNIT_SIZE * 7 * UNIT_SIZE;
    p->GlueCount = 0;

    p->OrderFall = p->MaxOrder;
    p->RunLength = p->InitRL = (u32)(-(i32)((p->MaxOrder < 12) ? p->MaxOrder : 12) - 1);
    p->PrevSuccess = 0;
    {
        CTX7 *mc = (CTX7 *)(void *)(p->HiUnit -= UNIT_SIZE);
        STATE *s = (STATE *)(void *)p->LoUnit;
        p->LoUnit += U2B(256 / 2);
        p->MaxContext = p->MinContext = mc;
        p->FoundState = s;
        mc->NumStats = 256;
        mc->SummFreq = 256 + 1;
        mc->Stats = REF(s);
        mc->Suffix = 0;
        for (i = 0; i < 256; i++, s++) {
            s->Symbol = (u8)i;
            s->Freq = 1;
            SET_SUCC(s, 0);
        }
    }
    for (i = 0; i < 128; i++)
        for (k = 0; k < 8; k++) {
            unsigned m;
            u16 *dest = p->BinSumm[i] + k;
            const u16 val = (u16)(GZ_PPMD_BIN_SCALE - kInitBinEsc[k] / (i + 2));
            for (m = 0; m < 64; m += 8) dest[m] = val;
        }
    for (i = 0; i < 25; i++) {
        SEE *s = p->See[i];
        unsigned summ = ((5 * i + 10) << (GZ_PPMD_PERIOD_BITS - 4));
        for (k = 0; k < 16; k++, s++) {
            s->Summ = (u16)summ;
            s->Shift = (GZ_PPMD_PERIOD_BITS - 4);
            s->Count = 4;
        }
    }
    p->DummySee.Summ = 0;
    p->DummySee.Shift = GZ_PPMD_PERIOD_BITS;
    p->DummySee.Count = 64;
}

static void p7_init(gz_ppmd7 *p, unsigned maxOrder)
{
    p->MaxOrder = maxOrder;
    restart_model(p);
}

/* Called when FoundState->Successor is a raw-text successor: create the context
 * records along the suffix chain. Returns the new (or existing) context, NULL when
 * the memory block is full. */
static GZ_NOINLINE CTX7 *create_successors(gz_ppmd7 *p)
{
    CTX7 *c = p->MinContext;
    u32 upBranch = SUCC(p->FoundState);
    u8 newSym, newFreq;
    unsigned numPs = 0;
    STATE *ps[GZ_PPMD7_MAX_ORDER + 2];

    if (p->OrderFall != 0) ps[numPs++] = p->FoundState;
    while (c->Suffix) {
        u32 successor;
        STATE *s;
        c = SUFFIX(c);
        if (c->NumStats != 1) {
            u8 sym = p->FoundState->Symbol;
            for (s = STATS(c); s->Symbol != sym; s++) ;
        } else
            s = ONE_STATE(c);
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
    if (c->NumStats == 1)
        newFreq = ONE_STATE(c)->Freq;
    else {
        u32 cf, s0;
        STATE *s;
        for (s = STATS(c); s->Symbol != newSym; s++) ;
        cf = (u32)s->Freq - 1;
        s0 = (u32)c->SummFreq - c->NumStats - cf;
        newFreq = (u8)(1 + ((2 * cf <= s0) ? (5 * cf > s0) : (2 * cf + s0 - 1) / (2 * s0) + 1));
    }

    do {
        CTX7 *c1;
        if (p->HiUnit != p->LoUnit)
            c1 = (CTX7 *)(void *)(p->HiUnit -= UNIT_SIZE);
        else if (p->FreeList[0] != 0)
            c1 = (CTX7 *)remove_node(p, 0);
        else {
            c1 = (CTX7 *)alloc_units_rare(p, 0);
            if (!c1) return 0;
        }
        c1->NumStats = 1;
        ONE_STATE(c1)->Symbol = newSym;
        ONE_STATE(c1)->Freq = newFreq;
        SET_SUCC(ONE_STATE(c1), upBranch);
        c1->Suffix = REF(c);
        SET_SUCC(ps[--numPs], REF(c1));
        c = c1;
    } while (numPs != 0);
    return c;
}

#define SWAP_STATES(s) { STATE tmp_ = (s)[0]; (s)[0] = (s)[-1]; (s)[-1] = tmp_; }

static GZ_NOINLINE void update_model(gz_ppmd7 *p)
{
    u32 maxSuccessor, minSuccessor;
    CTX7 *c, *mc;
    unsigned s0, ns;

    if (p->FoundState->Freq < MAX_FREQ / 4 && p->MinContext->Suffix != 0) {
        /* update the symbol's frequency in the suffix context */
        c = SUFFIX(p->MinContext);
        if (c->NumStats == 1) {
            STATE *s = ONE_STATE(c);
            if (s->Freq < 32) s->Freq++;
        } else {
            STATE *s = STATS(c);
            u8 sym = p->FoundState->Symbol;
            if (s->Symbol != sym) {
                do { s++; } while (s->Symbol != sym);
                if (s[0].Freq >= s[-1].Freq) {
                    SWAP_STATES(s);
                    s--;
                }
            }
            if (s->Freq < MAX_FREQ - 9) {
                s->Freq = (u8)(s->Freq + 2);
                c->SummFreq = (u16)(c->SummFreq + 2);
            }
        }
    }

    if (p->OrderFall == 0) {
        /* max-order context: FoundState->Successor is a raw successor */
        p->MaxContext = p->MinContext = create_successors(p);
        if (!p->MinContext) { restart_model(p); return; }
        SET_SUCC(p->FoundState, REF(p->MinContext));
        return;
    }

    {
        u8 *text = p->Text;
        *text++ = p->FoundState->Symbol;
        p->Text = text;
        if (text >= p->UnitsStart) { restart_model(p); return; }
        maxSuccessor = REF(text);
    }

    minSuccessor = SUCC(p->FoundState);
    if (minSuccessor) {
        if (minSuccessor <= maxSuccessor) {
            /* raw successor: create the real context records */
            CTX7 *cs = create_successors(p);
            if (!cs) { restart_model(p); return; }
            minSuccessor = REF(cs);
        }
        if (--p->OrderFall == 0) {
            maxSuccessor = minSuccessor;
            p->Text -= (p->MaxContext != p->MinContext);
        }
    } else {
        /* NULL successor (order-0 only): make it a raw successor */
        SET_SUCC(p->FoundState, maxSuccessor);
        minSuccessor = REF(p->MinContext);
    }

    mc = p->MinContext;
    c = p->MaxContext;
    p->MaxContext = p->MinContext = CTX(minSuccessor);
    if (c == mc) return;

    /* add the symbol to the contexts [MaxContext .. MinContext) */
    s0 = mc->SummFreq - (ns = mc->NumStats) - ((unsigned)p->FoundState->Freq - 1);
    do {
        unsigned ns1;
        u32 sum;
        if ((ns1 = c->NumStats) != 1) {
            if ((ns1 & 1) == 0) {
                /* grow the state vector by one unit */
                unsigned oldNU = ns1 >> 1;
                unsigned i = U2I(oldNU);
                if (i != U2I((size_t)oldNU + 1)) {
                    void *ptr = alloc_units(p, i + 1);
                    void *oldPtr;
                    if (!ptr) { restart_model(p); return; }
                    oldPtr = STATS(c);
                    copy_units(ptr, oldPtr, oldNU);
                    insert_node(p, oldPtr, i);
                    c->Stats = REF(ptr);
                }
            }
            sum = c->SummFreq;
            sum += (u32)(2 * ns1 < ns) + 2 * ((unsigned)(4 * ns1 <= ns) & (sum <= 8 * ns1));
        } else {
            /* binary context becomes a 2-symbol context */
            STATE *s = (STATE *)alloc_units(p, 0);
            if (!s) { restart_model(p); return; }
            {
                unsigned freq = ONE_STATE(c)->Freq;
                s->Symbol = ONE_STATE(c)->Symbol;
                s->Successor_0 = ONE_STATE(c)->Successor_0;
                s->Successor_1 = ONE_STATE(c)->Successor_1;
                c->Stats = REF(s);
                if (freq < MAX_FREQ / 4 - 1) freq <<= 1;
                else freq = MAX_FREQ - 4;
                s->Freq = (u8)freq;
                sum = freq + p->InitEsc + (ns > 3);
            }
        }
        {
            STATE *s = STATS(c) + ns1;
            u32 cf = 2 * (sum + 6) * (u32)p->FoundState->Freq;
            u32 sf = (u32)s0 + sum;
            s->Symbol = p->FoundState->Symbol;
            c->NumStats = (u16)(ns1 + 1);
            SET_SUCC(s, maxSuccessor);
            if (cf < 6 * sf) {
                cf = (u32)1 + (cf > sf) + (cf >= 4 * sf);
                sum += 3;
            } else {
                cf = (u32)4 + (cf >= 9 * sf) + (cf >= 12 * sf) + (cf >= 15 * sf);
                sum += cf;
            }
            c->SummFreq = (u16)sum;
            s->Freq = (u8)cf;
        }
        c = SUFFIX(c);
    } while (c != mc);
}

static GZ_NOINLINE void rescale(gz_ppmd7 *p)
{
    unsigned i, adder, sumFreq, escFreq;
    STATE *stats = STATS(p->MinContext);
    STATE *s = p->FoundState;

    /* move the found state to the front */
    if (s != stats) {
        STATE tmp = *s;
        do s[0] = s[-1]; while (--s != stats);
        *s = tmp;
    }
    sumFreq = s->Freq;
    escFreq = p->MinContext->SummFreq - sumFreq;
    /* symbols may be dropped only from max-order contexts */
    adder = (p->OrderFall != 0);
    sumFreq = (sumFreq + 4 + adder) >> 1;
    i = (unsigned)p->MinContext->NumStats - 1;
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
        /* remove the states with Freq == 0 */
        CTX7 *mc;
        unsigned numStats, numStatsNew, n0, n1;
        i = 0;
        do { i++; } while ((--s)->Freq == 0);
        escFreq += i;
        mc = p->MinContext;
        numStats = mc->NumStats;
        numStatsNew = numStats - i;
        mc->NumStats = (u16)numStatsNew;
        n0 = (numStats + 1) >> 1;
        if (numStatsNew == 1) {
            unsigned freq = stats->Freq;
            do {
                escFreq >>= 1;
                freq = (freq + 1) >> 1;
            } while (escFreq > 1);
            s = ONE_STATE(mc);
            *s = *stats;
            s->Freq = (u8)freq;
            p->FoundState = s;
            insert_node(p, stats, U2I(n0));
            return;
        }
        n1 = (numStatsNew + 1) >> 1;
        if (n0 != n1) {
            unsigned i0 = U2I(n0);
            unsigned i1 = U2I(n1);
            if (i0 != i1) {
                if (p->FreeList[i1] != 0) {
                    void *ptr = remove_node(p, i1);
                    p->MinContext->Stats = REF(ptr);
                    copy_units(ptr, stats, n1);
                    insert_node(p, stats, i0);
                } else
                    split_block(p, stats, i0, i1);
            }
        }
    }
    {
        CTX7 *mc = p->MinContext;
        mc->SummFreq = (u16)(sumFreq + escFreq - (escFreq >> 1));
        p->FoundState = STATS(mc);
    }
}

static SEE *make_esc_freq(gz_ppmd7 *p, unsigned numMasked, u32 *escFreq)
{
    SEE *see;
    const CTX7 *mc = p->MinContext;
    unsigned numStats = mc->NumStats;
    if (numStats != 256) {
        unsigned nonMasked = numStats - numMasked;
        see = p->See[(unsigned)p->NS2Indx[(size_t)nonMasked - 1]]
            + (nonMasked < (unsigned)SUFFIX(mc)->NumStats - numStats)
            + 2 * (unsigned)(mc->SummFreq < 11 * numStats)
            + 4 * (unsigned)(numMasked > nonMasked)
            + p->HiBitsFlag;
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

GZ_INLINE void next_context(gz_ppmd7 *p)
{
    CTX7 *c = CTX(SUCC(p->FoundState));
    if (p->OrderFall == 0 && (const u8 *)c > p->Text)
        p->MaxContext = p->MinContext = c;
    else
        update_model(p);
}

static void update1(gz_ppmd7 *p)
{
    STATE *s = p->FoundState;
    unsigned freq = s->Freq;
    freq += 4;
    p->MinContext->SummFreq = (u16)(p->MinContext->SummFreq + 4);
    s->Freq = (u8)freq;
    if (freq > s[-1].Freq) {
        SWAP_STATES(s);
        p->FoundState = --s;
        if (freq > MAX_FREQ) rescale(p);
    }
    next_context(p);
}

static void update1_0(gz_ppmd7 *p)
{
    STATE *s = p->FoundState;
    CTX7 *mc = p->MinContext;
    unsigned freq = s->Freq;
    unsigned summFreq = mc->SummFreq;
    p->PrevSuccess = (2 * freq > summFreq);
    p->RunLength += p->PrevSuccess;
    mc->SummFreq = (u16)(summFreq + 4);
    freq += 4;
    s->Freq = (u8)freq;
    if (freq > MAX_FREQ) rescale(p);
    next_context(p);
}

static void update2(gz_ppmd7 *p)
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

/* Probability slot of a binary context; also sets HiBitsFlag from the last symbol. */
GZ_INLINE u16 *bin_summ(gz_ppmd7 *p)
{
    const STATE *one = ONE_STATE(p->MinContext);
    p->HiBitsFlag = HIBITS3(p->FoundState->Symbol);
    return &p->BinSumm[(size_t)one->Freq - 1]
        [p->PrevSuccess + ((p->RunLength >> 26) & 0x20)
         + p->NS2BSIndx[(size_t)SUFFIX(p->MinContext)->NumStats - 1]
         + HIBITS4(one->Symbol) + p->HiBitsFlag];
}

/* ---------------- range decoders (rar: 0 = 7z, 1 = RAR / Subbotin) ---------------- */

#define IN_BYTE() gz_ppmd_in_byte(p->in)

GZ_INLINE void rc_norm(gz_ppmd7 *p, const int rar)
{
    if (!rar) {
        if (p->Range < RC_TOP) {
            p->Code = (p->Code << 8) | IN_BYTE();
            p->Range <<= 8;
            if (p->Range < RC_TOP) {
                p->Code = (p->Code << 8) | IN_BYTE();
                p->Range <<= 8;
            }
        }
    } else {
        /* Range != 0 always holds for model-driven intervals; the check only makes a
         * broken state fail (freq sum > Range) instead of spinning. */
        while (p->Range && ((p->Low ^ (p->Low + p->Range)) < RC_TOP
               || (p->Range < RC_BOT && ((p->Range = (0 - p->Low) & (RC_BOT - 1)), 1)))) {
            p->Code = (p->Code << 8) | IN_BYTE();
            p->Range <<= 8;
            p->Low <<= 8;
        }
    }
}

GZ_INLINE void rc_decode(gz_ppmd7 *p, u32 start, u32 size, const int rar)
{
    start *= p->Range;
    if (rar) p->Low += start;
    p->Code -= start;
    p->Range *= size;
}

GZ_INLINE u32 rc_threshold(gz_ppmd7 *p, u32 total)
{
    return p->Code / (p->Range /= total);
}

GZ_INLINE int p7_decode(gz_ppmd7 *p, const int rar)
{
    size_t maskw[256 / sizeof(size_t)];
    u8 *mask = (u8 *)maskw;

    if (p->MinContext->NumStats != 1) {
        STATE *s = STATS(p->MinContext);
        unsigned i;
        u32 count, hiCnt;
        const u32 summFreq = p->MinContext->SummFreq;
        if (rar && summFreq > p->Range) return GZ_PPMD_SYM_ERROR;
        count = rc_threshold(p, summFreq);
        hiCnt = count;
        if ((i32)(count -= s->Freq) < 0) {
            u8 sym;
            rc_decode(p, 0, s->Freq, rar);
            rc_norm(p, rar);
            p->FoundState = s;
            sym = s->Symbol;
            update1_0(p);
            return sym;
        }
        p->PrevSuccess = 0;
        i = (unsigned)p->MinContext->NumStats - 1;
        do {
            if ((i32)(count -= (++s)->Freq) < 0) {
                u8 sym;
                rc_decode(p, (hiCnt - count) - s->Freq, s->Freq, rar);
                rc_norm(p, rar);
                p->FoundState = s;
                sym = s->Symbol;
                update1(p);
                return sym;
            }
        } while (--i);
        if (hiCnt >= summFreq) return GZ_PPMD_SYM_ERROR;
        hiCnt -= count;
        rc_decode(p, hiCnt, summFreq - hiCnt, rar);
        p->HiBitsFlag = HIBITS3(p->FoundState->Symbol);
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
            if (rar) rc_norm(p, 1);
            else if (p->Range < RC_TOP) {
                /* one step is enough: min(BinSumm) = 95 > 1 << (14 - 8) */
                p->Code = (p->Code << 8) | IN_BYTE();
                p->Range <<= 8;
            }
            {
                unsigned freq = s->Freq;
                CTX7 *c = CTX(SUCC(s));
                sym = s->Symbol;
                p->FoundState = s;
                p->PrevSuccess = 1;
                p->RunLength++;
                s->Freq = (u8)(freq + (freq < 128));
                if (p->OrderFall == 0 && (const u8 *)c > p->Text)
                    p->MaxContext = p->MinContext = c;
                else
                    update_model(p);
            }
            return sym;
        }
        *prob = (u16)pr;
        p->InitEsc = p->ExpEscape[pr >> 10];
        if (rar) {
            p->Low += size0;
            p->Code -= size0;
            p->Range = (p->Range & ~((u32)GZ_PPMD_BIN_SCALE - 1)) - size0;
        } else {
            p->Code -= size0;
            p->Range -= size0;
        }
        gz_ppmd_mask_all(mask);
        mask[ONE_STATE(p->MinContext)->Symbol] = 0;
        p->PrevSuccess = 0;
    }

    for (;;) {
        STATE *s, *s2;
        u32 freqSum, count, hiCnt;
        SEE *see;
        CTX7 *mc;
        unsigned numMasked;
        rc_norm(p, rar);
        mc = p->MinContext;
        numMasked = mc->NumStats;
        do {
            p->OrderFall++;
            if (!mc->Suffix) return GZ_PPMD_SYM_END;
            mc = CTX(mc->Suffix);
        } while (mc->NumStats == numMasked);

        s = STATS(mc);
        {
            unsigned num = mc->NumStats;
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
        if (rar && freqSum > p->Range) return GZ_PPMD_SYM_ERROR;
        count = rc_threshold(p, freqSum);

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
            rc_decode(p, (hiCnt - count) - s->Freq, s->Freq, rar);
            rc_norm(p, rar);
            GZ_PPMD_SEE_UPDATE(see);
            p->FoundState = s;
            sym = s->Symbol;
            update2(p);
            return sym;
        }
        if (count >= freqSum) return GZ_PPMD_SYM_ERROR;
        rc_decode(p, hiCnt, freqSum - hiCnt, rar);
        see->Summ = (u16)(see->Summ + freqSum);

        s = STATS(p->MinContext);
        s2 = s + p->MinContext->NumStats;
        do {
            mask[s->Symbol] = 0;
            s++;
        } while (s != s2);
    }
}

/* ---------------- 7z stream decoder ---------------- */

typedef struct {
    gz_ppmd_in in;                   /* must stay first */
    const gz_stream_io *io;
    u8 *buf;
    u64 total;
} p7_reader;

static int p7_refill(gz_ppmd_in *in)
{
    p7_reader *r = (p7_reader *)in;
    u32 got = 0;
    int e = r->io->read(r->io->ctx, r->buf, IBUF_SIZE, &got);
    if (e) return e;
    r->total += got;
    in->cur = r->buf;
    in->end = r->buf + got;
    return GZ_OK;
}

int gz_ppmd7z_props(const u8 *props, u32 n, u32 *order, u32 *mem)
{
    if (n < 5) return GZ_E_FORMAT;
    *order = props[0];
    *mem = rd32(props + 1);
    if (*order < GZ_PPMD7_MIN_ORDER || *order > GZ_PPMD7_MAX_ORDER ||
        *mem < GZ_PPMD7_MIN_MEM || *mem > GZ_PPMD7_MAX_MEM)
        return GZ_E_METHOD;
    return GZ_OK;
}

static int p7_check(u32 order, u32 mem)
{
    if (order < GZ_PPMD7_MIN_ORDER || order > GZ_PPMD7_MAX_ORDER ||
        mem < GZ_PPMD7_MIN_MEM || mem > GZ_PPMD7_MAX_MEM)
        return GZ_E_METHOD;
    if (mem > GZ_PPMD_MEM_CAP) return GZ_E_LIMIT;
    return GZ_OK;
}

static int p7z_decode_sym(gz_ppmd7 *p) { return p7_decode(p, 0); }

int gz_ppmd7z_decode_ex(gz_ppmd7 *p, u32 order, u32 mem, const gz_stream_io *io, u64 out_size,
                        u64 *in_used)
{
    p7_reader rd;
    u8 *obuf;
    u64 left = out_size;
    int sym = 0, r, i;
    if (in_used) *in_used = 0;
    if ((r = p7_check(order, mem)) != GZ_OK) return r;
    if ((r = p7_alloc(p, mem)) != GZ_OK || (r = p7_buffers(p)) != GZ_OK) return r;
    p->rar = 0;

    __builtin_memset(&rd, 0, sizeof(rd));
    rd.in.refill = p7_refill;
    rd.io = io;
    rd.buf = p->buf;
    obuf = p->buf + IBUF_SIZE;
    p->in = &rd.in;

    /* range decoder: a zero byte, then the 32-bit code */
    p->Code = 0;
    p->Range = 0xFFFFFFFF;
    p->Low = 0;
    r = (int)IN_BYTE();
    for (i = 0; i < 4; i++) p->Code = (p->Code << 8) | IN_BYTE();
    if (rd.in.extra) { r = rd.in.err ? rd.in.err : GZ_E_TRUNC; goto done; }
    if (r != 0 || p->Code == 0xFFFFFFFF) { r = GZ_E_DATA; goto done; }
    p7_init(p, order);

    r = GZ_OK;
    while (left) {
        u32 n = left < OBUF_SIZE ? (u32)left : OBUF_SIZE, k;
        for (k = 0; k < n; k++) {
            sym = p7z_decode_sym(p);
            if (sym < 0 || rd.in.extra) break;
            obuf[k] = (u8)sym;
        }
        if (k && (r = io->write(io->ctx, obuf, k)) != GZ_OK) goto done;
        if (out_size != GZ_SIZE_UNKNOWN) left -= k;
        if (rd.in.extra) { r = rd.in.err ? rd.in.err : GZ_E_TRUNC; goto done; }
        if (sym < 0) break;
    }
    if (sym == GZ_PPMD_SYM_ERROR) { r = GZ_E_DATA; goto done; }
    if (sym == GZ_PPMD_SYM_END) {
        /* end marker: only valid at the end, with a finished range coder */
        if ((out_size != GZ_SIZE_UNKNOWN && left) || p->Code != 0) r = GZ_E_DATA;
        goto done;
    }
    /* all bytes out: the range coder must be finished, or an end marker follows */
    if (p->Code != 0) {
        sym = p7z_decode_sym(p);
        if (rd.in.extra) r = rd.in.err ? rd.in.err : GZ_E_TRUNC;
        else if (sym != GZ_PPMD_SYM_END || p->Code != 0) r = GZ_E_DATA;
    }
done:
    if (in_used) *in_used = rd.total - (u64)(rd.in.end - rd.in.cur);
    p->in = 0;
    return r;
}

int gz_ppmd7z_decode(gz_ppmd7 *p, u32 order, u32 mem, const gz_stream_io *io, u64 out_size)
{
    return gz_ppmd7z_decode_ex(p, order, mem, io, out_size, 0);
}

/* ---------------- RAR 3.x symbol decoder ---------------- */

int gz_ppmd7_rar_model(gz_ppmd7 *p, u32 max_order, u32 mem)
{
    int r;
    p->rar = 0;
    if (max_order < GZ_PPMD7_MIN_ORDER || max_order > GZ_PPMD7_MAX_ORDER || mem < GZ_PPMD7_MIN_MEM)
        return GZ_E_DATA;
    if (mem > GZ_PPMD_MEM_CAP) return GZ_E_LIMIT;
    if ((r = p7_alloc(p, mem)) != GZ_OK) return r;
    p7_init(p, max_order);
    p->rar = 1;
    return GZ_OK;
}

void gz_ppmd7_rar_rc_init(gz_ppmd7 *p, gz_ppmd_in *in)
{
    int i;
    p->in = in;
    p->Code = 0;
    p->Range = 0xFFFFFFFF;
    p->Low = 0;
    for (i = 0; i < 4; i++) p->Code = (p->Code << 8) | gz_ppmd_in_byte(in);
}

GZ_NOINLINE int gz_ppmd7_rar_decode(gz_ppmd7 *p)
{
    int sym;
    if (p->rar != 1 || !p->in) return GZ_PPMD_SYM_ERROR;
    sym = p7_decode(p, 1);
    if (sym < 0) p->rar = 2;
    return sym;
}

int gz_ppmd7_rar_ready(const gz_ppmd7 *p) { return p->rar == 1; }
void gz_ppmd7_rar_drop(gz_ppmd7 *p) { p->rar = 0; }

/* ---------------- 7z encoder ---------------- */

static GZ_NOINLINE void enc_flush(gz_ppmd7 *p)
{
    size_t n = (size_t)(p->op - p->obuf);
    p->op = p->obuf;
    if (n && !p->oerr) {
        int r = p->oio->write(p->oio->ctx, p->obuf, n);
        if (r) p->oerr = r;
        p->out_total += n;
    }
}

GZ_INLINE void enc_byte(gz_ppmd7 *p, u8 b)
{
    if (GZ_UNLIKELY(p->op == p->oend)) enc_flush(p);
    *p->op++ = b;
}

static GZ_NOINLINE void rc_shift_low(gz_ppmd7 *p)
{
    if ((u32)p->eLow < 0xFF000000u || (unsigned)(p->eLow >> 32) != 0) {
        u8 temp = p->Cache;
        do {
            enc_byte(p, (u8)(temp + (u8)(p->eLow >> 32)));
            temp = 0xFF;
        } while (--p->CacheSize != 0);
        p->Cache = (u8)((u32)p->eLow >> 24);
    }
    p->CacheSize++;
    p->eLow = (u32)((u32)p->eLow << 8);
}

/* encoder normalisation / interval (Range already divided by the total) */
GZ_INLINE void rce_norm(gz_ppmd7 *p, const int rar)
{
    if (!rar) {
        if (p->Range < RC_TOP) {
            p->Range <<= 8;
            rc_shift_low(p);
            if (p->Range < RC_TOP) {
                p->Range <<= 8;
                rc_shift_low(p);
            }
        }
    } else {
        while ((p->Low ^ (p->Low + p->Range)) < RC_TOP
               || (p->Range < RC_BOT && ((p->Range = (0 - p->Low) & (RC_BOT - 1)), 1))) {
            enc_byte(p, (u8)(p->Low >> 24));
            p->Range <<= 8;
            p->Low <<= 8;
        }
    }
}

GZ_INLINE void rce_encode(gz_ppmd7 *p, u32 start, u32 size, const int rar)
{
    if (!rar) p->eLow += start * p->Range;
    else p->Low += start * p->Range;
    p->Range *= size;
}

/* Range /= total; the RAR coder cannot code a total above Range (the decoder rejects
 * it too), which only our test encoder can meet. */
GZ_INLINE void rce_div(gz_ppmd7 *p, u32 total, const int rar)
{
    if (rar && GZ_UNLIKELY(total > p->Range) && !p->oerr) p->oerr = GZ_E_DATA;
    p->Range /= total;
}

/* symbol: 0..255, or -1 for the end marker */
GZ_INLINE void p7_encode(gz_ppmd7 *p, int symbol, const int rar)
{
    size_t maskw[256 / sizeof(size_t)];
    u8 *mask = (u8 *)maskw;

    if (p->MinContext->NumStats != 1) {
        STATE *s = STATS(p->MinContext);
        u32 sum;
        unsigned i;
        rce_div(p, p->MinContext->SummFreq, rar);
        if (s->Symbol == symbol) {
            rce_encode(p, 0, s->Freq, rar);
            rce_norm(p, rar);
            p->FoundState = s;
            update1_0(p);
            return;
        }
        p->PrevSuccess = 0;
        sum = s->Freq;
        i = (unsigned)p->MinContext->NumStats - 1;
        do {
            if ((++s)->Symbol == symbol) {
                rce_encode(p, sum, s->Freq, rar);
                rce_norm(p, rar);
                p->FoundState = s;
                update1(p);
                return;
            }
            sum += s->Freq;
        } while (--i);
        rce_encode(p, sum, p->MinContext->SummFreq - sum, rar);
        p->HiBitsFlag = HIBITS3(p->FoundState->Symbol);
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
            if (rar) rce_norm(p, 1);
            else if (p->Range < RC_TOP) {
                p->Range <<= 8;
                rc_shift_low(p);
            }
            {
                const unsigned freq = s->Freq;
                CTX7 *c = CTX(SUCC(s));
                p->FoundState = s;
                p->PrevSuccess = 1;
                p->RunLength++;
                s->Freq = (u8)(freq + (freq < 128));
                if (p->OrderFall == 0 && (const u8 *)c > p->Text)
                    p->MaxContext = p->MinContext = c;
                else
                    update_model(p);
            }
            return;
        }
        *prob = (u16)pr;
        p->InitEsc = p->ExpEscape[pr >> 10];
        if (rar) {
            p->Low += bound;
            p->Range = (p->Range & ~((u32)GZ_PPMD_BIN_SCALE - 1)) - bound;
        } else {
            p->eLow += bound;
            p->Range -= bound;
        }
        gz_ppmd_mask_all(mask);
        mask[s->Symbol] = 0;
        p->PrevSuccess = 0;
    }

    for (;;) {
        SEE *see;
        STATE *s;
        u32 sum, escFreq;
        CTX7 *mc;
        unsigned i, numMasked;
        rce_norm(p, rar);
        mc = p->MinContext;
        numMasked = mc->NumStats;
        do {
            p->OrderFall++;
            if (!mc->Suffix) return;          /* end marker (symbol -1) */
            mc = CTX(mc->Suffix);
            i = mc->NumStats;
        } while (i == numMasked);
        p->MinContext = mc;
        see = make_esc_freq(p, numMasked, &escFreq);

        s = STATS(mc);
        sum = 0;
        do {
            const unsigned cur = s->Symbol;
            if ((int)cur == symbol) {
                const u32 low = sum;
                const u32 freq = s->Freq;
                unsigned num2;
                GZ_PPMD_SEE_UPDATE(see);
                p->FoundState = s;
                sum += escFreq;
                /* add the unmasked frequencies from s to the end */
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
                rce_div(p, sum, rar);
                rce_encode(p, low, freq, rar);
                rce_norm(p, rar);
                update2(p);
                return;
            }
            sum += (s->Freq & (unsigned)mask[cur]);
            s++;
        } while (--i);
        {
            const u32 total = sum + escFreq;
            see->Summ = (u16)(see->Summ + total);
            rce_div(p, total, rar);
            rce_encode(p, sum, escFreq, rar);
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

static void p7z_encode_sym(gz_ppmd7 *p, int sym) { p7_encode(p, sym, 0); }

void gz_ppmd7z_write_props(u8 props[5], u32 order, u32 mem)
{
    props[0] = (u8)order;
    wr32(props + 1, mem);
}

void gz_ppmd7z_level(int level, u64 size, u32 *order, u32 *mem)
{
    static const u8 kOrders[10] = { 3, 4, 4, 5, 5, 6, 8, 16, 24, 32 };
    u32 m, i;
    if (level < 0) level = 5;
    if (level > 9) level = 9;
    m = (u32)1 << (level + 19);
    if (size < 0xFFFFFFFFu && m / 16 > size)
        for (i = 16; i < 32; i++) {
            u32 mm = (u32)1 << i;
            if (size <= mm / 16) {
                if (m > mm) m = mm;
                break;
            }
        }
    *mem = m;
    *order = kOrders[level];
}

int gz_ppmd7z_encode_ex(gz_ppmd7 *p, u32 order, u32 mem, const gz_stream_io *io,
                        u64 *in_size, u64 *out_size)
{
    u8 *ibuf;
    u64 total = 0;
    int r, i;
    if (in_size) *in_size = 0;
    if (out_size) *out_size = 0;
    if ((r = p7_check(order, mem)) != GZ_OK) return r;
    if ((r = p7_alloc(p, mem)) != GZ_OK || (r = p7_buffers(p)) != GZ_OK) return r;
    p->rar = 0;
    ibuf = p->buf;
    p->obuf = p->op = p->buf + EIN_SIZE;
    p->oend = p->obuf + EOUT_SIZE;
    p->oio = io;
    p->oerr = 0;
    p->out_total = 0;

    p->eLow = 0;
    p->Range = 0xFFFFFFFF;
    p->Cache = 0;
    p->CacheSize = 1;
    p7_init(p, order);

    for (;;) {
        u32 got = 0, k;
        if ((r = io->read(io->ctx, ibuf, EIN_SIZE, &got)) != GZ_OK) return r;
        if (!got) break;
        for (k = 0; k < got; k++) p7z_encode_sym(p, ibuf[k]);
        if (p->oerr) return p->oerr;
        total += got;
    }
    for (i = 0; i < 5; i++) rc_shift_low(p);
    enc_flush(p);
    if (in_size) *in_size = total;
    if (out_size) *out_size = p->out_total;
    return p->oerr;
}

int gz_ppmd7z_encode(gz_ppmd7 *p, u32 order, u32 mem, const gz_stream_io *io)
{
    return gz_ppmd7z_encode_ex(p, order, mem, io, 0, 0);
}

/* ---------------- test helpers (not used by the readers) ---------------- */

static void p7rar_encode_sym(gz_ppmd7 *p, int sym) { p7_encode(p, sym, 1); }

int gz_ppmd7_rar_enc_begin(gz_ppmd7 *p, u32 max_order, u32 mem, const gz_stream_io *io)
{
    int r;
    if (max_order < GZ_PPMD7_MIN_ORDER || max_order > GZ_PPMD7_MAX_ORDER || mem < GZ_PPMD7_MIN_MEM)
        return GZ_E_METHOD;
    if (mem > GZ_PPMD_MEM_CAP) return GZ_E_LIMIT;
    if ((r = p7_alloc(p, mem)) != GZ_OK || (r = p7_buffers(p)) != GZ_OK) return r;
    p->rar = 0;
    p->obuf = p->op = p->buf + EIN_SIZE;
    p->oend = p->obuf + EOUT_SIZE;
    p->oio = io;
    p->oerr = 0;
    p->out_total = 0;
    p->Low = 0;
    p->Range = 0xFFFFFFFF;
    p7_init(p, max_order);
    return GZ_OK;
}

int gz_ppmd7_rar_enc_begin_rc(gz_ppmd7 *p, const gz_stream_io *io)
{
    if (!p->Base || !p->buf) return GZ_E_DATA;
    p->obuf = p->op = p->buf + EIN_SIZE;
    p->oend = p->obuf + EOUT_SIZE;
    p->oio = io;
    p->Low = 0;
    p->Range = 0xFFFFFFFF;
    return p->oerr;
}

int gz_ppmd7_rar_enc_symbol(gz_ppmd7 *p, int sym)
{
    p7rar_encode_sym(p, sym);
    return p->oerr;
}

int gz_ppmd7_rar_enc_end(gz_ppmd7 *p)
{
    int i;
    for (i = 0; i < 4; i++, p->Low <<= 8) enc_byte(p, (u8)(p->Low >> 24));
    enc_flush(p);
    return p->oerr;
}

void gz_ppmd7_rar_rc_test(gz_ppmd7 *p, gz_ppmd_in *in, u32 seed, u32 n,
                          void (*cb)(void *user, const u32 rec[8]), void *user)
{
    u32 rec[8], x = seed | 1, i;
#define RND() (x ^= x << 13, x ^= x >> 17, x ^= x << 5, x)
    gz_ppmd7_rar_rc_init(p, in);
    for (i = 0; i < n; i++) {
        __builtin_memset(rec, 0, sizeof(rec));
        if (RND() & 1) {
            u32 total = 1 + RND() % 0x7FFF, count, start, end;
            rec[0] = 0;
            rec[1] = total;
            if (total > p->Range) break;          /* cannot happen after rc_norm */
            count = rc_threshold(p, total);
            rec[3] = count;
            if (count >= total) { rec[0] = 2; cb(user, rec); break; }
            start = count - RND() % (count + 1);
            end = count + 1 + RND() % (total - count);
            rec[2] = (start << 16) | (end - start);
            rc_decode(p, start, end - start, 1);
        } else {
            u32 pr = 95 + RND() % (16384 - 95 - 64), size0 = (p->Range >> 14) * pr;
            rec[0] = 1;
            rec[1] = pr;
            rec[3] = p->Code >= size0;
            if (!rec[3]) p->Range = size0;
            else {
                p->Low += size0;
                p->Code -= size0;
                p->Range = (p->Range & ~((u32)GZ_PPMD_BIN_SCALE - 1)) - size0;
            }
        }
        rc_norm(p, 1);
        rec[4] = p->Range;
        rec[5] = p->Code;
        rec[6] = p->Low;
        rec[7] = in->extra;
        cb(user, rec);
    }
#undef RND
}
