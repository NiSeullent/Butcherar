/*
 * 고깃ZIP - RAR 1.5 - 4.x unpacker (see rar3dec.h)
 *
 * Window: a power-of-two ring; pos is the 64-bit stream offset of window
 * index wp_sync. The decoding loops run while the input pointer is below p_lim
 * (enough buffered input) and the window index below wp_stop (no wrap inside
 * one match, unflushed data within bounds, declared size not reached).
 * sync() accounts decoded bytes, flushes, refills input and sets those limits.
 *
 * Bit input is MSB first (unrar's getbits): a 64-bit buffer refilled branch-
 * free from big-endian 8-byte loads; the input buffer has zero padding. PPMd
 * blocks read bytes straight from the same buffer through a gz_ppmd_in.
 *
 * RAR VM filters keep absolute stream positions. flush() follows unrar's
 * UnpWriteBuf30: filters are visited in definition order, plain data is
 * written up to a filter's block, the block is filtered (with the filters
 * stacked on the same block) once it is decoded completely, and window data
 * stays unfiltered for later matches.
 *
 * The algorithms follow unrar's unpack15.cpp / unpack20.cpp / unpack30.cpp /
 * rarvm.cpp (the public unRAR sources) and 7-Zip's Rar1/2/3 decoders.
 */
#include "rar3dec.h"
#include "ppmd7.h"
#include "crc32.h"

#define NC30   299
#define DC30   60
#define LDC30  17
#define RC30   28
#define BC30   20
#define T30    (NC30 + DC30 + LDC30 + RC30)
#define NC20   298
#define DC20   48
#define RC20   28
#define BC20   19
#define MC20   257
#define T20    (MC20 * 4)
#define MAXM   512u                /* bound on one match (longest: PPMd 255 + 32) */
#define MIN_WIN (1u << 20)
#define IN_CAP (256u << 10)
#define IN_PAD 64u
#define VM_MEM 0x40000u            /* RAR VM memory: filter blocks are at most this */
#define MAX_FILTERS 8192u
#define VMCODE_CAP (0x10000u + 16)

/* quick-lookup widths (bits) per table */
#define QB_MAIN 10
#define QB_DIST 9
#define QB_LOW  7
#define QB_LEN  8
#define QB_BD   7

enum { R3_DONE = -1, R3_EOF = -2, R3_SWITCH = -3 };
enum { F_UNKNOWN = 0, F_E8, F_E8E9, F_ITANIUM, F_DELTA, F_RGB, F_AUDIO, F_BADCODE };

typedef struct {
    u32 lim[17];             /* left-justified 16-bit end of the codes of length <= L */
    u16 pos[17];             /* index in sym[] of the first code of length L          */
    u16 sym[NC30];           /* symbols ordered by (length, value)                    */
    u16 quick[1 << QB_MAIN]; /* sym << 4 | length, 0 = longer than the quick width    */
} huff;

typedef struct { u64 start; u32 len, type, r0, r1; u8 live, pad_[7]; } r3_flt;
typedef struct { u32 type, len; } r3_fdef;

typedef struct {
    int k[5], d[4], last_delta;
    u32 dif[11], count;
    u32 last_char;
} r3_audio;

struct gz_rar3_dec {
    /* window */
    u8 *win;
    size_t wsize, wmask;
    size_t wp, wp_sync, wp_stop;
    u64 pos;                 /* stream position of wp_sync                         */
    u64 wr;                  /* stream position written out                        */
    int full;                /* every window byte holds decoded data               */
    /* bit input */
    u8 *in;
    const u8 *p, *in_end, *p_lim;
    u64 bb;
    u32 bc;
    int in_eof;
    u64 in_base;             /* packed stream offset of in[0]                      */
    /* current call */
    const gz_stream_io *io;
    u64 file_start, out_size, out_done, thresh;
    int alg, state_ok;
    /* LZ state shared by RAR 1.5 / 2.0 / 2.9 (as in unrar) */
    u32 rep[4], rep_ptr, last_len, last_dist;
    /* RAR 2.9 */
    huff tmain, tdist, tlow, tlen, tbd;
    u8 old30[T30];
    int tables30, ppm_mode, esc;
    u32 prev_low, low_rep;
    gz_ppmd7 *ppm;
    u64 ppm_mem;
    gz_ppmd_in pin;
    r3_fdef *fdef;  u32 nfdef, capfdef;
    r3_flt *flt;    u32 nflt, capflt;
    u32 last_filter;
    u8 *vm;                  /* 2 * VM_MEM + 8: filter input / output          */
    u8 *vmcode;              /* VMCODE_CAP                                      */
    /* RAR 2.0 */
    huff md[4];
    u8 old20[T20];
    int tables20, audio;
    u32 channels, cur_channel;
    int channel_delta;
    r3_audio aud[4];
    /* RAR 1.5 */
    u16 chset[256], chseta[256], chsetb[256], chsetc[256];
    u8 ntopl[256], ntoplb[256], ntoplc[256];
    u32 avr_plc, avr_plcb, avr_ln1, avr_ln2, avr_ln3, num_huf, buf60, max_dist3, nhfb, nlzb;
    int flags_cnt, st_mode, lcount;
    u32 flag_buf;
};

static const u8 ldec[28] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224 };
static const u8 lbits[28] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5 };
static const u32 ddec[DC30] = {
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
    1048576, 1310720, 1572864, 1835008, 2097152, 2359296, 2621440, 2883584, 3145728, 3407872,
    3670016, 3932160 };
static const u8 dbits[DC30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
    14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18 };
static const u8 sddec[8] = { 0, 4, 8, 16, 32, 64, 128, 192 };
static const u8 sdbits[8] = { 2, 2, 3, 4, 5, 6, 6, 6 };

GZ_INLINE int iabs(int v) { return v < 0 ? -v : v; }

/* ---------------- Huffman tables ---------------- */

static int huff_build(huff *h, const u8 *len, u32 n, u32 qb)
{
    u32 cnt[16], next[16];
    __builtin_memset(cnt, 0, sizeof cnt);
    for (u32 i = 0; i < n; i++) cnt[len[i] & 15]++;
    u32 code = 0, idx = 0;
    h->lim[0] = 0;
    h->pos[0] = 0;
    for (u32 l = 1; l <= 15; l++) {
        h->pos[l] = (u16)idx;
        next[l] = idx;
        idx += cnt[l];
        if (code + cnt[l] > (1u << l)) return 0;          /* over-subscribed */
        h->lim[l] = (code + cnt[l]) << (16 - l);
        code = (code + cnt[l]) << 1;
    }
    h->lim[16] = h->lim[15];
    for (u32 i = 0; i < n; i++)
        if (len[i] & 15) h->sym[next[len[i] & 15]++] = (u16)i;
    __builtin_memset(h->quick, 0, sizeof(u16) << qb);
    for (u32 l = 1; l <= qb; l++) {
        u32 c = h->lim[l - 1] >> (16 - l), step = 1u << (qb - l);
        for (u32 j = 0; j < cnt[l]; j++, c++) {
            u16 v = (u16)(h->sym[h->pos[l] + j] << 4 | l);
            u16 *q = h->quick + (c << (qb - l));
            for (u32 t = 0; t < step; t++) q[t] = v;
        }
    }
    return 1;
}

/* code longer than the quick width (or invalid: 0) for the 16 bits v */
static GZ_NOINLINE u32 huff_slow(const huff *h, u32 v, u32 qb)
{
    for (u32 l = qb + 1; l <= 15; l++)
        if (v < h->lim[l]) return (u32)h->sym[h->pos[l] + ((v - h->lim[l - 1]) >> (16 - l))] << 4 | l;
    return 0;
}

/* ---------------- bit input ---------------- */

GZ_INLINE u64 rd64be_(const u8 *p) { return __builtin_bswap64(rd64(p)); }

#define REFILL()   do { bb |= rd64be_(p) >> bc; p += (63 - bc) >> 3; bc |= 56; } while (0)
#define GETBITS(n) ((bb >> (63 - (n))) >> 1)        /* n = 0..63 */
#define DROP(n)    do { bb <<= (n); bc -= (n); } while (0)
#define DECODE(h, qb, out) do { \
        u32 v_ = (u32)(bb >> 48); \
        u32 q_ = (h)->quick[v_ >> (16 - (qb))]; \
        if (GZ_UNLIKELY(!(q_ & 15))) { q_ = huff_slow((h), v_, (qb)); if (!q_) goto bad; } \
        DROP(q_ & 15); \
        (out) = q_ >> 4; \
    } while (0)
#define LOADBITS() const u8 *p = d->p; u64 bb = d->bb; u32 bc = d->bc
#define SAVEBITS() do { d->p = p; d->bb = bb; d->bc = bc; } while (0)

/* unrar's fgetbits() / faddbits() on the decoder state (RAR 1.5 code) */
GZ_INLINE u32 fget(gz_rar3_dec *d)
{
    if (d->bc < 16) {
        d->bb |= rd64be_(d->p) >> d->bc;
        d->p += (63 - d->bc) >> 3;
        d->bc |= 56;
    }
    return (u32)(d->bb >> 48);
}

GZ_INLINE void fadd(gz_rar3_dec *d, u32 n)
{
    if (d->bc < n) fget(d);
    d->bb <<= n;
    d->bc -= n;
}

static u64 bitpos(const gz_rar3_dec *d)
{
    return (d->in_base + (u64)(d->p - d->in)) * 8 - d->bc;
}

static u64 in_end_bits(const gz_rar3_dec *d)
{
    return (d->in_base + (u64)(d->in_end - d->in)) * 8;
}

/* Keep the unread tail and read until the buffer is full or the input ends. */
static int fill(gz_rar3_dec *d)
{
    size_t keep = d->p < d->in_end ? (size_t)(d->in_end - d->p) : 0;
    if (d->p != d->in) {
        if (keep) __builtin_memmove(d->in, d->p, keep);
        d->in_base += (u64)(d->p - d->in);
        d->p = d->in;
    }
    u32 n = (u32)keep;
    while (!d->in_eof && n + 4096 <= IN_CAP) {
        u32 got = 0;
        int r = d->io->read(d->io->ctx, d->in + n, IN_CAP - n, &got);
        if (r) return r;
        if (!got) { d->in_eof = 1; break; }
        if (got > IN_CAP - n) return GZ_E_IO;
        n += got;
    }
    d->in_end = d->in + n;
    __builtin_memset(d->in + n, 0, IN_PAD);
    return GZ_OK;
}

static int need(gz_rar3_dec *d)
{
    return (!d->in_eof && d->p + 32 > d->in_end) ? fill(d) : GZ_OK;
}

/* byte reader for PPMd blocks: refill from the same input buffer */
static int ppm_refill(gz_ppmd_in *in)
{
    gz_rar3_dec *d = (gz_rar3_dec *)in->user;
    d->p = in->cur;
    d->bb = 0;
    d->bc = 0;
    int r = fill(d);
    in->cur = d->p;
    in->end = d->in_end;
    return r;
}

/* ---------------- output ---------------- */

static int emit(gz_rar3_dec *d, const u8 *p, size_t n)
{
    if (d->out_size != GZ_SIZE_UNKNOWN) {
        u64 rem = d->out_size - d->out_done;
        if (n > rem) n = (size_t)rem;
    }
    if (!n) return GZ_OK;
    d->out_done += n;
    return d->io->write(d->io->ctx, p, n);
}

static int emit_win(gz_rar3_dec *d, u64 from, u64 to)
{
    while (from < to) {
        size_t i = (size_t)from & d->wmask;
        u64 n = to - from;
        if (n > d->wsize - i) n = d->wsize - i;
        int r = emit(d, d->win + i, (size_t)n);
        if (r) return r;
        from += n;
    }
    return GZ_OK;
}

static void advance(gz_rar3_dec *d)
{
    d->pos += (u64)((d->wp - d->wp_sync) & d->wmask);
    d->wp_sync = d->wp;
    if (d->pos >= d->wsize) d->full = 1;
}

/* LZ copy without checks (dist >= 1, the source was written) */
GZ_INLINE void lzcopy(u8 *win, size_t *pwp, size_t mask, size_t wsize, u32 len, size_t dist)
{
    size_t wp = *pwp, src = (wp - dist) & mask;
    /* fast copy: source behind the destination (dist >= 8: 8-byte steps are
     * exact LZ semantics), or a wrapped source that does not overlap */
    if (GZ_LIKELY(wp + len <= wsize && (src < wp || (src + len <= wsize && wp + len <= src)))) {
        u8 *o = win + wp;
        const u8 *s = win + src;
        if (dist >= 8 || src > wp) {
            if (len >= 8) {
                u8 *e = o + len - 8;
                const u8 *se = s + len - 8;
                do { wr64(o, rd64(s)); o += 8; s += 8; } while (o < e);
                wr64(e, rd64(se));
            } else if (len >= 4) {
                u32 a = rd32(s), b = rd32(s + len - 4);
                wr32(o, a);
                wr32(o + len - 4, b);
            } else {
                for (u32 i = 0; i < len; i++) o[i] = s[i];
            }
        } else if (dist == 1 && len >= 8) {
            u64 v = 0x0101010101010101ull * s[0];
            u8 *e = o + len - 8;
            do { wr64(o, v); o += 8; } while (o < e);
            wr64(e, v);
        } else {
            for (u32 i = 0; i < len; i++) o[i] = s[i];
        }
        *pwp = (wp + len) & mask;
    } else {
        for (u32 i = 0; i < len; i++) {
            win[wp] = win[src];
            wp = (wp + 1) & mask;
            src = (src + 1) & mask;
        }
        *pwp = wp;
    }
}

/* checked copy for the slower paths (PPMd, RAR 1.5) */
static int copy(gz_rar3_dec *d, u32 len, u32 dist)
{
    if (!len) return GZ_OK;
    size_t wfull = d->full ? d->wsize : 0;
    if ((size_t)dist - 1 >= d->wp && (size_t)dist - 1 >= wfull) return GZ_E_DATA;
    lzcopy(d->win, &d->wp, d->wmask, d->wsize, len, dist);
    return GZ_OK;
}

/* ---------------- RAR VM standard filters ---------------- */

static void flt_e8(u8 *b, u32 n, u32 off, int e9)
{
    if (n <= 4) return;
    /* E8 / E9 bytes are found 8 at a time: (x & m) ^ E8.. has a zero byte */
    const u64 m = e9 ? 0xFEFEFEFEFEFEFEFEull : ~0ull, k = 0xE8E8E8E8E8E8E8E8ull;
    const u64 lo = 0x0101010101010101ull, hi = 0x8080808080808080ull;
    for (u32 i = 0, lim = n - 4; i < lim;) {
        while (i + 8 <= lim) {
            u64 x = (rd64(b + i) & m) ^ k;
            if ((x - lo) & ~x & hi) break;
            i += 8;
        }
        if (i >= lim) break;
        u8 c = b[i++];
        if (c != 0xE8 && !(e9 && c == 0xE9)) continue;
        u32 o = i + off, a = rd32(b + i);
        if (a & 0x80000000u) {
            if (!((a + o) & 0x80000000u)) wr32(b + i, a + 0x1000000u);
        } else if (a < 0x1000000u) {
            wr32(b + i, a - o);
        }
        i += 4;
    }
}

static u32 ita_get(const u8 *p, u32 pos, u32 cnt)
{
    const u8 *q = p + (pos >> 3);
    u32 v = (u32)q[0] | (u32)q[1] << 8 | (u32)q[2] << 16 | (u32)q[3] << 24;
    return (v >> (pos & 7)) & (0xFFFFFFFFu >> (32 - cnt));
}

static void ita_set(u8 *p, u32 v, u32 pos, u32 cnt)
{
    u8 *q = p + (pos >> 3);
    u32 sh = pos & 7, am = ~((0xFFFFFFFFu >> (32 - cnt)) << sh);
    v <<= sh;
    for (u32 i = 0; i < 4; i++) {
        q[i] = (u8)((q[i] & am) | v);
        am = (am >> 8) | 0xFF000000u;
        v >>= 8;
    }
}

static void flt_itanium(u8 *b, u32 n, u32 off)
{
    static const u8 masks[16] = { 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0 };
    if (n <= 21) return;
    u32 fo = off >> 4;
    for (u32 pos = 0; pos < n - 21; pos += 16, fo++) {
        u8 *q = b + pos;
        int t = (q[0] & 0x1F) - 0x10;
        if (t < 0) continue;
        u32 cm = masks[t];
        for (u32 s = 0; s <= 2; s++) {
            if (!(cm & (1u << s))) continue;
            u32 sp = s * 41 + 5;
            if (ita_get(q, sp + 37, 4) == 5) ita_set(q, (ita_get(q, sp + 13, 20) - fo) & 0xFFFFF, sp + 13, 20);
        }
    }
}

static void flt_delta(const u8 *s, u8 *o, u32 n, u32 ch)
{
    for (u32 c = 0; c < ch; c++) {
        u8 prev = 0;
        for (u32 i = c; i < n; i += ch) o[i] = prev = (u8)(prev - *s++);
    }
}

/* width: RAR's R0 (bytes per line + 3), 4 <= width <= n; posr <= 2 */
static void flt_rgb(const u8 *s, u8 *o, u32 n, u32 width, u32 posr)
{
    for (u32 c = 0; c < 3; c++) {
        u32 prev = 0;
        for (u32 i = c; i < n; i += 3) {
            u32 pred = prev;
            if (i >= width) {
                int up = o[i - width + 3], ul = o[i - width], pr = (int)prev + up - ul;
                int pa = iabs(pr - (int)prev), pb = iabs(pr - up), pc = iabs(pr - ul);
                if (pa <= pb && pa <= pc) pred = prev;
                else if (pb <= pc) pred = (u32)up;
                else pred = (u32)ul;
            }
            o[i] = (u8)(pred - *s++);
            prev = o[i];
        }
    }
    for (u32 i = posr; i + 2 < n; i += 3) {
        u8 g = o[i + 1];
        o[i] = (u8)(o[i] + g);
        o[i + 2] = (u8)(o[i + 2] + g);
    }
}

static void flt_audio(const u8 *s, u8 *o, u32 n, u32 ch)
{
    for (u32 c = 0; c < ch; c++) {
        u32 prev = 0, dif[7];
        int pdelta = 0, d1 = 0, d2 = 0, d3, k1 = 0, k2 = 0, k3 = 0;
        __builtin_memset(dif, 0, sizeof dif);
        for (u32 i = c, cnt = 0; i < n; i += ch, cnt++) {
            d3 = d2;
            d2 = pdelta - d1;
            d1 = pdelta;
            /* unsigned arithmetic: only the low 8 bits after >> 3 matter */
            u32 pred = 8 * prev + (u32)(k1 * d1) + (u32)(k2 * d2) + (u32)(k3 * d3);
            pred = (pred >> 3) & 0xFF;
            u32 cur = *s++;
            pred = (pred - cur) & 0xFF;
            o[i] = (u8)pred;
            pdelta = (i8)(u8)(pred - prev);
            prev = pred;
            int dd = (i8)(u8)cur * 8;
            dif[0] += (u32)iabs(dd);
            dif[1] += (u32)iabs(dd - d1);
            dif[2] += (u32)iabs(dd + d1);
            dif[3] += (u32)iabs(dd - d2);
            dif[4] += (u32)iabs(dd + d2);
            dif[5] += (u32)iabs(dd - d3);
            dif[6] += (u32)iabs(dd + d3);
            if (!(cnt & 0x1F)) {
                u32 md = dif[0], nm = 0;
                dif[0] = 0;
                for (u32 j = 1; j < 7; j++) {
                    if (dif[j] < md) { md = dif[j]; nm = j; }
                    dif[j] = 0;
                }
                switch (nm) {
                case 1: if (k1 >= -16) k1--; break;
                case 2: if (k1 < 16) k1++; break;
                case 3: if (k2 >= -16) k2--; break;
                case 4: if (k2 < 16) k2++; break;
                case 5: if (k3 >= -16) k3--; break;
                case 6: if (k3 < 16) k3++; break;
                }
            }
        }
    }
}

/* Run filter f on d->vm[0..len): output pointer and size (unrar's limits). */
static int run_filter(gz_rar3_dec *d, const r3_flt *f, u64 file_off, u8 **out)
{
    u8 *m = d->vm;
    u32 n = f->len;
    *out = m;
    switch (f->type) {
    case F_E8:
    case F_E8E9:
        if (n > VM_MEM) return GZ_E_DATA;
        flt_e8(m, n, (u32)file_off, f->type == F_E8E9);
        return GZ_OK;
    case F_ITANIUM:
        if (n > VM_MEM) return GZ_E_DATA;
        flt_itanium(m, n, (u32)file_off);
        return GZ_OK;
    case F_DELTA:
        if (n > VM_MEM / 2 || !f->r0 || f->r0 > 1024) return GZ_E_DATA;
        flt_delta(m, m + n, n, f->r0);
        break;
    case F_RGB:
        if (n > VM_MEM / 2 || n < 3 || f->r0 <= 3 || f->r0 > n || f->r1 > 2) return GZ_E_DATA;
        flt_rgb(m, m + n, n, f->r0, f->r1);
        break;
    case F_AUDIO:
        if (n > VM_MEM / 2 || !f->r0 || f->r0 > 128) return GZ_E_DATA;
        flt_audio(m, m + n, n, f->r0);
        break;
    default:
        return GZ_E_METHOD;
    }
    *out = m + n;
    return GZ_OK;
}

static void compact_filters(gz_rar3_dec *d)
{
    u32 k = 0;
    for (u32 i = 0; i < d->nflt; i++)
        if (d->flt[i].live) d->flt[k++] = d->flt[i];
    d->nflt = k;
}

/* Write decoded data up to stream position `to`, applying filters. A filter
 * whose block is not complete yet holds back everything from its start. */
static int flush(gz_rar3_dec *d, u64 to)
{
    int r;
    u64 w = d->wr;
    for (u32 i = 0; i < d->nflt; i++) {
        r3_flt *f = &d->flt[i];
        if (!f->live) continue;
        if (f->start < w) { f->live = 0; continue; }     /* behind the output: never applies */
        if (f->start >= to) continue;                     /* not reached yet */
        if (f->start > w) {
            if ((r = emit_win(d, w, f->start))) return r;
            w = f->start;
        }
        if (f->start + f->len > to) break;                /* block not complete */
        /* filter input: a copy of the window data */
        size_t ix = (size_t)f->start & d->wmask, first = d->wsize - ix;
        if (first > f->len) first = f->len;
        __builtin_memcpy(d->vm, d->win + ix, first);
        if (f->len > first) __builtin_memcpy(d->vm + first, d->win, f->len - first);
        u8 *o;
        u32 on = f->len;
        f->live = 0;
        if ((r = run_filter(d, f, f->start - d->file_start, &o))) return r;
        /* filters stacked on the same block run on the previous output */
        while (i + 1 < d->nflt) {
            r3_flt *g = &d->flt[i + 1];
            if (!g->live || g->start != f->start || g->len != on) break;
            if (o != d->vm) __builtin_memmove(d->vm, o, on);
            g->live = 0;
            i++;
            if ((r = run_filter(d, g, f->start - d->file_start, &o))) return r;
        }
        if ((r = emit(d, o, on))) return r;
        w = f->start + f->len;
    }
    if (w < to) {
        int held = 0;
        for (u32 i = 0; i < d->nflt; i++)
            if (d->flt[i].live && d->flt[i].start >= w && d->flt[i].start < to) { held = 1; break; }
        if (!held) {
            if ((r = emit_win(d, w, to))) return r;
            w = to;
        }
    }
    d->wr = w;
    compact_filters(d);
    return GZ_OK;
}

/* ---------------- loop control ---------------- */

/* Account decoded bytes, flush, refill input (bits != 0) and set the loop
 * limits. GZ_OK: continue (single-step if still at a limit), R3_DONE (declared
 * size reached or a 1.5 / 2.0 stream of unknown size exhausted), or an error. */
static int sync(gz_rar3_dec *d, int bits)
{
    int r;
    const u64 w = d->wsize;
    advance(d);
    u64 done = d->pos - d->file_start;
    if (d->out_size != GZ_SIZE_UNKNOWN && done >= d->out_size) return R3_DONE;
    if (bits) {
        if ((r = need(d))) return r;
        u64 cur = bitpos(d), end = in_end_bits(d);
        if (cur > end) return GZ_E_DATA;
        if (d->in_eof && d->out_size == GZ_SIZE_UNKNOWN && d->alg != 29 && end - cur < 8) return R3_DONE;
    }
    u64 unfl = d->pos - d->wr;
    if (unfl >= d->thresh) {
        if ((r = flush(d, d->pos))) return r;
        unfl = d->pos - d->wr;
    }
    u64 room = unfl < d->thresh ? d->thresh - unfl : 0;
    if (!room) {
        /* a filter block holds back the output: use the rest of the window */
        u64 hard = w - 2 * MAXM;
        if (unfl >= hard) return GZ_E_DATA;
        room = hard - unfl;
    }
    if (d->out_size != GZ_SIZE_UNKNOWN && d->out_size - done < room) room = d->out_size - done;
    size_t wlim = (size_t)w - MAXM;
    if (d->wp >= wlim) {
        d->wp_stop = 0;
    } else {
        u64 n = wlim - d->wp;
        d->wp_stop = d->wp + (size_t)(n < room ? n : room);
    }
    u64 avail = d->in_base + (u64)(d->in_end - d->in);
    u64 lim = avail > 32 ? avail - 32 : 0;
    d->p_lim = lim > d->in_base ? d->in + (size_t)(lim - d->in_base) : d->in;
    return GZ_OK;
}

/* ================= RAR 2.9: tables, PPMd, VM code ================= */

static int ppm_start(gz_rar3_dec *d)
{
    gz_ppmd_in *in = &d->pin;
    in->cur = d->p - (d->bc >> 3);      /* byte aligned: unread bytes of the bit buffer */
    in->end = d->in_end;
    in->refill = ppm_refill;
    in->user = d;
    in->extra = 0;
    in->err = 0;
    d->bb = 0;
    d->bc = 0;
    d->ppm_mode = 1;
    if (!d->ppm && !(d->ppm = gz_ppmd7_new())) return GZ_E_NOMEM;
    u32 flags = gz_ppmd_in_byte(in), maxmb = 0;
    int reset = (flags & 0x20) != 0;
    if (reset) maxmb = gz_ppmd_in_byte(in);
    else if (!gz_ppmd7_rar_ready(d->ppm)) return GZ_E_DATA;
    if (flags & 0x40) d->esc = (int)gz_ppmd_in_byte(in);
    if (in->err) return in->err;
    if (in->extra) return GZ_E_DATA;
    int r = gz_ppmd7_rar_rc_init(d->ppm, in);
    if (r) return r == GZ_E_TRUNC ? GZ_E_DATA : r;
    if (reset) {
        u32 order = (flags & 0x1F) + 1;
        if (order > 16) order = 16 + (order - 16) * 3;
        if (order == 1) { gz_ppmd7_rar_drop(d->ppm); return GZ_E_DATA; }
        u32 mem = (maxmb + 1) << 20;
        d->ppm_mem = mem;
        if ((r = gz_ppmd7_rar_model(d->ppm, order, mem))) return r;
    }
    return GZ_OK;
}

/* ReadTables30: byte align, PPMd block header or LZ tables (delta coded). */
static int read_tables29(gz_rar3_dec *d)
{
    u8 bl[BC30], lens[T30];
    int r;
    d->bb <<= d->bc & 7;
    d->bc &= ~7u;
    if ((r = need(d))) return r;
    {
        LOADBITS();
        REFILL();
        u32 v = (u32)GETBITS(16);
        if (v & 0x8000) {
            SAVEBITS();
            return ppm_start(d);
        }
        d->ppm_mode = 0;
        d->prev_low = d->low_rep = 0;
        if (!(v & 0x4000)) __builtin_memset(d->old30, 0, T30);
        DROP(2);
        for (u32 i = 0; i < BC30;) {
            REFILL();
            u32 l = (u32)GETBITS(4);
            DROP(4);
            if (l == 15) {
                u32 z = (u32)GETBITS(4);
                DROP(4);
                if (!z) bl[i++] = 15;
                else for (z += 2; z-- && i < BC30;) bl[i++] = 0;
            } else {
                bl[i++] = (u8)l;
            }
        }
        SAVEBITS();
    }
    if (!huff_build(&d->tbd, bl, BC30, QB_BD)) return GZ_E_DATA;
    for (u32 i = 0; i < T30;) {
        if ((r = need(d))) return r;
        LOADBITS();
        REFILL();
        u32 s, n;
        DECODE(&d->tbd, QB_BD, s);
        if (s < 16) {
            lens[i] = (u8)((s + d->old30[i]) & 15);
            i++;
        } else {
            if (s & 1) { n = (u32)GETBITS(7) + 11; DROP(7); }
            else { n = (u32)GETBITS(3) + 3; DROP(3); }
            if (s < 18) {
                if (!i) goto bad;
                for (; n-- && i < T30; i++) lens[i] = lens[i - 1];
            } else {
                for (; n-- && i < T30; i++) lens[i] = 0;
            }
        }
        SAVEBITS();
        if (bitpos(d) > in_end_bits(d)) return GZ_E_DATA;
        continue;
    bad:
        return GZ_E_DATA;
    }
    d->tables30 = 1;
    if (!huff_build(&d->tmain, lens, NC30, QB_MAIN) ||
        !huff_build(&d->tdist, lens + NC30, DC30, QB_DIST) ||
        !huff_build(&d->tlow, lens + NC30 + DC30, LDC30, QB_LOW) ||
        !huff_build(&d->tlen, lens + NC30 + DC30 + LDC30, RC30, QB_LEN))
        return GZ_E_DATA;
    __builtin_memcpy(d->old30, lens, T30);
    return GZ_OK;
}

/* VM code bit reader (zero bytes past the end) */
typedef struct { const u8 *p; u32 n, bit; } vbits;

static u32 vb_byte(const vbits *v, u32 i) { return i < v->n ? v->p[i] : 0; }

static u32 vb16(const vbits *v)
{
    u32 i = v->bit >> 3;
    u32 x = vb_byte(v, i) << 16 | vb_byte(v, i + 1) << 8 | vb_byte(v, i + 2);
    return (x >> (8 - (v->bit & 7))) & 0xFFFF;
}

/* RarVM::ReadData: 4, 8 (or negative 8), 16 or 32-bit numbers */
static u32 vb_data(vbits *v)
{
    u32 x = vb16(v);
    switch (x & 0xC000) {
    case 0:
        v->bit += 6;
        return (x >> 10) & 0xF;
    case 0x4000:
        if (!(x & 0x3C00)) {
            v->bit += 14;
            return 0xFFFFFF00u | ((x >> 2) & 0xFF);
        }
        v->bit += 10;
        return (x >> 6) & 0xFF;
    case 0x8000:
        v->bit += 2;
        x = vb16(v);
        v->bit += 16;
        return x;
    default:
        v->bit += 2;
        x = vb16(v) << 16;
        v->bit += 16;
        x |= vb16(v);
        v->bit += 16;
        return x;
    }
}

static int grow_arr(void **p, u32 *cap, u32 need_n, size_t elem)
{
    if (need_n <= *cap) return GZ_OK;
    u32 nc = *cap ? *cap : 16;
    while (nc < need_n) nc *= 2;
    void *np = gz_realloc(*p, (size_t)nc * elem);
    if (!np) return GZ_E_NOMEM;
    *p = np;
    *cap = nc;
    return GZ_OK;
}

/* Unpack::AddVMCode: filter number, block start / length, registers, code. */
static int add_vm_code(gz_rar3_dec *d, u32 first, const u8 *code, u32 n)
{
    static const struct { u32 len, crc; } std[6] = {
        { 53, 0xAD576887u }, { 57, 0x3CD7E57Eu }, { 120, 0x3769893Fu },
        { 29, 0x0E06077Du }, { 149, 0x1C2C5DC8u }, { 216, 0xBC85E701u } };
    vbits v = { code, n, 0 };
    u32 fpos;
    int r;
    if (first & 0x80) {
        fpos = vb_data(&v);
        if (!fpos) {
            d->nfdef = 0;                  /* InitFilters30: forget every filter */
            d->nflt = 0;
            d->last_filter = 0;
        } else {
            fpos--;
        }
    } else {
        fpos = d->last_filter;
    }
    if (fpos > d->nfdef) return GZ_E_DATA;
    d->last_filter = fpos;
    int newf = fpos == d->nfdef;
    if (newf) {
        if (fpos > MAX_FILTERS) return GZ_E_DATA;
        if ((r = grow_arr((void **)&d->fdef, &d->capfdef, d->nfdef + 1, sizeof(r3_fdef)))) return r;
        d->fdef[d->nfdef].type = F_UNKNOWN;
        d->fdef[d->nfdef].len = 0;
        d->nfdef++;
    }
    if (d->nflt >= MAX_FILTERS) {
        compact_filters(d);
        if (d->nflt >= MAX_FILTERS) return GZ_E_DATA;
    }
    u32 bstart = vb_data(&v);
    if (first & 0x40) bstart += 258;
    u32 blen;
    if (first & 0x20) {
        blen = vb_data(&v);
        d->fdef[fpos].len = blen;
    } else {
        blen = d->fdef[fpos].len;
    }
    u32 reg[7] = { 0, 0, 0, 0, blen, 0, 0 };
    if (first & 0x10) {
        u32 mask = vb16(&v) >> 9;
        v.bit += 7;
        for (u32 i = 0; i < 7; i++)
            if (mask & (1u << i)) reg[i] = vb_data(&v);
    }
    if (newf) {
        u32 csz = vb_data(&v);
        if (csz >= 0x10000 || !csz || (v.bit >> 3) + csz > n) return GZ_E_DATA;
        /* the program is identified by its length and CRC32; its bytes must XOR to 0 */
        u8 buf[256];
        u32 crc = 0, k = 0, x = 0;
        for (u32 i = 0; i < csz; i++) {
            u8 b = (u8)(vb16(&v) >> 8);
            v.bit += 8;
            x ^= b;
            buf[k++] = b;
            if (k == sizeof buf) { crc = gz_crc32(crc, buf, k); k = 0; }
        }
        crc = gz_crc32(crc, buf, k);
        u32 type = x ? F_BADCODE : F_UNKNOWN;
        for (u32 i = 0; i < 6 && !x; i++)
            if (std[i].len == csz && std[i].crc == crc) type = F_E8 + i;
        d->fdef[fpos].type = type;
    }
    u32 type = d->fdef[fpos].type;
    if (type == F_UNKNOWN) return GZ_E_METHOD;
    if (type == F_BADCODE) return GZ_E_DATA;
    /* standard filters take their block size from R4 = block length */
    if (reg[4] != blen || blen > VM_MEM) return GZ_E_DATA;
    advance(d);
    if ((r = grow_arr((void **)&d->flt, &d->capflt, d->nflt + 1, sizeof(r3_flt)))) return r;
    r3_flt *f = &d->flt[d->nflt++];
    __builtin_memset(f, 0, sizeof *f);
    f->start = d->pos + bstart;
    f->len = blen;
    f->type = type;
    f->r0 = reg[0];
    f->r1 = reg[1];
    f->live = blen != 0;
    return GZ_OK;
}

static int vm_buffers(gz_rar3_dec *d)
{
    if (!d->vmcode && !(d->vmcode = (u8 *)gz_alloc(VMCODE_CAP))) return GZ_E_NOMEM;
    if (!d->vm && !(d->vm = (u8 *)gz_alloc(2 * VM_MEM + 8))) return GZ_E_NOMEM;
    return GZ_OK;
}

/* ReadVMCode: filter code in the LZ bit stream */
static int read_vm_lz(gz_rar3_dec *d)
{
    int r;
    if ((r = vm_buffers(d)) || (r = need(d))) return r;
    u32 first, len;
    {
        LOADBITS();
        REFILL();
        first = (u32)GETBITS(8);
        DROP(8);
        len = (first & 7) + 1;
        if (len == 7) {
            len = (u32)GETBITS(8) + 7;
            DROP(8);
        } else if (len == 8) {
            len = (u32)GETBITS(16);
            DROP(16);
        }
        SAVEBITS();
    }
    if (!len) return GZ_E_DATA;
    for (u32 i = 0; i < len; i++) {
        if ((r = need(d))) return r;
        LOADBITS();
        REFILL();
        d->vmcode[i] = (u8)GETBITS(8);
        DROP(8);
        SAVEBITS();
        if (bitpos(d) > in_end_bits(d)) return GZ_E_DATA;
    }
    return add_vm_code(d, first, d->vmcode, len);
}

/* one PPMd symbol, or -1 with *err set */
static int psym(gz_rar3_dec *d, int *err)
{
    int c = gz_ppmd7_rar_decode(d->ppm);
    if (d->pin.err) { *err = d->pin.err; return -1; }
    if (c < 0 || d->pin.extra > 2) { *err = GZ_E_DATA; return -1; }
    return c;
}

static int read_vm_ppm(gz_rar3_dec *d)
{
    int r, e = GZ_OK;
    if ((r = vm_buffers(d))) return r;
    int first = psym(d, &e);
    if (first < 0) return e;
    u32 len = ((u32)first & 7) + 1;
    if (len == 7) {
        int b = psym(d, &e);
        if (b < 0) return e;
        len = (u32)b + 7;
    } else if (len == 8) {
        int b1 = psym(d, &e), b2 = b1 < 0 ? -1 : psym(d, &e);
        if (b2 < 0) return e;
        len = (u32)b1 * 256 + (u32)b2;
    }
    if (!len) return GZ_E_DATA;
    for (u32 i = 0; i < len; i++) {
        int c = psym(d, &e);
        if (c < 0) return e;
        d->vmcode[i] = (u8)c;
    }
    return add_vm_code(d, (u32)first, d->vmcode, len);
}

/* PPMd block: symbols until the end of the block (R3_SWITCH to LZ), the end
 * of the file (R3_EOF) or the declared size (R3_DONE). */
static int ppm29(gz_rar3_dec *d)
{
    int r, e = GZ_OK;
    for (;;) {
        if (d->wp >= d->wp_stop && (r = sync(d, 0))) return r;
        int c = psym(d, &e);
        if (c < 0) return e;
        if (c == d->esc) {
            int n = psym(d, &e);
            if (n < 0) return e;
            if (n == 0) {
                /* end of the PPMd block: tables of the next block follow */
                d->p = d->pin.cur;
                d->bb = 0;
                d->bc = 0;
                if ((r = read_tables29(d))) return r;
                if (!d->ppm_mode) return R3_SWITCH;
                continue;
            }
            if (n == 2) return R3_EOF;
            if (n == 3) {
                if ((r = read_vm_ppm(d))) return r;
                continue;
            }
            if (n == 4) {
                u32 dist = 0;
                for (int k = 0; k < 3; k++) {
                    int b = psym(d, &e);
                    if (b < 0) return e;
                    dist = dist << 8 | (u32)b;
                }
                int l = psym(d, &e);
                if (l < 0) return e;
                if ((r = copy(d, (u32)l + 32, dist + 2))) return r;
                continue;
            }
            if (n == 5) {
                int l = psym(d, &e);
                if (l < 0) return e;
                if ((r = copy(d, (u32)l + 4, 1))) return r;
                continue;
            }
            /* 1 (and unknown codes): the escape byte itself */
        }
        d->win[d->wp] = (u8)c;
        d->wp = (d->wp + 1) & d->wmask;
    }
}

/* ReadEndOfBlock: "1" new tables here, "00" new file, "01" new file + new tables */
static int end_of_block(gz_rar3_dec *d)
{
    int r;
    if ((r = need(d))) return r;
    LOADBITS();
    REFILL();
    if (GETBITS(1)) {
        DROP(1);
        SAVEBITS();
        d->tables30 = 0;
        if ((r = read_tables29(d))) return r;
        return d->ppm_mode ? R3_SWITCH : GZ_OK;
    }
    u32 nt = (u32)GETBITS(2) & 1;
    DROP(2);
    SAVEBITS();
    d->tables30 = !nt;
    return R3_EOF;
}

/* ================= RAR 2.9 LZ loop ================= */

#define LZ29_SAVE() do { \
        SAVEBITS(); d->wp = wp; d->last_len = lastlen; \
        d->rep[0] = r0; d->rep[1] = r1; d->rep[2] = r2; d->rep[3] = r3; \
        d->prev_low = prev_low; d->low_rep = low_rep; \
    } while (0)
#define LZ29_LOAD() do { \
        p = d->p; bb = d->bb; bc = d->bc; \
        prev_low = d->prev_low; low_rep = d->low_rep; \
    } while (0)

static int lz29(gz_rar3_dec *d)
{
    u8 *const win = d->win;
    const size_t mask = d->wmask, wsize = d->wsize;
    const huff *const tm = &d->tmain, *const td = &d->tdist, *const tl = &d->tlow, *const tr = &d->tlen;
    size_t wp = d->wp;
    LOADBITS();
    u32 r0 = d->rep[0], r1 = d->rep[1], r2 = d->rep[2], r3 = d->rep[3];
    u32 lastlen = d->last_len, prev_low = d->prev_low, low_rep = d->low_rep;
    const u8 *p_lim = p;
    size_t wp_stop = 0, wfull = 0;
    int r;
    for (;;) {
        if (GZ_UNLIKELY(p >= p_lim || wp >= wp_stop)) {
            LZ29_SAVE();
            if ((r = sync(d, 1))) return r;
            p = d->p;
            bb = d->bb;
            bc = d->bc;
            p_lim = d->p_lim;
            wp_stop = d->wp_stop;
            wfull = d->full ? wsize : 0;
        }
        REFILL();
        u32 sym, len, dist;
        DECODE(tm, QB_MAIN, sym);
        if (sym < 256) {
            win[wp] = (u8)sym;
            wp = (wp + 1) & mask;
            continue;
        }
        if (sym >= 271) {
            u32 s = sym - 271;
            len = ldec[s] + 3u + (u32)GETBITS(lbits[s]);
            DROP(lbits[s]);
            REFILL();
            u32 ds;
            DECODE(td, QB_DIST, ds);
            u32 nb = dbits[ds];
            dist = ddec[ds] + 1;
            if (ds > 9) {
                if (nb > 4) {
                    dist += (u32)GETBITS(nb - 4) << 4;
                    DROP(nb - 4);
                }
                if (low_rep) {
                    low_rep--;
                    dist += prev_low;
                } else {
                    if (bc < 16) REFILL();
                    u32 lo;
                    DECODE(tl, QB_LOW, lo);
                    if (lo == 16) {
                        low_rep = 15;
                        dist += prev_low;
                    } else {
                        dist += lo;
                        prev_low = lo;
                    }
                }
            } else {
                dist += (u32)GETBITS(nb);
                DROP(nb);
            }
            if (dist >= 0x2000) {
                len++;
                if (dist >= 0x40000) len++;
            }
            r3 = r2;
            r2 = r1;
            r1 = r0;
            r0 = dist;
        } else if (sym == 256) {
            LZ29_SAVE();
            if ((r = end_of_block(d))) return r;
            LZ29_LOAD();
            continue;
        } else if (sym == 257) {
            LZ29_SAVE();
            if ((r = read_vm_lz(d))) return r;
            LZ29_LOAD();
            continue;
        } else if (sym == 258) {
            if (!lastlen) continue;
            len = lastlen;
            dist = r0;
        } else if (sym < 263) {
            /* repeated distance k moves to the front */
            if (sym == 259) {
                dist = r0;
            } else if (sym == 260) {
                dist = r1; r1 = r0;
            } else if (sym == 261) {
                dist = r2; r2 = r1; r1 = r0;
            } else {
                dist = r3; r3 = r2; r2 = r1; r1 = r0;
            }
            r0 = dist;
            u32 ls;
            DECODE(tr, QB_LEN, ls);
            len = ldec[ls] + 2u + (u32)GETBITS(lbits[ls]);
            DROP(lbits[ls]);
        } else {
            u32 s = sym - 263;
            dist = sddec[s] + 1u + (u32)GETBITS(sdbits[s]);
            DROP(sdbits[s]);
            len = 2;
            r3 = r2;
            r2 = r1;
            r1 = r0;
            r0 = dist;
        }
        lastlen = len;
        if (GZ_UNLIKELY((size_t)dist - 1 >= wp && (size_t)dist - 1 >= wfull)) goto bad;
        lzcopy(win, &wp, mask, wsize, len, dist);
    }
bad:
    LZ29_SAVE();
    return GZ_E_DATA;
}

/* After the declared size: consume the end-of-file marker so that a solid
 * continuation starts with unrar's state. Returns 1 if the state is unusable. */
static int trailer29(gz_rar3_dec *d)
{
    int e = GZ_OK;
    for (int k = 0; k < 4; k++) {
        if (d->ppm_mode) {
            int c = psym(d, &e);
            if (c < 0) return e == GZ_E_CANCEL ? -1 : 1;
            if (c != d->esc) return 1;
            c = psym(d, &e);
            if (c == 2) return 0;
            if (c != 0) return 1;
            d->p = d->pin.cur;
            d->bb = 0;
            d->bc = 0;
            if (read_tables29(d)) return 1;
            continue;
        }
        if (need(d)) return 1;
        if (bitpos(d) >= in_end_bits(d)) return 0;                /* no marker */
        LOADBITS();
        REFILL();
        u32 sym;
        DECODE(&d->tmain, QB_MAIN, sym);
        if (sym != 256) return 0;
        if (GETBITS(1)) {
            DROP(1);
            SAVEBITS();
            d->tables30 = 0;
            if (read_tables29(d)) return 1;
            continue;
        }
        u32 nt = (u32)GETBITS(2) & 1;
        DROP(2);
        SAVEBITS();
        if (bitpos(d) <= in_end_bits(d)) d->tables30 = !nt;
        return 0;
    bad:
        return 0;
    }
    return 0;
}

static int decode29(gz_rar3_dec *d, int solid)
{
    int r;
    if (!solid) {
        __builtin_memset(d->rep, 0, sizeof d->rep);
        d->last_len = d->last_dist = 0;
        d->tables30 = 0;
        d->ppm_mode = 0;
        d->esc = 2;
        d->prev_low = d->low_rep = 0;
        __builtin_memset(d->old30, 0, T30);
        if (d->ppm) gz_ppmd7_rar_drop(d->ppm);
        d->nfdef = 0;
        d->last_filter = 0;
    }
    d->nflt = 0;
    /* an empty file without packed data leaves the state alone; with data
     * (tables, end marker) it is decoded like any other for a solid successor */
    if ((r = sync(d, 1)) && (r != R3_DONE || !in_end_bits(d))) return r == R3_DONE ? GZ_OK : r;
    if (!solid || !d->tables30) {
        if ((r = read_tables29(d))) return r;
    } else if (d->ppm_mode) {
        d->pin.cur = d->p;
        d->pin.end = d->in_end;
        d->pin.extra = 0;
        d->pin.err = 0;
    }
    for (;;) {
        r = d->ppm_mode ? ppm29(d) : lz29(d);
        if (r != R3_SWITCH) break;
    }
    if (r == R3_DONE) {
        int t = trailer29(d);
        if (t < 0) return GZ_E_CANCEL;
        return t ? R3_SWITCH : GZ_OK;        /* R3_SWITCH: data fine, state not */
    }
    return r == R3_EOF ? GZ_OK : r;
}

/* ================= RAR 2.0 ================= */

static int read_tables20(gz_rar3_dec *d)
{
    u8 bl[BC20], lens[T20];
    u32 n;
    int r;
    if ((r = need(d))) return r;
    {
        LOADBITS();
        REFILL();
        u32 v = (u32)GETBITS(16);
        d->audio = (v & 0x8000) != 0;
        if (!(v & 0x4000)) __builtin_memset(d->old20, 0, T20);
        DROP(2);
        if (d->audio) {
            d->channels = ((v >> 12) & 3) + 1;
            if (d->cur_channel >= d->channels) d->cur_channel = 0;
            DROP(2);
            n = MC20 * d->channels;
        } else {
            n = NC20 + DC20 + RC20;
        }
        for (u32 i = 0; i < BC20; i++) {
            REFILL();
            bl[i] = (u8)GETBITS(4);
            DROP(4);
        }
        SAVEBITS();
    }
    if (!huff_build(&d->tbd, bl, BC20, QB_BD)) return GZ_E_DATA;
    for (u32 i = 0; i < n;) {
        if ((r = need(d))) return r;
        LOADBITS();
        REFILL();
        u32 s, c;
        DECODE(&d->tbd, QB_BD, s);
        if (s < 16) {
            lens[i] = (u8)((s + d->old20[i]) & 15);
            i++;
        } else if (s == 16) {
            c = (u32)GETBITS(2) + 3;
            DROP(2);
            if (!i) goto bad;
            for (; c-- && i < n; i++) lens[i] = lens[i - 1];
        } else {
            if (s == 17) { c = (u32)GETBITS(3) + 3; DROP(3); }
            else { c = (u32)GETBITS(7) + 11; DROP(7); }
            for (; c-- && i < n; i++) lens[i] = 0;
        }
        SAVEBITS();
        if (bitpos(d) > in_end_bits(d)) return GZ_E_DATA;
        continue;
    bad:
        return GZ_E_DATA;
    }
    d->tables20 = 1;
    if (d->audio) {
        for (u32 i = 0; i < d->channels; i++)
            if (!huff_build(&d->md[i], lens + i * MC20, MC20, QB_MAIN)) return GZ_E_DATA;
    } else if (!huff_build(&d->tmain, lens, NC20, QB_MAIN) ||
               !huff_build(&d->tdist, lens + NC20, DC20, QB_DIST) ||
               !huff_build(&d->tlen, lens + NC20 + DC20, RC20, QB_LEN)) {
        return GZ_E_DATA;
    }
    __builtin_memcpy(d->old20, lens, n);
    return GZ_OK;
}

/* Unpack::DecodeAudio */
static u8 audio_byte(gz_rar3_dec *d, u32 delta)
{
    r3_audio *v = &d->aud[d->cur_channel];
    v->count++;
    v->d[3] = v->d[2];
    v->d[2] = v->d[1];
    v->d[1] = v->last_delta - v->d[0];
    v->d[0] = v->last_delta;
    /* unsigned arithmetic: only the low 8 bits after >> 3 matter */
    u32 pch = 8 * v->last_char + (u32)(v->k[0] * v->d[0]) + (u32)(v->k[1] * v->d[1]) +
              (u32)(v->k[2] * v->d[2]) + (u32)(v->k[3] * v->d[3]) + (u32)(v->k[4] * d->channel_delta);
    pch = (pch >> 3) & 0xFF;
    u32 ch = (pch - delta) & 0xFF;
    int dd = (i8)(u8)delta * 8;
    int t[5] = { v->d[0], v->d[1], v->d[2], v->d[3], d->channel_delta };
    v->dif[0] += (u32)iabs(dd);
    for (u32 i = 0; i < 5; i++) {
        v->dif[1 + 2 * i] += (u32)iabs(dd - t[i]);
        v->dif[2 + 2 * i] += (u32)iabs(dd + t[i]);
    }
    d->channel_delta = v->last_delta = (i8)(u8)(ch - v->last_char);
    v->last_char = ch;
    if (!(v->count & 0x1F)) {
        u32 md = v->dif[0], nm = 0;
        v->dif[0] = 0;
        for (u32 i = 1; i < 11; i++) {
            if (v->dif[i] < md) { md = v->dif[i]; nm = i; }
            v->dif[i] = 0;
        }
        if (nm) {
            int *k = &v->k[(nm - 1) >> 1];
            if (nm & 1) { if (*k >= -16) (*k)--; }
            else if (*k < 16) (*k)++;
        }
    }
    return (u8)ch;
}

static int lz20(gz_rar3_dec *d)
{
    u8 *const win = d->win;
    const size_t mask = d->wmask, wsize = d->wsize;
    size_t wp = d->wp;
    LOADBITS();
    const u8 *p_lim = p;
    size_t wp_stop = 0, wfull = 0;
    int r;
    for (;;) {
        if (GZ_UNLIKELY(p >= p_lim || wp >= wp_stop)) {
            SAVEBITS();
            d->wp = wp;
            if ((r = sync(d, 1))) return r;
            p = d->p;
            bb = d->bb;
            bc = d->bc;
            p_lim = d->p_lim;
            wp_stop = d->wp_stop;
            wfull = d->full ? wsize : 0;
        }
        REFILL();
        u32 sym, len, dist;
        if (d->audio) {
            DECODE(&d->md[d->cur_channel], QB_MAIN, sym);
            if (sym == 256) {
                SAVEBITS();
                d->wp = wp;
                if ((r = read_tables20(d))) return r;
                p = d->p;
                bb = d->bb;
                bc = d->bc;
                continue;
            }
            win[wp] = audio_byte(d, sym);
            wp = (wp + 1) & mask;
            if (++d->cur_channel == d->channels) d->cur_channel = 0;
            continue;
        }
        DECODE(&d->tmain, QB_MAIN, sym);
        if (sym < 256) {
            win[wp] = (u8)sym;
            wp = (wp + 1) & mask;
            continue;
        }
        if (sym > 269) {
            u32 s = sym - 270;
            len = ldec[s] + 3u + (u32)GETBITS(lbits[s]);
            DROP(lbits[s]);
            REFILL();
            u32 ds;
            DECODE(&d->tdist, QB_DIST, ds);
            dist = ddec[ds] + 1u + (u32)GETBITS(dbits[ds]);
            DROP(dbits[ds]);
            if (dist >= 0x2000) {
                len++;
                if (dist >= 0x40000) len++;
            }
        } else if (sym == 269) {
            SAVEBITS();
            d->wp = wp;
            if ((r = read_tables20(d))) return r;
            p = d->p;
            bb = d->bb;
            bc = d->bc;
            continue;
        } else if (sym == 256) {
            len = d->last_len;
            dist = d->last_dist;
        } else if (sym < 261) {
            dist = d->rep[(d->rep_ptr - (sym - 256)) & 3];
            u32 ls;
            DECODE(&d->tlen, QB_LEN, ls);
            len = ldec[ls] + 2u + (u32)GETBITS(lbits[ls]);
            DROP(lbits[ls]);
            if (dist >= 0x101) {
                len++;
                if (dist >= 0x2000) {
                    len++;
                    if (dist >= 0x40000) len++;
                }
            }
        } else {
            u32 s = sym - 261;
            dist = sddec[s] + 1u + (u32)GETBITS(sdbits[s]);
            DROP(sdbits[s]);
            len = 2;
        }
        d->last_dist = d->rep[d->rep_ptr++ & 3] = dist;
        d->last_len = len;
        if (!len) continue;
        if (GZ_UNLIKELY((size_t)dist - 1 >= wp && (size_t)dist - 1 >= wfull)) goto bad;
        lzcopy(win, &wp, mask, wsize, len, dist);
    }
bad:
    SAVEBITS();
    d->wp = wp;
    return GZ_E_DATA;
}

/* ReadLastTables: a table switch right after the last symbol of a file
 * belongs to the next file of a solid archive. */
static int last_tables20(gz_rar3_dec *d)
{
    int r;
    if ((r = need(d))) return r;
    u64 cur = bitpos(d), end = in_end_bits(d);
    if (cur > end || (end >> 3) - (cur >> 3) < 5) return GZ_OK;
    LOADBITS();
    REFILL();
    u32 sym;
    if (d->audio) {
        DECODE(&d->md[d->cur_channel], QB_MAIN, sym);
        if (sym != 256) return GZ_OK;
    } else {
        DECODE(&d->tmain, QB_MAIN, sym);
        if (sym != 269) return GZ_OK;
    }
    SAVEBITS();
    r = read_tables20(d);
    return r == GZ_E_CANCEL || r == GZ_E_NOMEM || r == GZ_E_IO ? r : (r ? R3_SWITCH : GZ_OK);
bad:
    return GZ_OK;
}

static int decode20(gz_rar3_dec *d, int solid)
{
    int r;
    if (!solid) {
        __builtin_memset(d->rep, 0, sizeof d->rep);
        d->rep_ptr = d->last_len = d->last_dist = 0;
        d->tables20 = 0;
        d->audio = 0;
        d->channel_delta = 0;
        d->cur_channel = 0;
        d->channels = 1;
        __builtin_memset(d->aud, 0, sizeof d->aud);
        __builtin_memset(d->old20, 0, T20);
    }
    if ((r = sync(d, 1)) && (r != R3_DONE || !in_end_bits(d))) return r == R3_DONE ? GZ_OK : r;
    if ((!solid || !d->tables20) && (r = read_tables20(d))) return r;
    r = lz20(d);
    if (r != R3_DONE) return r;
    return last_tables20(d);
}

/* ================= RAR 1.5 ================= */

static const u16 dl1[] = { 0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf200, 0xffff };
static const u16 pl1[] = { 0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32 };
static const u16 dl2[] = { 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf240, 0xffff };
static const u16 pl2[] = { 0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36 };
static const u16 dh0[] = { 0x8000, 0xc000, 0xe000, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xffff };
static const u16 ph0[] = { 0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33 };
static const u16 dh1[] = { 0x2000, 0xc000, 0xe000, 0xf000, 0xf200, 0xf200, 0xf7e0, 0xffff };
static const u16 ph1[] = { 0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127 };
static const u16 dh2[] = { 0x1000, 0x2400, 0x8000, 0xc000, 0xfa00, 0xffff, 0xffff, 0xffff };
static const u16 ph2[] = { 0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0 };
static const u16 dh3[] = { 0x800, 0x2400, 0xee00, 0xfe80, 0xffff, 0xffff, 0xffff };
static const u16 ph3[] = { 0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0 };
static const u16 dh4[] = { 0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff };
static const u16 ph4[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0 };

/* Unpack::DecodeNum: static Huffman-like code from a 16-bit peek */
static u32 decode_num(gz_rar3_dec *d, u32 num, u32 start, const u16 *dec, const u16 *pos)
{
    u32 i = 0;
    for (num &= 0xFFF0; dec[i] <= num; i++) start++;
    fadd(d, start);
    return ((num - (i ? dec[i - 1] : 0)) >> (16 - start)) + pos[start];
}

static void corr_huff(u16 *cs, u8 *ntp)
{
    for (int i = 7; i >= 0; i--)
        for (int j = 0; j < 32; j++, cs++) *cs = (u16)((*cs & ~0xFF) | i);
    __builtin_memset(ntp, 0, 256);
    for (int i = 6; i >= 0; i--) ntp[i] = (u8)((7 - i) * 32);
}

static void init_huff15(gz_rar3_dec *d)
{
    for (u32 i = 0; i < 256; i++) {
        d->chset[i] = d->chsetb[i] = (u16)(i << 8);
        d->chseta[i] = (u16)i;
        d->chsetc[i] = (u16)(((~i + 1) & 0xFF) << 8);
    }
    __builtin_memset(d->ntopl, 0, 256);
    __builtin_memset(d->ntoplb, 0, 256);
    __builtin_memset(d->ntoplc, 0, 256);
    corr_huff(d->chsetb, d->ntoplb);
}

static void get_flags15(gz_rar3_dec *d)
{
    u32 fp = decode_num(d, fget(d), 5, dh2, ph2);
    if (fp >= 256) return;
    for (;;) {
        u32 fl = d->chsetc[fp];
        d->flag_buf = fl >> 8;
        u32 np = d->ntoplc[fl++ & 0xFF]++;
        if (fl & 0xFF) {
            d->chsetc[fp] = d->chsetc[np];
            d->chsetc[np] = (u16)fl;
            return;
        }
        corr_huff(d->chsetc, d->ntoplc);
    }
}

static void push_dist15(gz_rar3_dec *d, u32 len, u32 dist)
{
    d->rep[d->rep_ptr & 3] = dist;
    d->rep_ptr = (d->rep_ptr + 1) & 3;
    d->last_len = len;
    d->last_dist = dist;
}

static int huff15(gz_rar3_dec *d)
{
    u32 bf = fget(d);
    int bp;
    if (d->avr_plc > 0x75ff) bp = (int)decode_num(d, bf, 8, dh4, ph4);
    else if (d->avr_plc > 0x5dff) bp = (int)decode_num(d, bf, 6, dh3, ph3);
    else if (d->avr_plc > 0x35ff) bp = (int)decode_num(d, bf, 5, dh2, ph2);
    else if (d->avr_plc > 0x0dff) bp = (int)decode_num(d, bf, 5, dh1, ph1);
    else bp = (int)decode_num(d, bf, 4, dh0, ph0);
    bp &= 0xFF;
    if (d->st_mode) {
        if (bp == 0 && bf > 0xFFF) bp = 0x100;
        if (--bp == -1) {
            bf = fget(d);
            fadd(d, 1);
            if (bf & 0x8000) {
                d->num_huf = 0;
                d->st_mode = 0;
                return GZ_OK;
            }
            u32 len = (bf & 0x4000) ? 4 : 3;
            fadd(d, 1);
            u32 dist = decode_num(d, fget(d), 5, dh2, ph2);
            dist = (dist << 5) | (fget(d) >> 11);
            fadd(d, 5);
            return copy(d, len, dist);
        }
    } else if (d->num_huf++ >= 16 && d->flags_cnt == 0) {
        d->st_mode = 1;
    }
    d->avr_plc += (u32)bp;
    d->avr_plc -= d->avr_plc >> 8;
    d->nhfb += 16;
    if (d->nhfb > 0xff) {
        d->nhfb = 0x90;
        d->nlzb >>= 1;
    }
    d->win[d->wp] = (u8)(d->chset[bp] >> 8);
    d->wp = (d->wp + 1) & d->wmask;
    for (;;) {
        u32 cur = d->chset[bp];
        u32 np = d->ntopl[cur++ & 0xFF]++;
        if ((cur & 0xFF) > 0xA1) {
            corr_huff(d->chset, d->ntopl);
        } else {
            d->chset[bp] = d->chset[np];
            d->chset[np] = (u16)cur;
            return GZ_OK;
        }
    }
}

static int longlz15(gz_rar3_dec *d)
{
    u32 len, dist, dp, ndp, old2, old3;
    d->num_huf = 0;
    d->nlzb += 16;
    if (d->nlzb > 0xff) {
        d->nlzb = 0x90;
        d->nhfb >>= 1;
    }
    old2 = d->avr_ln2;
    u32 bf = fget(d);
    if (d->avr_ln2 >= 122) {
        len = decode_num(d, bf, 3, dl2, pl2);
    } else if (d->avr_ln2 >= 64) {
        len = decode_num(d, bf, 2, dl1, pl1);
    } else if (bf < 0x100) {
        len = bf;
        fadd(d, 16);
    } else {
        for (len = 0; !((bf << len) & 0x8000); len++) {}
        fadd(d, len + 1);
    }
    d->avr_ln2 += len;
    d->avr_ln2 -= d->avr_ln2 >> 5;
    bf = fget(d);
    if (d->avr_plcb > 0x28ff) dp = decode_num(d, bf, 5, dh2, ph2);
    else if (d->avr_plcb > 0x6ff) dp = decode_num(d, bf, 5, dh1, ph1);
    else dp = decode_num(d, bf, 4, dh0, ph0);
    d->avr_plcb += dp;
    d->avr_plcb -= d->avr_plcb >> 8;
    for (;;) {
        dist = d->chsetb[dp & 0xFF];
        ndp = d->ntoplb[dist++ & 0xFF]++;
        if (dist & 0xFF) break;
        corr_huff(d->chsetb, d->ntoplb);
    }
    d->chsetb[dp & 0xFF] = d->chsetb[ndp];
    d->chsetb[ndp] = (u16)dist;
    dist = ((dist & 0xFF00) | (fget(d) >> 8)) >> 1;
    fadd(d, 7);
    old3 = d->avr_ln3;
    if (len != 1 && len != 4) {
        if (len == 0 && dist <= d->max_dist3) {
            d->avr_ln3++;
            d->avr_ln3 -= d->avr_ln3 >> 8;
        } else if (d->avr_ln3 > 0) {
            d->avr_ln3--;
        }
    }
    len += 3;
    if (dist >= d->max_dist3) len++;
    if (dist <= 256) len += 8;
    d->max_dist3 = (old3 > 0xb0 || (d->avr_plc >= 0x2a00 && old2 < 0x40)) ? 0x7f00 : 0x2001;
    push_dist15(d, len, dist);
    return copy(d, len, dist);
}

static int shortlz15(gz_rar3_dec *d)
{
    /* the 16th entry is a catch-all sentinel (codes are complete without it) */
    static const u8 sl1[16] = { 1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0 };
    static const u8 sx1[16] = { 0, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0, 0 };
    static const u8 sl2[16] = { 2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0 };
    static const u8 sx2[16] = { 0, 0x40, 0x60, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0, 0 };
    u32 len, dist, l = 0;
    d->num_huf = 0;
    u32 bf = fget(d);
    if (d->lcount == 2) {
        fadd(d, 1);
        if (bf >= 0x8000) return copy(d, d->last_len, d->last_dist);
        bf <<= 1;
        d->lcount = 0;
    }
    bf = (bf >> 8) & 0xFF;
    if (d->avr_ln1 < 37) {
        for (len = 0; len < 16; len++) {
            l = len == 1 ? d->buf60 + 3 : sl1[len];
            if (!((bf ^ sx1[len]) & ~(0xFFu >> l) & 0xFF)) break;
        }
    } else {
        for (len = 0; len < 16; len++) {
            l = len == 3 ? d->buf60 + 3 : sl2[len];
            if (!((bf ^ sx2[len]) & ~(0xFFu >> l) & 0xFF)) break;
        }
    }
    fadd(d, l);
    if (len >= 9) {
        if (len == 9) {
            d->lcount++;
            return copy(d, d->last_len, d->last_dist);
        }
        if (len == 14) {
            d->lcount = 0;
            len = decode_num(d, fget(d), 3, dl2, pl2) + 5;
            dist = (fget(d) >> 1) | 0x8000;
            fadd(d, 15);
            d->last_len = len;
            d->last_dist = dist;
            return copy(d, len, dist);
        }
        d->lcount = 0;
        u32 save = len;
        dist = d->rep[(d->rep_ptr - (len - 9)) & 3];
        len = decode_num(d, fget(d), 2, dl1, pl1) + 2;
        if (len == 0x101 && save == 10) {
            d->buf60 ^= 1;
            return GZ_OK;
        }
        if (dist > 256) len++;
        if (dist >= d->max_dist3) len++;
        push_dist15(d, len, dist);
        return copy(d, len, dist);
    }
    d->lcount = 0;
    d->avr_ln1 += len;
    d->avr_ln1 -= d->avr_ln1 >> 4;
    int dp = (int)(decode_num(d, fget(d), 5, dh2, ph2) & 0xFF);
    dist = d->chseta[dp];
    if (--dp != -1) {
        d->chseta[dp + 1] = d->chseta[dp];
        d->chseta[dp] = (u16)dist;
    }
    len += 2;
    push_dist15(d, len, ++dist);
    return copy(d, len, dist);
}

static int decode15(gz_rar3_dec *d, int solid)
{
    int r;
    if (!solid) {
        __builtin_memset(d->rep, 0, sizeof d->rep);
        d->rep_ptr = d->last_len = d->last_dist = 0;
        d->avr_plcb = d->avr_ln1 = d->avr_ln2 = d->avr_ln3 = d->num_huf = d->buf60 = 0;
        d->avr_plc = 0x3500;
        d->max_dist3 = 0x2001;
        d->nhfb = d->nlzb = 0x80;
        init_huff15(d);
    }
    d->flags_cnt = 0;
    d->flag_buf = 0;
    d->st_mode = 0;
    d->lcount = 0;
    if ((r = sync(d, 1))) return r == R3_DONE ? GZ_OK : r;
    get_flags15(d);
    d->flags_cnt = 8;
    for (;;) {
        if (d->p >= d->p_lim || d->wp >= d->wp_stop) {
            if ((r = sync(d, 1))) return r == R3_DONE ? GZ_OK : r;
        }
        if (d->st_mode) {
            r = huff15(d);
        } else {
            if (--d->flags_cnt < 0) {
                get_flags15(d);
                d->flags_cnt = 7;
            }
            if (d->flag_buf & 0x80) {
                d->flag_buf <<= 1;
                r = d->nlzb > d->nhfb ? longlz15(d) : huff15(d);
            } else {
                d->flag_buf <<= 1;
                if (--d->flags_cnt < 0) {
                    get_flags15(d);
                    d->flags_cnt = 7;
                }
                if (d->flag_buf & 0x80) {
                    d->flag_buf <<= 1;
                    r = d->nlzb > d->nhfb ? huff15(d) : longlz15(d);
                } else {
                    d->flag_buf <<= 1;
                    r = shortlz15(d);
                }
            }
        }
        if (r) return r;
    }
}

/* ================= public API ================= */

gz_rar3_dec *gz_rar3_dec_new(void)
{
    return (gz_rar3_dec *)gz_alloc(sizeof(gz_rar3_dec));
}

void gz_rar3_dec_trim(gz_rar3_dec *d, u64 keep)
{
    if (!d) return;
    if (d->win && d->wsize > keep) {
        gz_free_big(d->win, d->wsize);
        d->win = 0;
        d->wsize = d->wmask = 0;
        d->state_ok = 0;
    }
    if (d->ppm && (d->ppm_mem > keep || !keep)) {
        gz_ppmd7_free(d->ppm);
        d->ppm = 0;
        d->ppm_mem = 0;
        d->state_ok = 0;
    }
    if (!keep) {
        gz_free(d->vm);
        gz_free(d->vmcode);
        d->vm = d->vmcode = 0;
    }
}

void gz_rar3_dec_free(gz_rar3_dec *d)
{
    if (!d) return;
    gz_rar3_dec_trim(d, 0);
    gz_free(d->in);
    gz_free(d->fdef);
    gz_free(d->flt);
    gz_free(d);
}

u64 gz_rar3_window_size(u64 dict, u64 total)
{
    u64 w = dict;
    if (total < w) w = total;
    if (w <= MIN_WIN) return MIN_WIN;
    if (w > ((u64)1 << 62)) return (u64)1 << 63;
    u64 p = MIN_WIN;
    while (p < w) p <<= 1;
    return p;
}

/* Solid stream with a larger window: move the history to its new places. */
static int grow(gz_rar3_dec *d, size_t nw)
{
    u8 *n = (u8 *)gz_alloc_big(nw);
    if (!n) return GZ_E_NOMEM;
    const size_t om = d->wmask, nm = nw - 1;
    u64 keep = d->pos < d->wsize ? d->pos : d->wsize, from = d->pos - keep;
    while (from < d->pos) {
        size_t oi = (size_t)from & om, ni = (size_t)from & nm;
        u64 c = d->pos - from;
        if (c > d->wsize - oi) c = d->wsize - oi;
        if (c > nw - ni) c = nw - ni;
        __builtin_memcpy(n + ni, d->win + oi, (size_t)c);
        from += c;
    }
    gz_free_big(d->win, d->wsize);
    d->win = n;
    d->wsize = nw;
    d->wmask = nm;
    d->wp = d->wp_sync = (size_t)d->pos & nm;
    d->full = d->pos >= nw;
    return GZ_OK;
}

int gz_rar3_decode(gz_rar3_dec *d, const gz_stream_io *io, u64 out_size, const gz_rar3_params *pp)
{
    int r, alg;
    u32 v = pp->version;
    if (v <= 15) alg = 15;
    else if (v == 20 || v == 26) alg = 20;
    else if (v == 29 || v == 36) alg = 29;
    else return GZ_E_METHOD;
    u64 w = pp->window;
    if (w < MIN_WIN || (w & (w - 1)) || w > ((u64)1 << 30)) return GZ_E_LIMIT;
    if (!d->in) {
        d->in = (u8 *)gz_alloc(IN_CAP + IN_PAD);
        if (!d->in) return GZ_E_NOMEM;
    }
    if (pp->solid) {
        if (!d->state_ok || !d->win) return GZ_E_DATA;
        d->state_ok = 0;
        if (w > d->wsize && (r = grow(d, (size_t)w))) return r;
    } else {
        /* a new stream can use any window at least as large as asked */
        d->state_ok = 0;
        if (d->wsize < w) {
            if (d->win) gz_free_big(d->win, d->wsize);
            d->wsize = d->wmask = 0;
            d->win = (u8 *)gz_alloc_big((size_t)w);
            if (!d->win) return GZ_E_NOMEM;
            d->wsize = (size_t)w;
            d->wmask = (size_t)w - 1;
        }
        d->pos = 0;
        d->wp = d->wp_sync = 0;
        d->full = 0;
    }
    d->alg = alg;
    d->io = io;
    d->out_size = out_size;
    d->out_done = 0;
    d->file_start = d->wr = d->pos;
    d->wp_stop = 0;
    d->thresh = d->wsize / 2 < (1u << 20) ? d->wsize / 2 : (1u << 20);
    d->in_base = 0;
    d->p = d->in_end = d->p_lim = d->in;
    d->in_eof = 0;
    d->bb = 0;
    d->bc = 0;
    d->nflt = 0;
    if ((r = fill(d))) return r;
    int broken = 0;
    if (alg == 29) r = decode29(d, pp->solid);
    else if (alg == 20) r = decode20(d, pp->solid);
    else r = decode15(d, pp->solid);
    if (r == R3_SWITCH) {
        broken = 1;                   /* the file is fine, the stream state is not */
        r = GZ_OK;
    }
    if (r) return r;
    advance(d);
    if ((r = flush(d, d->pos))) return r;
    if (out_size != GZ_SIZE_UNKNOWN ? d->out_done != out_size : d->wr != d->pos) return GZ_E_DATA;
    d->state_ok = !broken;
    return GZ_OK;
}
