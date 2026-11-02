/*
 * 고깃ZIP - AZO decoder (see azo.h for the stream layout)
 *
 * Models (all reset per block):
 *   bool state   12-bit probability per 8-bit history of previous outcomes,
 *                adapt by 1/64
 *   bit tree     10-bit probabilities over a binary tree of the symbol bits,
 *                adapt by 1/16
 *   predict      two bit trees per context (fine: ctx, coarse: ctx >> shift); the
 *                one that predicted better so far ("lucky" counter) codes the
 *                symbol, the other only learns it
 * Literal: predict<256 ctx = previous byte, coarse shift 5>.
 * Match: flag (bool state); then either a reused (position, length) pair from a
 * 128-entry move-to-front table of earlier matches (index through a 2-entry
 * recent list or a 7-bit tree), or a distance (2 recent distances or a 7-bit
 * code + uniform extra bits) and a length (predict<128 ctx = distance code,
 * shift 4> + extra bits). Codes: 16/32 direct values, then 4/8 per extra bit.
 */
#include "azo.h"

/* ---------------- arithmetic decoder ---------------- */

typedef struct {
    const u8 *p;          /* block data, readable for 8 bytes past nbits / 8 */
    u64 pos, nbits;       /* bits consumed (reads past the end count nothing) */
    u32 low, up, tag;
} az_rc;

GZ_INLINE u64 ld_be64(const u8 *p) { return rd64be(p); }

/* next k (1..31) bits MSB first; bits past the end read as 0 */
GZ_INLINE u32 rc_bits(az_rc *r, u32 k)
{
    u64 pos = r->pos;
    u32 v = (u32)((ld_be64(r->p + (pos >> 3)) << (pos & 7)) >> (64 - k));
    pos += k;
    if (GZ_UNLIKELY(pos > r->nbits)) {
        u32 over = (u32)(pos - r->nbits);
        v = over >= k ? 0 : v & ~((1u << over) - 1);
        pos = r->nbits;
    }
    r->pos = pos;
    return v;
}

static void rc_init(az_rc *r, const u8 *p, u32 n)
{
    r->p = p;
    r->pos = 0;
    r->nbits = (u64)n * 8;
    r->low = 0;
    r->up = 0xFFFFFFFFu;
    u32 hi = rc_bits(r, 16);
    r->tag = hi << 16 | rc_bits(r, 16);
}

/* E3: low = 01..., up = 10... (rare) */
static GZ_NOINLINE void rc_e3(az_rc *r)
{
    do {
        r->tag = ((r->tag << 1) | rc_bits(r, 1)) ^ 0x80000000u;
        r->low = (r->low << 1) & 0x7FFFFFFFu;
        r->up = (r->up << 1) | 0x80000001u;
    } while ((r->low & 0x40000000u) && !(r->up & 0x40000000u));
}

GZ_INLINE void rc_rescale(az_rc *r)
{
    /* E1/E2: leading bits of low and up agree */
    u32 x = r->low ^ r->up;
    if (!(x & 0x80000000u)) {
        u32 k = (u32)__builtin_clz(x);            /* low < up, so x != 0 and k <= 31 */
        r->low <<= k;
        r->up = (r->up << k) | ((1u << k) - 1);
        r->tag = (r->tag << k) | rc_bits(r, k);
    }
    if (GZ_UNLIKELY((r->low & 0x40000000u) && !(r->up & 0x40000000u))) rc_e3(r);
}

/* width of one count unit: the range split into 2^tb parts */
GZ_INLINE u32 rc_unit(const az_rc *r, u32 tb)
{
    if (!r->low && r->up == 0xFFFFFFFFu) return 1u << (32 - tb);
    return (r->up - r->low + 1) >> tb;
}

/* binary decision, cum = count of 0 out of 2^tb */
GZ_INLINE u32 rc_bit(az_rc *r, u32 cum, u32 tb)
{
    u32 t = rc_unit(r, tb), s = t * cum;          /* s < range: no overflow */
    u32 b;
    if (r->tag - r->low >= s) { r->low += s; b = 1; }
    else { r->up = r->low + s - 1; b = 0; }
    rc_rescale(r);
    return b;
}

/* uniform value of tb (1..27) bits */
static u32 rc_uniform(az_rc *r, u32 tb)
{
    u32 t = rc_unit(r, tb);
    u32 v = (r->tag - r->low) / t, max = (1u << tb) - 1;
    if (v > max) v = max;                         /* corrupt data: stay inside the range */
    r->up = r->low + t * (v + 1) - 1;
    r->low += t * v;
    rc_rescale(r);
    return v;
}

/* ---------------- models ---------------- */

typedef struct { u16 p[256]; u32 st; } az_bool;       /* history of 8 outcomes */

static void bool_init(az_bool *b)
{
    for (u32 i = 0; i < 256; i++) b->p[i] = 2048;
    b->st = 0;
}

GZ_INLINE u32 bool_dec(az_bool *b, az_rc *r)
{
    u16 *p = &b->p[b->st];
    u32 v = rc_bit(r, *p, 12);
    if (v) *p = (u16)(*p - (*p >> 6));
    else *p = (u16)(*p + ((4096u - *p) >> 6));
    b->st = ((b->st << 1) & 255) | v;
    return v;
}

/* bit tree over nb bits, p[1 .. 2^nb - 1] */
GZ_INLINE void tree_learn(u16 *p, u32 pre, u32 v)
{
    if (v) p[pre] = (u16)(p[pre] - (p[pre] >> 4));
    else p[pre] = (u16)(p[pre] + ((1024u - p[pre]) >> 4));
}

static u32 tree_dec(u16 *p, u32 nb, az_rc *r)
{
    u32 pre = 1;
    for (u32 i = 0; i < nb; i++) {
        u32 v = rc_bit(r, p[pre], 10);
        tree_learn(p, pre, v);
        pre = pre << 1 | v;
    }
    return pre - (1u << nb);
}

GZ_INLINE void tree_update(u16 *p, u32 nb, u32 val)
{
    u32 pre = 1;
    for (u32 i = nb; i-- > 0;) {
        u32 v = (val >> i) & 1;
        tree_learn(p, pre, v);
        pre = pre << 1 | v;
    }
}

/* which tree predicts val better (after both learned it): 1, -1 or 0 */
GZ_INLINE int tree_cmp(const u16 *a, const u16 *b, u32 nb, u32 val)
{
    u32 x = 1, y = 1, pre = 1;
    for (u32 i = nb; i-- > 0;) {
        u32 v = (val >> i) & 1, pa = a[pre], pb = b[pre];
        if ((x | y) & 0xFFC00000u) { x >>= 10; y >>= 10; }
        x *= v ? 1024u - pa : pa;
        y *= v ? 1024u - pb : pb;
        pre = pre << 1 | v;
    }
    return x > y ? 1 : x < y ? -1 : 0;
}

/* predict model decode: fine trees fine[ctx], coarse trees coarse[ctx >> sh] */
static u32 pred_dec(u16 *fine, u16 *coarse, i32 *lucky, u32 ctx, u32 sh, u32 nb, az_rc *r)
{
    u16 *f = fine + (ctx << nb), *c = coarse + ((ctx >> sh) << nb);
    u32 v;
    if (lucky[ctx] >= 0) { v = tree_dec(f, nb, r); tree_update(c, nb, v); }
    else { v = tree_dec(c, nb, r); tree_update(f, nb, v); }
    lucky[ctx] += tree_cmp(f, c, nb, v);
    return v;
}

/* recent list of 2 values coded as flag + 1-bit index, moved to the front on use */
typedef struct { az_bool flag; u16 sel[2]; u32 v[2]; } az_recent;

static void recent_init(az_recent *h, u32 first)
{
    bool_init(&h->flag);
    h->sel[0] = h->sel[1] = 512;
    h->v[0] = first;
    h->v[1] = first + 1;
}

/* 1 and *val when a recent value is used */
static int recent_dec(az_recent *h, az_rc *r, u32 *val)
{
    if (!bool_dec(&h->flag, r)) return 0;
    u32 i = tree_dec(h->sel, 1, r);
    u32 v = h->v[i];
    if (i) h->v[1] = h->v[0];
    h->v[0] = v;
    *val = v;
    return 1;
}

GZ_INLINE void recent_push(az_recent *h, u32 v) { h->v[1] = h->v[0]; h->v[0] = v; }

#define AZ_CODES 128u

struct gz_azo_dec {
    /* models */
    u16 lit_fine[256 * 256], lit_coarse[8 * 256];
    i32 lit_lucky[256];
    u16 len_fine[AZ_CODES * AZ_CODES], len_coarse[8 * AZ_CODES];
    i32 len_lucky[AZ_CODES];
    az_bool match;
    az_bool reuse;                         /* dictionary of earlier matches */
    az_recent reuse_recent;
    u16 reuse_tree[AZ_CODES];
    u32 dict_pos[AZ_CODES], dict_len[AZ_CODES];
    az_recent dist_recent;
    u16 dist_tree[AZ_CODES];
    /* tables */
    u32 len_base[AZ_CODES], dist_base[AZ_CODES];
    u8 len_extra[AZ_CODES], dist_extra[AZ_CODES];
    /* stream buffers */
    u8 *ib, *ob;                           /* block input (+8) and output */
    size_t ib_cap, ob_cap;
    u8 st[64u << 10];                      /* staging for io->read */
    u32 st_pos, st_len;
    int st_eof;
    u64 in_total;
};

static void fill16(u16 *p, size_t n, u16 v) { for (size_t i = 0; i < n; i++) p[i] = v; }

static void models_reset(gz_azo_dec *d)
{
    fill16(d->lit_fine, GZ_COUNTOF(d->lit_fine), 512);
    fill16(d->lit_coarse, GZ_COUNTOF(d->lit_coarse), 512);
    fill16(d->len_fine, GZ_COUNTOF(d->len_fine), 512);
    fill16(d->len_coarse, GZ_COUNTOF(d->len_coarse), 512);
    fill16(d->reuse_tree, AZ_CODES, 512);
    fill16(d->dist_tree, AZ_CODES, 512);
    __builtin_memset(d->lit_lucky, 0, sizeof d->lit_lucky);
    __builtin_memset(d->len_lucky, 0, sizeof d->len_lucky);
    bool_init(&d->match);
    bool_init(&d->reuse);
    recent_init(&d->reuse_recent, 0);
    recent_init(&d->dist_recent, 1);
    for (u32 i = 0; i < AZ_CODES; i++) { d->dict_pos[i] = 0; d->dict_len[i] = 2 + i; }
}

gz_azo_dec *gz_azo_dec_new(void)
{
    gz_azo_dec *d = (gz_azo_dec *)gz_alloc(sizeof(gz_azo_dec));
    if (!d) return 0;
    /* code tables: base[0] = minimum, then +2^extra; extra grows every 8 (length,
     * after 32 direct codes) or 4 (distance, after 16) codes */
    d->len_base[0] = 2;
    d->dist_base[0] = 1;
    for (u32 i = 1; i < AZ_CODES; i++) {
        d->len_extra[i] = (u8)(i < 32 ? 0 : (i - 32) / 8);
        d->dist_extra[i] = (u8)(i < 16 ? 0 : (i - 16) / 4);
        d->len_base[i] = d->len_base[i - 1] + (1u << d->len_extra[i - 1]);
        d->dist_base[i] = d->dist_base[i - 1] + (1u << d->dist_extra[i - 1]);
    }
    return d;
}

void gz_azo_dec_free(gz_azo_dec *d)
{
    if (!d) return;
    if (d->ib) gz_free_big(d->ib, d->ib_cap);
    if (d->ob) gz_free_big(d->ob, d->ob_cap);
    gz_free(d);
}

void *gz_azo_slot_new(void) { return gz_azo_dec_new(); }
void gz_azo_slot_free(void *p) { gz_azo_dec_free((gz_azo_dec *)p); }

/* code of a distance: 16 direct values, then 4 codes per extra bit */
GZ_INLINE u32 dist_code(u32 dist)
{
    u32 v = dist - 1;
    if (v < 16) return v;
    v -= 16;
    u32 e = 31 - (u32)__builtin_clz(v / 4 + 1);
    u32 c = 16 + e * 4 + (v - ((1u << e) - 1) * 4) / (1u << e);
    return c < AZ_CODES ? c : AZ_CODES - 1;
}

static int decode_block(gz_azo_dec *d, const u8 *in, u32 in_len, u8 *out, u32 out_len)
{
    az_rc r;
    models_reset(d);
    rc_init(&r, in, in_len);
    out[0] = (u8)pred_dec(d->lit_fine, d->lit_coarse, d->lit_lucky, 0, 5, 8, &r);
    u32 pos = 1;
    while (pos < out_len) {
        if (!bool_dec(&d->match, &r)) {
            out[pos] = (u8)pred_dec(d->lit_fine, d->lit_coarse, d->lit_lucky, out[pos - 1], 5, 8, &r);
            pos++;
            continue;
        }
        u32 dist, len, n;
        if (bool_dec(&d->reuse, &r)) {
            /* an earlier (position, length) pair, moved to the front */
            if (!recent_dec(&d->reuse_recent, &r, &n)) {
                n = tree_dec(d->reuse_tree, 7, &r);
                recent_push(&d->reuse_recent, n);
            }
            u32 p0 = d->dict_pos[n];
            len = d->dict_len[n];
            for (u32 k = n; k; k--) { d->dict_pos[k] = d->dict_pos[k - 1]; d->dict_len[k] = d->dict_len[k - 1]; }
            d->dict_pos[0] = p0;
            d->dict_len[0] = len;
            dist = pos - p0;
        } else {
            if (!recent_dec(&d->dist_recent, &r, &dist)) {
                u32 c = tree_dec(d->dist_tree, 7, &r);
                dist = d->dist_base[c];
                if (d->dist_extra[c]) dist += rc_uniform(&r, d->dist_extra[c]);
                recent_push(&d->dist_recent, dist);
            }
            u32 c = pred_dec(d->len_fine, d->len_coarse, d->len_lucky, dist_code(dist), 4, 7, &r);
            len = d->len_base[c];
            if (d->len_extra[c]) len += rc_uniform(&r, d->len_extra[c]);
            for (u32 k = AZ_CODES - 1; k; k--) { d->dict_pos[k] = d->dict_pos[k - 1]; d->dict_len[k] = d->dict_len[k - 1]; }
            d->dict_pos[0] = pos;
            d->dict_len[0] = len;
        }
        if (!dist || dist > pos || len > out_len - pos) return GZ_E_DATA;
        u8 *o = out + pos;
        const u8 *s = o - dist;
        if (dist >= len) __builtin_memcpy(o, s, len);
        else for (u32 k = 0; k < len; k++) o[k] = s[k];
        pos += len;
    }
    /* the coder must have touched exactly the block's bytes */
    return (r.pos + 7) / 8 == in_len ? GZ_OK : GZ_E_DATA;
}

void gz_azo_x86_unfilter(u8 *buf, u32 size)
{
    if (size < 5) return;
    for (u32 i = 0; i < size - 4;) {
        if ((buf[i] & 0xFE) != 0xE8) { i++; continue; }
        if (buf[i + 4] == 0x00 || buf[i + 4] == 0xFF) {
            u32 a = rd32(buf + i + 1) - i;
            a = (a >> 24) & 1 ? a | 0xFF000000u : a & 0x00FFFFFFu;
            wr32(buf + i + 1, a);
        }
        i += 5;
    }
}

/* ---------------- stream ---------------- */

static int grow(u8 **p, size_t *cap, size_t need)
{
    if (*cap >= need) return GZ_OK;
    if (*p) gz_free_big(*p, *cap);
    *cap = 0;
    size_t n = need < (1u << 20) ? (1u << 20) : need;
    *p = (u8 *)gz_alloc_big(n);
    if (!*p) return GZ_E_NOMEM;
    *cap = n;
    return GZ_OK;
}

int gz_azo_decode_block(gz_azo_dec *d, const u8 *in, u32 in_len, u8 *out, u32 out_len)
{
    if (!out_len || in_len + 8 > out_len || in_len > GZ_AZO_MAX_BLOCK) return GZ_E_DATA;
    int r = grow(&d->ib, &d->ib_cap, (size_t)in_len + 8);
    if (r) return r;
    __builtin_memcpy(d->ib, in, in_len);
    return decode_block(d, d->ib, in_len, out, out_len);
}

/* read exactly n bytes (GZ_E_TRUNC at end of input) */
static int rd_exact(gz_azo_dec *d, const gz_stream_io *io, u8 *dst, u32 n)
{
    while (n) {
        if (d->st_pos == d->st_len) {
            if (d->st_eof) return GZ_E_TRUNC;
            u32 got = 0;
            int r = io->read(io->ctx, d->st, sizeof d->st, &got);
            if (r) return r;
            if (got > sizeof d->st) return GZ_E_IO;
            if (!got) { d->st_eof = 1; return GZ_E_TRUNC; }
            d->st_pos = 0;
            d->st_len = got;
        }
        u32 k = d->st_len - d->st_pos;
        if (k > n) k = n;
        __builtin_memcpy(dst, d->st + d->st_pos, k);
        d->st_pos += k;
        d->in_total += k;
        dst += k;
        n -= k;
    }
    return GZ_OK;
}

int gz_azo_decode(gz_azo_dec *d, const gz_stream_io *io, u64 out_size, u64 *in_used)
{
    d->st_pos = d->st_len = 0;
    d->st_eof = 0;
    d->in_total = 0;
    u8 h[12];
    int r = rd_exact(d, io, h, 2);
    if (r) return r == GZ_E_TRUNC ? GZ_E_DATA : r;
    if (h[0] != '1') return GZ_E_DATA;
    int filter = h[1] & 1;
    u64 done = 0;
    while (out_size == GZ_SIZE_UNKNOWN || done < out_size) {
        if ((r = rd_exact(d, io, h, 12))) return r;
        u32 bs = rd32be(h), cs = rd32be(h + 4);
        if (bs < cs || (bs ^ cs) != rd32be(h + 8)) return GZ_E_DATA;
        if (!bs || !cs) {
            if (out_size != GZ_SIZE_UNKNOWN) return GZ_E_DATA;   /* ended early */
            break;
        }
        if (out_size != GZ_SIZE_UNKNOWN && bs > out_size - done) return GZ_E_DATA;
        if (bs > GZ_AZO_MAX_BLOCK) return GZ_E_LIMIT;
        if (cs != bs && cs + 8 > bs) return GZ_E_DATA;
        if ((r = grow(&d->ib, &d->ib_cap, (size_t)cs + 8)) || (r = grow(&d->ob, &d->ob_cap, bs))) return r;
        if ((r = rd_exact(d, io, d->ib, cs))) return r;
        if (cs == bs) __builtin_memcpy(d->ob, d->ib, bs);
        else if ((r = decode_block(d, d->ib, cs, d->ob, bs))) return r;
        if (filter) gz_azo_x86_unfilter(d->ob, bs);
        for (u32 o = 0; o < bs;) {
            u32 k = bs - o < (1u << 20) ? bs - o : (1u << 20);
            if ((r = io->write(io->ctx, d->ob + o, k))) return r;
            o += k;
        }
        done += bs;
    }
    if (in_used) *in_used = d->in_total;
    return GZ_OK;
}
