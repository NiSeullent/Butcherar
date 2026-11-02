/*
 * 고깃ZIP - HC4 / BT4 match finders (see lz_mf.h)
 *
 * Algorithms follow 7-Zip's LzFind.c (public domain): CRC-table hashing with
 * exact 2/3-byte heads, cyclic link buffer, positions starting at cyc_size so
 * that 0 means "empty", one compare per byte to reach the slow path.
 */
#include "lz_mf.h"

#define H2_SIZE (1u << 10)
#define H3_SIZE (1u << 16)
#define FIX3    H2_SIZE
#define FIX4    (H2_SIZE + H3_SIZE)

static u32 hash_mask_for(u32 dict)
{
    u32 hs = dict - 1;
    hs |= hs >> 1;
    hs |= hs >> 2;
    hs |= hs >> 4;
    hs |= hs >> 8;
    hs |= hs >> 16;
    hs >>= 1;
    hs |= 0xFFFF;
    if (hs > (1u << 24)) hs >>= 1;     /* above 32 MiB: dict/4 heads (xz, 7-Zip) */
    return hs;
}

/* Table and window sizes in u64 (no size_t overflow on 32-bit builds). */
static void sizes_for(const gz_lz_mf_cfg *c, u64 *hash_bytes, u64 *son_bytes, u64 *buf_size)
{
    u64 cyc = (u64)c->dict_size + 1;
    *hash_bytes = ((u64)FIX4 + hash_mask_for(c->dict_size) + 1) * 4;
    *son_bytes = cyc * (c->type == GZ_MF_BT4 ? 8 : 4);
    *buf_size = (u64)c->keep_before + c->keep_after + c->block;
}

u64 gz_lz_mf_memusage(const gz_lz_mf_cfg *c)
{
    u64 h, s, b;
    sizes_for(c, &h, &s, &b);
    return h + s + b;
}

void gz_lz_mf_release(gz_lz_mf *m)
{
    if (m->hash_mem) gz_free_big(m->hash_mem, m->hash_bytes);
    if (m->son_mem) gz_free_big(m->son_mem, m->son_bytes);
    if (m->buf) gz_free_big(m->buf, m->buf_size);
    m->hash_mem = 0; m->son_mem = 0; m->buf = 0;
    m->hash = m->son = 0;
    m->hash_bytes = m->son_bytes = m->buf_size = 0;
}

/* ---------------- window / limits ---------------- */

static void mf_normalize(gz_lz_mf *m)
{
    u32 sub = m->pos - m->cyc_size;      /* entries <= sub are out of reach anyway */
    size_t nh = FIX4 + (size_t)m->hash_mask + 1;
    size_t ns = m->son_bytes / 4;
    u32 *p = m->hash;
    for (size_t i = 0; i < nh; i++) p[i] = p[i] > sub ? p[i] - sub : 0;
    p = m->son;
    for (size_t i = 0; i < ns; i++) p[i] = p[i] > sub ? p[i] - sub : 0;
    m->pos -= sub;
    m->norm_at = (m->norm_step && m->norm_step < 0xFFFFFFFFu - m->pos) ? m->pos + m->norm_step : 0xFFFFFFFFu;
}

static void mf_refill(gz_lz_mf *m)
{
    u8 *lim = m->buf + m->buf_size;
    if (m->eof) return;
    if ((size_t)(lim - m->end) < m->read_chunk) {
        /* move the kept history to the front; nothing outside holds pointers */
        size_t back = (size_t)(m->cur - m->buf);
        if (back > m->keep_before) {
            size_t drop = back - m->keep_before;
            __builtin_memmove(m->buf, m->buf + drop, (size_t)(m->end - m->buf) - drop);
            m->cur -= drop;
            m->end -= drop;
        }
    }
    size_t want = (size_t)(lim - m->end);
    if (want > m->read_chunk) want = m->read_chunk;
    while (want) {
        u32 cap = want > (1u << 30) ? (1u << 30) : (u32)want, got = 0;
        int r = m->io->read(m->io->ctx, m->end, cap, &got);
        if (r) { m->err = r; m->eof = 1; break; }
        if (!got) { m->eof = 1; break; }
        if (got > cap) got = cap;
        m->end += got;
        m->in_total += got;
        want -= got;
    }
}

static void mf_set_limits(gz_lz_mf *m)
{
    u32 lim = m->norm_at - m->pos, l2 = m->cyc_size - m->cyc_pos;
    size_t avail = (size_t)(m->end - m->cur);
    if (l2 < lim) lim = l2;
    if (avail <= m->keep_after) l2 = avail ? 1 : 0;   /* tail: re-check every byte */
    else l2 = avail - m->keep_after > 0x7FFFFFFF ? 0x7FFFFFFF : (u32)(avail - m->keep_after);
    if (l2 < lim) lim = l2;
    m->len_limit = avail < m->nice_len ? (u32)avail : m->nice_len;
    m->pos_limit = m->pos + lim;
}

static GZ_NOINLINE void mf_check_limits(gz_lz_mf *m)
{
    if (m->pos == m->norm_at) mf_normalize(m);
    if (!m->eof && (size_t)(m->end - m->cur) <= m->keep_after) mf_refill(m);
    if (m->cyc_pos == m->cyc_size) m->cyc_pos = 0;
    mf_set_limits(m);
}

GZ_INLINE void mf_move(gz_lz_mf *m)
{
    m->cyc_pos++;
    m->cur++;
    if (++m->pos == m->pos_limit) mf_check_limits(m);
}

/* ---------------- hash chains ---------------- */

static u32 *hc_search(u32 len_limit, u32 cm, u32 pos, const u8 *cur, u32 *son, u32 cyc_pos,
                      u32 cyc, u32 cut, u32 *d, u32 max_len)
{
    son[cyc_pos] = cm;
    for (;;) {
        u32 delta = pos - cm;
        if (cut-- == 0 || delta >= cyc) return d;
        const u8 *pb = cur - delta;
        cm = son[cyc_pos - delta + (delta > cyc_pos ? cyc : 0)];
        if (pb[max_len] == cur[max_len] && pb[0] == cur[0]) {
            u32 len = gz_lz_match_len(pb, cur, 1, len_limit);
            if (max_len < len) {
                *d++ = max_len = len;
                *d++ = delta - 1;
                if (len == len_limit) return d;
            }
        }
    }
}

/* ---------------- binary trees ---------------- */

static u32 *bt_search(u32 len_limit, u32 cm, u32 pos, const u8 *cur, u32 *son, u32 cyc_pos,
                      u32 cyc, u32 cut, u32 *d, u32 max_len)
{
    u32 *ptr0 = son + ((size_t)cyc_pos << 1) + 1;
    u32 *ptr1 = son + ((size_t)cyc_pos << 1);
    u32 len0 = 0, len1 = 0;
    for (;;) {
        u32 delta = pos - cm;
        if (cut-- == 0 || delta >= cyc) {
            *ptr0 = *ptr1 = 0;
            return d;
        }
        u32 *pair = son + ((size_t)(cyc_pos - delta + (delta > cyc_pos ? cyc : 0)) << 1);
        const u8 *pb = cur - delta;
        u32 len = len0 < len1 ? len0 : len1;
        if (pb[len] == cur[len]) {
            len = gz_lz_match_len(pb, cur, len + 1, len_limit);
            if (max_len < len) {
                *d++ = max_len = len;
                *d++ = delta - 1;
                if (len == len_limit) {
                    *ptr1 = pair[0];
                    *ptr0 = pair[1];
                    return d;
                }
            }
        }
        if (pb[len] < cur[len]) {
            *ptr1 = cm;
            ptr1 = pair + 1;
            cm = *ptr1;
            len1 = len;
        } else {
            *ptr0 = cm;
            ptr0 = pair;
            cm = *ptr0;
            len0 = len;
        }
    }
}

static void bt_insert(u32 len_limit, u32 cm, u32 pos, const u8 *cur, u32 *son, u32 cyc_pos,
                      u32 cyc, u32 cut)
{
    u32 *ptr0 = son + ((size_t)cyc_pos << 1) + 1;
    u32 *ptr1 = son + ((size_t)cyc_pos << 1);
    u32 len0 = 0, len1 = 0;
    for (;;) {
        u32 delta = pos - cm;
        if (cut-- == 0 || delta >= cyc) {
            *ptr0 = *ptr1 = 0;
            return;
        }
        u32 *pair = son + ((size_t)(cyc_pos - delta + (delta > cyc_pos ? cyc : 0)) << 1);
        const u8 *pb = cur - delta;
        u32 len = len0 < len1 ? len0 : len1;
        if (pb[len] == cur[len]) {
            len = gz_lz_match_len(pb, cur, len + 1, len_limit);
            if (len == len_limit) {
                *ptr1 = pair[0];
                *ptr0 = pair[1];
                return;
            }
        }
        if (pb[len] < cur[len]) {
            *ptr1 = cm;
            ptr1 = pair + 1;
            cm = *ptr1;
            len1 = len;
        } else {
            *ptr0 = cm;
            ptr0 = pair;
            cm = *ptr0;
            len0 = len;
        }
    }
}

/* ---------------- 4-byte finders ---------------- */

#define HASH4(m, cur, h2, h3, hv) do {                          \
        u32 t_ = (m)->crc[(cur)[0]] ^ (cur)[1];                 \
        h2 = t_ & (H2_SIZE - 1);                                \
        t_ ^= (u32)(cur)[2] << 8;                               \
        h3 = t_ & (H3_SIZE - 1);                                \
        hv = (t_ ^ ((m)->crc[(cur)[3]] << 5)) & (m)->hash_mask; \
    } while (0)

/* 2- and 3-byte candidates (exact thanks to the CRC hash), then the long search.
 * Returns the u32 count; *cm gets the 4-byte head for the long search. */
GZ_INLINE u32 heads4(gz_lz_mf *m, const u8 *cur, u32 *d, u32 *cm, u32 *maxl)
{
    u32 h2, h3, hv, pos = m->pos, cyc = m->cyc_size, *hash = m->hash;
    HASH4(m, cur, h2, h3, hv);
    if (m->prefetch && m->len_limit > 5) {
        /* Large tables miss the cache. Two-stage look-ahead: fetch the bucket of
         * position + 2, and the first tree node / window bytes of position + 1
         * (whose bucket was fetched by the previous call). */
        u32 h1 = ((m->crc[cur[1]] ^ cur[2] ^ ((u32)cur[3] << 8)) ^ (m->crc[cur[4]] << 5)) & m->hash_mask;
        u32 hn = ((m->crc[cur[2]] ^ cur[3] ^ ((u32)cur[4] << 8)) ^ (m->crc[cur[5]] << 5)) & m->hash_mask;
        __builtin_prefetch(hash + FIX4 + hn);
        u32 dn = pos + 1 - hash[FIX4 + h1];
        if (dn < cyc) {
            u32 np = m->cyc_pos + 1;
            np = np - dn + (dn > np ? cyc : 0);
            __builtin_prefetch(m->son + ((size_t)np << m->son_shift));
            __builtin_prefetch(cur + 1 - dn);
        }
    }
    u32 d2 = pos - hash[h2], d3 = pos - hash[FIX3 + h3];
    *cm = hash[FIX4 + hv];
    hash[h2] = pos;
    hash[FIX3 + h3] = pos;
    hash[FIX4 + hv] = pos;
    u32 max_len = 1, n = 0;
    if (d2 < cyc && *(cur - d2) == cur[0]) {
        d[0] = max_len = 2;
        d[1] = d2 - 1;
        n = 2;
    }
    if (d2 != d3 && d3 < cyc && *(cur - d3) == cur[0]) {
        max_len = 3;
        d[n + 1] = d3 - 1;
        n += 2;
        d2 = d3;
    }
    if (n) {
        max_len = gz_lz_match_len(cur - d2, cur, max_len, m->len_limit);
        d[n - 2] = max_len;
    }
    *maxl = max_len;
    return n;
}

static u32 hc4_find(gz_lz_mf *m, u32 *d)
{
    u32 cm, max_len;
    if (m->len_limit < 4) { mf_move(m); return 0; }
    const u8 *cur = m->cur;
    u32 n = heads4(m, cur, d, &cm, &max_len);
    if (max_len == m->len_limit) {
        m->son[m->cyc_pos] = cm;
    } else {
        if (max_len < 3) max_len = 3;
        n = (u32)(hc_search(m->len_limit, cm, m->pos, cur, m->son, m->cyc_pos, m->cyc_size,
                            m->depth, d + n, max_len) - d);
    }
    mf_move(m);
    return n;
}

static void hc4_skip(gz_lz_mf *m, u32 num)
{
    do {
        if (m->len_limit >= 4) {
            u32 h2, h3, hv;
            const u8 *cur = m->cur;
            HASH4(m, cur, h2, h3, hv);
            m->son[m->cyc_pos] = m->hash[FIX4 + hv];
            m->hash[h2] = m->pos;
            m->hash[FIX3 + h3] = m->pos;
            m->hash[FIX4 + hv] = m->pos;
        }
        mf_move(m);
    } while (--num);
}

static u32 bt4_find(gz_lz_mf *m, u32 *d)
{
    u32 cm, max_len;
    if (m->len_limit < 4) { mf_move(m); return 0; }
    const u8 *cur = m->cur;
    u32 n = heads4(m, cur, d, &cm, &max_len);
    if (max_len == m->len_limit) {
        bt_insert(m->len_limit, cm, m->pos, cur, m->son, m->cyc_pos, m->cyc_size, m->depth);
    } else {
        if (max_len < 3) max_len = 3;
        n = (u32)(bt_search(m->len_limit, cm, m->pos, cur, m->son, m->cyc_pos, m->cyc_size,
                            m->depth, d + n, max_len) - d);
    }
    mf_move(m);
    return n;
}

static void bt4_skip(gz_lz_mf *m, u32 num)
{
    do {
        if (m->len_limit >= 4) {
            u32 h2, h3, hv;
            const u8 *cur = m->cur;
            HASH4(m, cur, h2, h3, hv);
            u32 cm = m->hash[FIX4 + hv];
            m->hash[h2] = m->pos;
            m->hash[FIX3 + h3] = m->pos;
            m->hash[FIX4 + hv] = m->pos;
            bt_insert(m->len_limit, cm, m->pos, cur, m->son, m->cyc_pos, m->cyc_size, m->depth);
        }
        mf_move(m);
    } while (--num);
}

/* ---------------- setup ---------------- */

int gz_lz_mf_alloc(gz_lz_mf *m, const gz_lz_mf_cfg *c)
{
    u64 h64, s64, b64;
    size_t hb, sb, bs;
    if (c->dict_size < GZ_MF_DICT_MIN || c->dict_size > 0x7FFFFFF0u ||
        c->keep_before <= c->dict_size || c->keep_after <= GZ_MF_LEN_MAX || !c->block)
        return GZ_E_METHOD;
    sizes_for(c, &h64, &s64, &b64);
    if (h64 + s64 + b64 > (u64)(~(size_t)0 >> 1)) return GZ_E_LIMIT;   /* 32-bit address space */
    hb = (size_t)h64;
    sb = (size_t)s64;
    bs = (size_t)b64;
    if (hb != m->hash_bytes || !m->hash_mem) {
        if (m->hash_mem) gz_free_big(m->hash_mem, m->hash_bytes);
        m->hash_bytes = hb;
        m->hash_mem = gz_alloc_big(hb);
        m->fresh = 1;
    }
    if (sb != m->son_bytes || !m->son_mem) {
        if (m->son_mem) gz_free_big(m->son_mem, m->son_bytes);
        m->son_bytes = sb;
        m->son_mem = (u32 *)gz_alloc_big(sb);
    }
    if (bs != m->buf_size || !m->buf) {
        if (m->buf) gz_free_big(m->buf, m->buf_size);
        m->buf_size = bs;
        m->buf = (u8 *)gz_alloc_big(bs);
    }
    if (!m->hash_mem || !m->son_mem || !m->buf) {
        gz_lz_mf_release(m);
        return GZ_E_NOMEM;
    }
    m->hash = (u32 *)m->hash_mem;
    m->son = m->son_mem;
    m->hash_mask = hash_mask_for(c->dict_size);
    m->prefetch = m->hash_mask >= (1u << 20) - 1;
    m->son_shift = c->type == GZ_MF_BT4;
    m->cyc_size = c->dict_size + 1;
    m->nice_len = c->nice_len < 4 ? 4 : c->nice_len > GZ_MF_LEN_MAX ? GZ_MF_LEN_MAX : c->nice_len;
    m->depth = c->depth ? c->depth : 1;
    m->keep_before = c->keep_before;
    m->keep_after = c->keep_after;
    m->read_chunk = c->block < (1u << 20) ? c->block : (1u << 20);
    m->norm_step = c->norm_step;
    m->find = c->type == GZ_MF_BT4 ? bt4_find : hc4_find;
    m->skip = c->type == GZ_MF_BT4 ? bt4_skip : hc4_skip;
    m->cfg = *c;
    for (u32 i = 0; i < 256; i++) {
        u32 r = i;
        for (int k = 0; k < 8; k++) r = (r >> 1) ^ (0xEDB88320u & (0u - (r & 1)));
        m->crc[i] = r;
    }
    return GZ_OK;
}

void gz_lz_mf_start(gz_lz_mf *m, const gz_stream_io *io)
{
    if (!m->fresh) __builtin_memset(m->hash, 0, m->hash_bytes);
    m->fresh = 0;
    m->io = io;
    m->cur = m->end = m->buf;
    m->eof = 0;
    m->err = 0;
    m->in_total = 0;
    m->pos = m->cyc_size;
    m->cyc_pos = 0;
    m->norm_at = (m->norm_step && m->norm_step < 0xFFFFFFFFu - m->pos) ? m->pos + m->norm_step : 0xFFFFFFFFu;
    mf_refill(m);
    mf_set_limits(m);
}
