/*
 * 고깃ZIP - LZ match finders for the LZMA encoder
 *
 *   HC4  hash chains   (fast modes): one link per position, newest first
 *   BT4  binary trees  (normal modes): every position is inserted into a binary
 *        search tree ordered by the bytes that follow it; a search visits the
 *        path from the hash head and re-links it around the new node
 *
 * Both use 7-Zip's CRC-table hashing: an exact 2-byte head (1 Ki entries) and
 * an exact 3-byte head (64 Ki entries), plus a 4-byte head sized from the
 * dictionary. Links live in a cyclic buffer of dict_size + 1 entries (two per
 * position for BT4) holding absolute positions; they are renormalised before
 * the 32-bit position counter would wrap, so inputs of any size work.
 *
 * Window: one buffer holding [cur - keep_before, end): the dictionary behind
 * the current position, the bytes not coded yet and a read-ahead block. Input
 * is pulled from a gz_stream_io in chunks; when the tail is full, the last
 * keep_before bytes are moved to the front. Memory is bounded by
 * dictionary + look-ahead + block whatever the input size.
 *
 * The finder is self-contained (no globals): a second thread could later run
 * it ahead of the encoder and hand over match lists through a queue.
 */
#ifndef GZ_LZ_MF_H
#define GZ_LZ_MF_H
#include "base.h"
#include "stream.h"

enum { GZ_MF_HC4 = 0, GZ_MF_BT4 = 1 };

#define GZ_MF_LEN_MAX   273u           /* longest match the finder reports    */
#define GZ_MF_DICT_MIN  4096u

typedef struct gz_lz_mf_cfg {
    u32 dict_size;      /* maximum match distance in bytes (>= 4 KiB)           */
    u32 nice_len;       /* stop a search at this length (4..273)                 */
    u32 depth;          /* nodes visited per position (cut value, >= 1)          */
    int type;           /* GZ_MF_HC4 / GZ_MF_BT4                                 */
    size_t keep_before; /* bytes behind the current position kept addressable    */
                        /* (>= dict_size + 1; extra for encoder look-behind)      */
    size_t keep_after;  /* look-ahead: refill when fewer bytes are left (>= 274)  */
    size_t block;       /* read-ahead block size (memory = keep + block)          */
    u32 norm_step;      /* testing: renormalise every N positions (0 = at 2^32)   */
} gz_lz_mf_cfg;

typedef struct gz_lz_mf gz_lz_mf;
typedef u32  (*gz_mf_find_fn)(gz_lz_mf *m, u32 *out);
typedef void (*gz_mf_skip_fn)(gz_lz_mf *m, u32 n);

struct gz_lz_mf {
    /* hot state */
    u8  *cur;            /* current position in the window                       */
    u8  *end;            /* end of the bytes read so far                         */
    u32  pos;            /* absolute position of cur (normalised)                */
    u32  pos_limit;      /* when pos reaches it: refill / wrap / renormalise     */
    u32  cyc_pos, cyc_size;
    u32  len_limit;      /* min(nice_len, bytes available)                       */
    u32  nice_len, depth;
    u32  hash_mask;
    u32 *hash;           /* h2 | h3 | h4 heads                                   */
    u32 *son;            /* chain links (HC4) or tree children (BT4)             */
    gz_mf_find_fn find;
    gz_mf_skip_fn skip;
    int  prefetch;       /* head table larger than the caches                    */
    int  son_shift;      /* log2 links per position                              */
    int  eof;            /* input exhausted (or failed: err)                     */
    int  err;            /* read error                                           */
    const gz_stream_io *io;
    u64  in_total;       /* bytes read from io                                   */
    u32  norm_at, norm_step;
    /* window */
    u8  *buf;
    size_t buf_size, keep_before, keep_after, read_chunk;
    /* allocations */
    void  *hash_mem;
    size_t hash_bytes, son_bytes;
    u32   *son_mem;
    int    fresh;        /* hash table is still zero from the allocator          */
    gz_lz_mf_cfg cfg;
    u32  crc[256];
};

/* Allocate (or keep, when the sizes match) the window and tables. GZ_E_NOMEM. */
int  gz_lz_mf_alloc(gz_lz_mf *m, const gz_lz_mf_cfg *c);
void gz_lz_mf_release(gz_lz_mf *m);
/* Bytes the tables and window need for a configuration. */
u64  gz_lz_mf_memusage(const gz_lz_mf_cfg *c);
/* Start a new stream read from io (fills the first block). */
void gz_lz_mf_start(gz_lz_mf *m, const gz_stream_io *io);

/* Length of the common prefix of a and b counted from len, at most lim (word
 * compares; reads stay below a + lim and b + lim). */
static inline u32 gz_lz_match_len(const u8 *a, const u8 *b, u32 len, u32 lim)
{
#if defined(__x86_64__) || defined(__aarch64__)
    while (len + 8 <= lim) {
        u64 x = rd64(a + len) ^ rd64(b + len);
        if (x) return len + ((u32)__builtin_ctzll(x) >> 3);
        len += 8;
    }
#else
    while (len + 4 <= lim) {
        u32 x = rd32(a + len) ^ rd32(b + len);
        if (x) return len + ((u32)__builtin_ctz(x) >> 3);
        len += 4;
    }
#endif
    while (len < lim && a[len] == b[len]) len++;
    return len;
}

/* Bytes available from the current position (including it). */
static inline u32 gz_lz_mf_avail(const gz_lz_mf *m)
{
    size_t n = (size_t)(m->end - m->cur);
    return n > 0xFFFFFFF0u ? 0xFFFFFFF0u : (u32)n;
}

/* Matches at the current position as (len, distance - 1) pairs with strictly
 * increasing lengths; returns the number of u32 written (2 * pairs, at most
 * 2 * GZ_MF_LEN_MAX). Advances by one byte. Lengths stop at nice_len. */
static inline u32 gz_lz_mf_find(gz_lz_mf *m, u32 *out) { return m->find(m, out); }
/* Insert n >= 1 positions without reporting matches. */
static inline void gz_lz_mf_skip(gz_lz_mf *m, u32 n) { m->skip(m, n); }

#endif
