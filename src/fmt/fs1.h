/*
 * 고깃ZIP - helpers shared by the FAT, exFAT and ext2/3/4 readers
 *
 *   run sinks   walkers (cluster chains, extent trees, indirect blocks) emit the
 *               physical byte runs of a file in logical order; a sink coalesces
 *               them and copies them to a gz_out, collects them into a run list
 *               (random-access gz_src of a fragmented / sparse file) or reads
 *               them into memory (directories)
 *   FAT chains  32-bit cluster chain walker (FAT12/16/32 tables are normalised
 *               to 32-bit entries; big tables are read on demand)
 *   node tree   directories found while listing, and full path assembly from
 *               mixed UTF-16 / byte-string components
 *   key set     visited directories (cycle protection)
 */
#ifndef GZ_FS1_H
#define GZ_FS1_H
#include "arc.h"

#define GZ_FS1_HOLE (~(u64)0)     /* run of zeros (sparse hole, unwritten extent)     */
#define GZ_FS1_FULL 0x100         /* sink reached its limit: stop walking, not an error */
#define GZ_FS1_MAXDEPTH 256       /* directories deeper than this are not descended   */

/* ---------------- run sinks ---------------- */

typedef struct gz_fs1_sink gz_fs1_sink;
struct gz_fs1_sink {
    /* receive a coalesced run of len bytes at logical offset k->flushed */
    int (*put)(gz_fs1_sink *k, u64 poff, u64 len);
    u64 limit;          /* logical size: runs are clipped here                  */
    u64 pos;            /* logical bytes accepted (including the pending run)   */
    u64 flushed;        /* logical bytes handed to put()                         */
    u64 p_off, p_len;   /* pending run                                           */
};

void gz_fs1_sink_init(gz_fs1_sink *k, int (*put)(gz_fs1_sink *, u64, u64), u64 limit);
/* Append a run (poff = GZ_FS1_HOLE for zeros). GZ_OK, GZ_FS1_FULL at the limit, or an error. */
int  gz_fs1_emit(gz_fs1_sink *k, u64 poff, u64 len);
/* Hand the pending run to put(); with pad != 0 first extend with zeros up to the limit. */
int  gz_fs1_flush(gz_fs1_sink *k, int pad);

/* copy runs from s to an entry output (zeros for holes), 256 KiB chunks */
typedef struct {
    gz_fs1_sink k;
    gz_src *s;
    gz_out *out;
    gz_ctx *c;
    u8 *buf;
    u32 cap;
    int zeroed;
} gz_fs1_copy;
int gz_fs1_copy_init(gz_fs1_copy *w, gz_src *s, gz_out *out, gz_ctx *c, u64 size);

/* read runs into a growing memory buffer (p, k.flushed bytes; free with gz_free) */
typedef struct {
    gz_fs1_sink k;
    gz_src *s;
    u8 *p;
    size_t cap;
} gz_fs1_mem;
void gz_fs1_mem_init(gz_fs1_mem *m, gz_src *s, u64 limit);

/* collect runs into a run list (at most max_runs) */
typedef struct { u64 loff, poff; } gz_fs1_run;
typedef struct {
    gz_fs1_sink k;
    gz_fs1_run *r;
    u32 n, cap, max;
} gz_fs1_list;
void gz_fs1_list_init(gz_fs1_list *l, u64 size, u32 max_runs);
void gz_fs1_list_free(gz_fs1_list *l);
/* Random-access source over the collected runs (call after gz_fs1_flush(&l->k, 1)).
 * One data run gives a plain gz_src_sub view. Always consumes the list (l is emptied). */
gz_src *gz_fs1_list_src(gz_src *parent, gz_fs1_list *l);

/* ---------------- FAT cluster chains ---------------- */

typedef struct {
    const u32 *tab;     /* whole table (FAT12/16 always, FAT32/exFAT when small) or NULL */
    u64 fat_off;        /* byte offset of the 32-bit table when read on demand          */
    u32 nclus;          /* data clusters are 2 .. nclus + 1                              */
    u32 mask;           /* 0x0FFFFFFF (FAT) / 0xFFFFFFFF (exFAT)                        */
    u32 eoc;            /* masked values >= eoc end a chain                              */
    u32 cshift;         /* log2 of the cluster size in bytes                             */
    u64 heap;           /* byte offset of cluster 2                                      */
} gz_fs1_fat;

/* On-demand FAT reads: small direct-mapped cache (allocate with gz_fs1_fatcache_new). */
typedef struct gz_fs1_fatcache gz_fs1_fatcache;
gz_fs1_fatcache *gz_fs1_fatcache_new(void);
void gz_fs1_fatcache_free(gz_fs1_fatcache *fc);

/* Load the table from s when it has at most max_entries entries (32-bit on-disk entries).
 * Returns GZ_OK with *tab = NULL when it is bigger (read on demand). */
int gz_fs1_fat_load32(gz_src *s, u64 off, u32 nent, u32 max_entries, u32 **tab);

/* Emit the runs of the chain starting at first (contiguous != 0: exFAT NoFatChain run).
 * Visits at most nclus clusters. GZ_OK when the chain ended (k->pos may be < limit),
 * GZ_FS1_FULL when the sink is full, GZ_E_DATA on a broken chain. fc may be NULL when
 * f->tab is set; otherwise a temporary cache is used. */
int gz_fs1_fat_walk(const gz_fs1_fat *f, gz_src *s, gz_fs1_fatcache *fc, u32 first, int contiguous,
                    gz_fs1_sink *k);

/* ---------------- key set ---------------- */

typedef struct { u64 *k; u32 n, cap; } gz_fs1_set;
/* 1 = added, 0 = already present, -1 = out of memory */
int  gz_fs1_set_add(gz_fs1_set *s, u64 key);
void gz_fs1_set_free(gz_fs1_set *s);

/* ---------------- directory nodes and paths ---------------- */

typedef struct {
    i32 parent;
    u32 name_off, name_len;   /* component bytes in tree names                         */
    u8  ne;                   /* GZ_NE_UTF16LE or the tree's byte encoding              */
    u8  na;                   /* path has non-ASCII: 1 byte component, 2 UTF-16 component */
    u16 depth;
    u64 loc, size;            /* format private: first cluster / inode, size            */
    u32 aux;
} gz_fs1_node;

typedef struct {
    gz_fs1_node *n;
    u32 nn, capn;
    u8 *names;
    u32 nlen, ncap;
    u8 *buf;                  /* path assembly */
    u32 bcap;
    int byte_ne;              /* encoding of byte components: GZ_NE_OEM / GZ_NE_LEGACY  */
    int cp;                   /* code page to widen byte components that mix with UTF-16 */
} gz_fs1_tree;

int  gz_fs1_tree_init(gz_fs1_tree *t, int byte_ne, int cp);   /* node 0 = root */
void gz_fs1_tree_free(gz_fs1_tree *t);
/* Add a directory node below parent. Returns its index, -1 out of memory, -2 too deep. */
i32  gz_fs1_tree_add(gz_fs1_tree *t, i32 parent, const u8 *name, u32 len, int ne,
                     u64 loc, u64 size, u32 aux);
/* Add an archive entry "<path of parent>/<name>" (name in encoding ne). */
int  gz_fs1_add_entry(gz_archive *a, gz_fs1_tree *t, i32 parent, const u8 *name, u32 len, int ne,
                      gz_entry **pe);

#endif
