/*
 * 고깃ZIP - entries under selected folders (see selmask.h)
 *
 * The folder tree of gz_arc_build_tree gives every file its folder (e->folder)
 * and every folder its parent; a parent is always created before its subfolders,
 * so "inside a selected folder" is known for all folders in one pass in index
 * order. A directory entry describes the folder whose base name it shares
 * (e->base points into that folder's name) and sits in that folder's parent.
 */
#include "selmask.h"

static u32 ptr_hash(const void *p)
{
    u64 v = 0;
    __builtin_memcpy(&v, &p, sizeof p < sizeof v ? sizeof p : sizeof v);
    v ^= v >> 29;
    v *= 0x9E3779B97F4A7C15ull;
    return (u32)(v >> 32);
}

int sel_mask_folders(const gz_archive *a, const i32 *sel, u32 nsel, u8 *m)
{
    u32 nf = a->nf;
    if (!nsel || !nf) return GZ_OK;
    u8 *in = (u8 *)gz_alloc(nf);                       /* 1: selected or inside a selected folder */
    if (!in) return GZ_E_NOMEM;
    u32 ntop = 0;
    for (u32 i = 0; i < nsel; i++)
        if (sel[i] >= 0 && (u32)sel[i] < nf && !in[sel[i]]) { in[sel[i]] = 1; ntop++; }
    for (u32 f = 1; f < nf; f++) {
        if (in[f]) continue;
        i32 p = a->f[f].parent;
        if (p >= 0 && (u32)p < f) { in[f] = in[p]; continue; }
        /* not produced by the core (parents come first): walk the chain, bounded */
        for (u32 s = 0; p >= 0 && (u32)p < nf && s < nf; s++, p = a->f[p].parent)
            if (in[p]) { in[f] = 1; break; }
    }

    /* Directory entries whose parent is outside the selection belong to it only when
     * they describe a selected folder: look their base pointer up among the selected
     * folders whose parent is outside (a set of pointers, open addressing). */
    u32 cap = 16;
    while (cap < ntop * 2 && cap < (1u << 30)) cap <<= 1;
    const gzch **set = (const gzch **)gz_alloc((size_t)cap * sizeof(const gzch *));
    if (!set) { gz_free(in); return GZ_E_NOMEM; }
    for (u32 i = 0; i < nsel; i++) {
        i32 f = sel[i];
        if (f <= 0 || (u32)f >= nf) continue;          /* the root has no directory entry */
        i32 p = a->f[f].parent;
        if (p >= 0 && (u32)p < nf && in[p]) continue;  /* its entries are found through the parent */
        const gzch *b = a->f[f].base;
        u32 h = ptr_hash(b) & (cap - 1);
        while (set[h] && set[h] != b) h = (h + 1) & (cap - 1);
        set[h] = b;
    }

    for (u32 k = 0; k < a->n; k++) {
        const gz_entry *e = &a->e[k];
        if (e->folder < 0 || (u32)e->folder >= nf) continue;   /* hidden (unusable name) */
        if (in[e->folder]) { m[k] = 1; continue; }
        if (!e->is_dir || !e->base) continue;
        u32 h = ptr_hash(e->base) & (cap - 1);
        while (set[h]) {
            if (set[h] == e->base) { m[k] = 1; break; }
            h = (h + 1) & (cap - 1);
        }
    }
    gz_free(set);
    gz_free(in);
    return GZ_OK;
}
