/*
 * 고깃ZIP - entries under selected folders (main window selection -> extraction mask)
 *
 * Portable C on top of the core's folder tree (no Windows headers), so the test
 * driver tests/drivers/win_selmask.c builds it natively.
 */
#ifndef GZ_SELMASK_H
#define GZ_SELMASK_H

#include "arc.h"

/* Sets m[k] = 1 (m has a->n bytes) for every entry inside one of the folders
 * sel[0..nsel) (folder indices, a->f): the files of the folder and of all its
 * subfolders and the directory entries of the folder and its subfolders. Other
 * bytes of m are left as they are. One pass over the folders and one over the
 * entries: O(a->nf + a->n + nsel), whatever the number of selected folders.
 * Returns GZ_OK or GZ_E_NOMEM. */
int sel_mask_folders(const gz_archive *a, const i32 *sel, u32 nsel, u8 *m);

#endif
