/*
 * 고깃ZIP - POSIX helpers shared by the CLI, GTK and Cocoa front ends
 */
#ifndef GZ_PLAT_POSIX_H
#define GZ_PLAT_POSIX_H
#include "arc.h"

gz_src *gz_posix_open_src(const char *path);              /* NULL on failure, free with gz_src_free */
char   *gz_posix_utf8(const gzch *w);                     /* malloc'ed UTF-8 copy  */
gzch   *gz_posix_wide(const char *s);                     /* malloc'ed UTF-16 copy */
int     gz_posix_open_volume(void *user, const gzch *name, gz_src **out);   /* gz_open_opts.open_volume */

#endif
