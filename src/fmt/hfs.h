/*
 * 고깃ZIP - shared bits of the Apple readers (hfs.c, dmg.c)
 */
#ifndef GZ_HFS_H
#define GZ_HFS_H
#include "base.h"

/* Mac OS Roman bytes 0x80..0xFF as Unicode (classic HFS names, old DMG resource names) */
extern const u16 gz_macroman_hi[128];

#endif
