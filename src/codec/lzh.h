/*
 * 고깃ZIP - LZH family decoders (LHA / LArc / ARJ / MS-DOS compress)
 *
 *   GZ_LZH_LH1     LHarc -lh1-: 4 KiB window, adaptive Huffman (LZHUF)
 *   GZ_LZH_LH4..7  LHA -lh4- -lh5- -lh6- -lh7-: static Huffman blocks,
 *                  4 / 8 / 32 / 64 KiB windows
 *   GZ_LZH_LZS     LArc -lzs-: 2 KiB LZSS, bit oriented
 *   GZ_LZH_LZ5     LArc / LHarc -lz5-: 4 KiB LZSS, flag bytes, preset dictionary
 *   GZ_LZH_ARJ     ARJ methods 1-3 (static Huffman, 26 KiB window)
 *   GZ_LZH_ARJ4    ARJ method 4 ("fastest", unary-prefixed lengths/positions)
 *   GZ_LZH_SZDD    MS compress.exe "SZDD" LZSS (window position 4096-16)
 *   GZ_LZH_SZQB    QBasic 4.5 "SZ" and KWAJ method 2 (window position 4096-18)
 *   GZ_LZH_KWAJ    MS "KWAJ" method 3 (LZ + five Huffman tables, Jeff Johnson)
 *
 * Every method needs out_size (the formats store it); GZ_SIZE_UNKNOWN decodes
 * until the input runs out (KWAJ without a length field). History before the
 * first byte reads as the format defines (spaces for LHA/SZDD/KWAJ).
 */
#ifndef GZ_LZH_H
#define GZ_LZH_H
#include "base.h"
#include "stream.h"

enum {
    GZ_LZH_LH1 = 1, GZ_LZH_LH4, GZ_LZH_LH5, GZ_LZH_LH6, GZ_LZH_LH7,
    GZ_LZH_LZS, GZ_LZH_LZ5, GZ_LZH_ARJ, GZ_LZH_ARJ4,
    GZ_LZH_SZDD, GZ_LZH_SZQB, GZ_LZH_KWAJ
};

typedef struct gz_lzh_dec gz_lzh_dec;     /* ~1.2 MiB, reusable */

gz_lzh_dec *gz_lzh_dec_new(void);
void gz_lzh_dec_free(gz_lzh_dec *d);
/* create/destroy pair for gz_ctx_slot(c, GZ_SLOT_MISC4, ...): one address shared by
 * every format (ARJ, LZH, SZDD/KWAJ) so the cached decoder is reused between them */
void *gz_lzh_slot_new(void);
void  gz_lzh_slot_free(void *d);

/* Returns GZ_OK, GZ_E_DATA (bad tables / codes), GZ_E_TRUNC, GZ_E_METHOD
 * (unknown method) or a callback error. Output stops after out_size bytes. */
int gz_lzh_decode(gz_lzh_dec *d, const gz_stream_io *io, u64 out_size, int method);

/* CRC-16/ARC (poly 0xA001, reflected) as used by LHA, start with 0 */
u16 gz_crc16(u16 crc, const void *p, size_t n);

#endif
