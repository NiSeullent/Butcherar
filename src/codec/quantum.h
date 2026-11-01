/*
 * 고깃ZIP - Quantum decoder (CAB folder type 2)
 *
 * Quantum (David Stafford, used by Microsoft's early cabinet tools) is an LZ77
 * coder with adaptive arithmetic coding. A CAB folder is one stream of 32 KiB
 * frames, one per CFDATA block: the models and the window carry over, the
 * arithmetic coder restarts at every frame and the bytes after a frame's last
 * symbol (0..4 padding bytes) are ignored.
 *
 *   d = gz_qtm_new(window_bits);          window_bits = (typeCompress >> 8) & 0x1f, 10..21
 *   gz_qtm_reset(d);                      at the start of a folder
 *   gz_qtm_decode_frame(d, data, cbData, out, cbUncomp);   for each CFDATA block
 */
#ifndef GZ_QUANTUM_H
#define GZ_QUANTUM_H
#include "base.h"

#define GZ_QTM_FRAME 32768u

typedef struct gz_qtm_dec gz_qtm_dec;

gz_qtm_dec *gz_qtm_new(u32 window_bits);          /* NULL: bad window bits or no memory */
void gz_qtm_free(gz_qtm_dec *d);
int  gz_qtm_init(gz_qtm_dec *d, u32 window_bits); /* reconfigure + reset (GZ_E_METHOD, GZ_E_NOMEM) */
void gz_qtm_reset(gz_qtm_dec *d);                 /* new stream: models, window */
/* One frame of out_n (1..32768) bytes from in[0..in_n). GZ_OK or GZ_E_DATA (then reset). */
int  gz_qtm_decode_frame(gz_qtm_dec *d, const u8 *in, u32 in_n, u8 *out, u32 out_n);

#endif
