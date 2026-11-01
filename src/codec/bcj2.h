/*
 * 고깃ZIP - BCJ2 decoder (7z method 03 03 01 1B)
 *
 * BCJ2 is 7-Zip's 4-stream x86 branch converter. In a .7z folder the BCJ2
 * coder has four inputs and one output:
 *
 *   input 0  MAIN  the code with the 4-byte operands of converted CALL/JMP/Jcc
 *                  removed (usually the output of an LZMA coder)
 *   input 1  CALL  big-endian absolute targets of converted E8 calls
 *   input 2  JUMP  big-endian absolute targets of converted E9 / 0F 8x jumps
 *   input 3  RC    range coder bits: one per marker byte (E8, E9, 0F 8x) in MAIN,
 *                  1 = "the next 4 bytes come from CALL/JUMP"
 *   output         the original x86 code; a converted operand is written as
 *                  (target - offset of the next instruction), offsets counted
 *                  from 0 at the start of the output.
 *
 * API (push MAIN, pull CALL/JUMP/RC, push output):
 *
 *   gz_bcj2_dec *b = gz_bcj2_dec_new();
 *   gz_bcj2_dec_init(b, &call_io, &jump_io, &rc_io, out_size, sink, sink_ctx);
 *       call_io/jump_io/rc_io: readers (only ->read and ->ctx are used); the 7z
 *       reader usually decodes CALL and JUMP to memory first and reads them with
 *       gz_bcj2_mem_read; RC is normally stored. They must stay valid until finish.
 *       out_size: the BCJ2 coder's unpack size (GZ_SIZE_UNKNOWN: until MAIN ends).
 *   then feed MAIN: gz_bcj2_dec_write(b, p, n) as often as needed - usable directly
 *       as the gz_stream_io.write of the MAIN decoder (ctx = b);
 *   r = gz_bcj2_dec_finish(b);      flushes the output, checks the size
 *   gz_bcj2_dec_free(b);            (or reuse with another init)
 *
 * Decoding stops after out_size bytes; MAIN bytes beyond that are ignored.
 * Errors: GZ_E_DATA (bad RC start, CALL/JUMP/RC stream too short, output shorter
 * than out_size), read errors, and sink errors (returned unchanged; also from
 * every later write/finish call).
 */
#ifndef GZ_BCJ2_H
#define GZ_BCJ2_H
#include "base.h"
#include "stream.h"

typedef struct gz_bcj2_dec gz_bcj2_dec;

gz_bcj2_dec *gz_bcj2_dec_new(void);
void gz_bcj2_dec_free(gz_bcj2_dec *d);

int gz_bcj2_dec_init(gz_bcj2_dec *d, const gz_stream_io *call, const gz_stream_io *jump,
                     const gz_stream_io *rc, u64 out_size,
                     int (*sink)(void *ctx, const u8 *p, size_t n), void *sink_ctx);
int gz_bcj2_dec_write(void *ctx, const u8 *p, size_t n);
int gz_bcj2_dec_finish(gz_bcj2_dec *d);

/* Simple memory reader for the CALL/JUMP/RC inputs:
 *   gz_bcj2_mem m = { data, size };  gz_stream_io io = { gz_bcj2_mem_read, 0, &m }; */
typedef struct gz_bcj2_mem { const u8 *p; size_t n; } gz_bcj2_mem;
int gz_bcj2_mem_read(void *ctx, u8 *buf, u32 cap, u32 *got);

#endif
