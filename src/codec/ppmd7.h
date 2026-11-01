/*
 * 고깃ZIP - PPMd var.H ("Ppmd7"): 7z method 03 04 01 (decoder + encoder) and the
 * symbol-level decoder used by RAR 3.x.
 *
 * The model is Shkarin's PPMd var.H exactly as in 7-Zip's Ppmd7 (sub-allocator, SEE,
 * binary contexts, restart when the memory block is exhausted), so streams decode
 * byte-identically with 7-Zip. Two range coders drive it:
 *   7z : 7-Zip's LZMA-style range coder (first byte 0, 32-bit code, Range >= 2^24)
 *   RAR: Subbotin's carry-less range coder as used by RAR 3.x (Ppmd7a in 7-Zip)
 */
#ifndef GZ_PPMD7_H
#define GZ_PPMD7_H
#include "ppmd.h"

#define GZ_PPMD7_MIN_ORDER 2
#define GZ_PPMD7_MAX_ORDER 64
#define GZ_PPMD7_MIN_MEM   (1u << 11)
#define GZ_PPMD7_MAX_MEM   (0xFFFFFFFFu - 12 * 3)   /* format maximum; we allocate up to GZ_PPMD_MEM_CAP */

gz_ppmd7 *gz_ppmd7_new(void);          /* tables only; the model block is allocated on use */
void gz_ppmd7_free(gz_ppmd7 *p);

/* Parse 7z coder properties (5 bytes: order, LE32 memory size).
 * GZ_E_FORMAT if n < 5, GZ_E_METHOD if order or size are outside the format range. */
int gz_ppmd7z_props(const u8 *props, u32 n, u32 *order, u32 *mem);

/* 7z decoder. Pulls the packed stream with io->read, pushes output with io->write.
 * out_size: exact unpacked size (decoding stops there; the range coder must then be
 * exactly finished, or an end marker must follow), or GZ_SIZE_UNKNOWN (the stream must
 * end with an end marker). The model block is kept and reused when mem is unchanged.
 * Returns GZ_OK, GZ_E_DATA (corrupt), GZ_E_TRUNC (input ends early), GZ_E_METHOD (bad
 * order/mem), GZ_E_LIMIT (mem above GZ_PPMD_MEM_CAP), GZ_E_NOMEM, or a callback error.
 * *in_used (optional) receives the number of packed bytes consumed. */
int gz_ppmd7z_decode(gz_ppmd7 *p, u32 order, u32 mem, const gz_stream_io *io, u64 out_size);
int gz_ppmd7z_decode_ex(gz_ppmd7 *p, u32 order, u32 mem, const gz_stream_io *io, u64 out_size,
                        u64 *in_used);

/* 7z encoder: pulls raw input with io->read until got == 0, pushes the packed stream
 * with io->write (no end marker, like 7-Zip; the 7z header stores the size). The coder
 * properties to store are gz_ppmd7z_write_props(). order 2..64, mem 2 KiB..cap.
 * *in_size / *out_size (optional) receive the byte counts. */
int gz_ppmd7z_encode(gz_ppmd7 *p, u32 order, u32 mem, const gz_stream_io *io);
int gz_ppmd7z_encode_ex(gz_ppmd7 *p, u32 order, u32 mem, const gz_stream_io *io,
                        u64 *in_size, u64 *out_size);
void gz_ppmd7z_write_props(u8 props[5], u32 order, u32 mem);
/* 7-Zip's parameters for level 0..9 (5 = default) and the input size (GZ_SIZE_UNKNOWN if
 * unknown): order {3,4,4,5,5,6,8,16,24,32}[level], mem 1 << (level + 19), reduced to the
 * smallest power of two m >= 64 KiB with size <= m / 16 for small inputs. */
void gz_ppmd7z_level(int level, u64 size, u32 *order, u32 *mem);

/* ---------------- RAR 3.x (symbol level) ----------------
 *
 * RAR 3.x interleaves PPMd and LZ blocks in one bit stream and handles the escape
 * character itself, so the RAR decoder drives the model symbol by symbol. 7-Zip's
 * Rar3Decoder::InitPPM()/DecodePPM() are the reference; the RAR decoder must do this:
 *
 *   PPM block start (after ReadTables found the PPM flag bit, bit stream byte-aligned):
 *     flags = 7 bits; reset = flags & 0x20
 *     if reset: maxMB = next 8 bits            (else: fail if no model or after an error)
 *     if flags & 0x40: escChar = next 8 bits   (initially 2, persists across blocks)
 *     gz_ppmd7_rar_rc_init(p, in)              -- reads the next 4 bytes of the stream
 *     if reset:
 *         order = (flags & 0x1F) + 1; if (order > 16) order = 16 + (order - 16) * 3;
 *         if (order == 1) -> data error (and drop the model: gz_ppmd7_rar_drop)
 *         gz_ppmd7_rar_model(p, order, (maxMB + 1) << 20)   -- GZ_OK or error
 *     The range decoder is re-initialised at every PPM block start, also when the model
 *     continues (no reset): model and range coder are independent.
 *
 *   Each symbol: c = gz_ppmd7_rar_decode(p)
 *     c < 0  : data error (GZ_PPMD_SYM_END is an error in RAR too). The model is then
 *              unusable until the next reset; gz_ppmd7_rar_decode keeps returning
 *              GZ_PPMD_SYM_ERROR and gz_ppmd7_rar_ready() is 0.
 *     c != escChar: literal byte c
 *     c == escChar: n = gz_ppmd7_rar_decode(p);
 *         n == 0: end of PPM block -> ReadTables (next block may be LZ or PPM)
 *         n == 2: end of file (of this solid entry)
 *         n == 3: RAR VM filter code, its bytes decoded as PPM symbols
 *         n == 4: match: 3 symbols = distance - 2 (big-endian), 1 symbol = length - 32
 *         n == 5: match at distance 1, 1 symbol = length - 4
 *                 (unrar: CopyString(c + 32, d + 2) / CopyString(c + 4, 1))
 *         other : literal escChar
 *   Also check in->extra / in->err as needed: reading past the end of the packed data
 *   yields zero bytes and counts them in in->extra.
 *
 * The byte reader `in` must stay valid while symbols are decoded; the RAR decoder can
 * point in->cur/end straight at its input buffer when its bit reader is byte-aligned
 * and holds no prefetched bits, or deliver every byte through refill().
 *
 * Range decoder differences from 7z: no leading zero byte, Low is tracked and the
 * normaliser is Subbotin's carry-less one (Range kept in [2^15, 2^32)), a binary-
 * context escape sets Range = (Range & ~(BIN_SCALE - 1)) - size0, and a frequency sum
 * larger than Range is a data error (7z's Range >= 2^24 makes that impossible). */
int  gz_ppmd7_rar_model(gz_ppmd7 *p, u32 max_order, u32 mem);  /* alloc (reuse) + restart */
void gz_ppmd7_rar_rc_init(gz_ppmd7 *p, gz_ppmd_in *in);
int  gz_ppmd7_rar_decode(gz_ppmd7 *p);                         /* 0..255 or < 0 */
int  gz_ppmd7_rar_ready(const gz_ppmd7 *p);                    /* model usable */
void gz_ppmd7_rar_drop(gz_ppmd7 *p);                           /* forget the model (error) */

/* Test helpers (unused by the readers; --gc-sections drops them from the apps).
 * RAR-variant encoder over the same model: begin (alloc + restart), one call per symbol
 * (0..255; -1 codes the end marker), end (flushes 4 bytes). Escape handling is up to
 * the caller, as in RAR. Returns GZ_E_DATA if a frequency total exceeded Range. */
int  gz_ppmd7_rar_enc_begin(gz_ppmd7 *p, u32 max_order, u32 mem, const gz_stream_io *io);
int  gz_ppmd7_rar_enc_begin_rc(gz_ppmd7 *p, const gz_stream_io *io);  /* new block, same model */
int  gz_ppmd7_rar_enc_symbol(gz_ppmd7 *p, int sym);
int  gz_ppmd7_rar_enc_end(gz_ppmd7 *p);
/* Runs n seeded pseudo-random valid operations on the RAR range decoder (initialised
 * from in) and reports each: rec = {op (0 freq, 1 binary, 2 count >= total),
 * total | prob, start << 16 | size, count | bit, Range, Code (relative to Low), Low,
 * extra}. Lets tests replay the decoder against an independent reference. */
void gz_ppmd7_rar_rc_test(gz_ppmd7 *p, gz_ppmd_in *in, u32 seed, u32 n,
                          void (*cb)(void *user, const u32 rec[8]), void *user);

#endif
