/*
 * 고깃ZIP - Apple Data Compression (ADC) decoder, used by DMG (UDCO) chunks
 */
#ifndef GZ_ADC_H
#define GZ_ADC_H
#include "base.h"

/* Decode one ADC chunk from in[0..in_n) into out[0..out_cap).
 * The stream has no terminator: decoding stops when the input is used up or the
 * output is full (a run that crosses out_cap is cut there). *out_n = bytes written,
 * *in_used (optional) = input bytes consumed.
 * GZ_OK, GZ_E_DATA (distance before the start of the output), GZ_E_TRUNC (input ends
 * inside an instruction). */
int gz_adc_decode(const u8 *in, size_t in_n, u8 *out, size_t out_cap, size_t *out_n, size_t *in_used);

#endif
