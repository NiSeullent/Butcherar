/*
 * 고깃ZIP - CPU feature detection and runtime dispatch
 */
#ifndef GZ_CPU_H
#define GZ_CPU_H

#include "base.h"

/* Raw CPU features (CPUID + OS state via XGETBV). */
enum {
    CPUF_CPUID   = 1u << 0,
    CPUF_MMX     = 1u << 1,
    CPUF_CMOV    = 1u << 2,
    CPUF_SSE     = 1u << 3,
    CPUF_SSE2    = 1u << 4,
    CPUF_SSE3    = 1u << 5,
    CPUF_SSSE3   = 1u << 6,
    CPUF_SSE41   = 1u << 7,
    CPUF_SSE42   = 1u << 8,
    CPUF_POPCNT  = 1u << 9,
    CPUF_PCLMUL  = 1u << 10,
    CPUF_AESNI   = 1u << 11,
    CPUF_AVX     = 1u << 12,   /* CPU has AVX AND the OS saves YMM (Win7 SP1+) */
    CPUF_AVX2    = 1u << 13,
    CPUF_BMI1    = 1u << 14,
    CPUF_BMI2    = 1u << 15,
    CPUF_VPCLMUL = 1u << 16,   /* 256-bit carry-less multiply (Ice Lake/Zen3+) */
    CPUF_VAES    = 1u << 17,
    CPUF_SHA     = 1u << 18,
    CPUF_AVX512  = 1u << 19,   /* F+BW+VL and OS saves ZMM */
    CPUF_AVX_HW  = 1u << 20    /* CPU has AVX but OS may not enable it */
};

/* Dispatch tiers, lowest to highest. */
enum {
    GZ_TIER_X86 = 0,     /* i586 integer code                  */
    GZ_TIER_MMX,         /* Pentium MMX / Pentium II           */
    GZ_TIER_SSE,         /* Pentium III / Athlon XP            */
    GZ_TIER_SSE2,        /* Pentium 4 / Athlon 64              */
    GZ_TIER_SSE41,       /* Core 2 Penryn / Westmere (+PCLMUL) */
    GZ_TIER_AVX,         /* Sandy Bridge, Windows 7 SP1+       */
    GZ_TIER_AVX2,        /* Haswell+ (AVX2 + BMI2)             */
    GZ_TIER_COUNT
};

typedef struct {
    u32  features;
    int  tier;           /* best tier the machine supports              */
    int  active;         /* tier currently in use (may be forced lower) */
    u32  family, model, stepping;
    char vendor[13];
    char brand[49];
} gz_cpu_info;

extern gz_cpu_info g_cpu;

void        gz_cpu_detect(void);
int         gz_cpu_tier_supported(int tier);
const char *gz_tier_name(int tier);     /* "AVX2", "SSE2", ... */

/* Select implementations for a tier (<= g_cpu.tier). Returns tier applied. */
int gz_dispatch_init(int force_tier);   /* force_tier < 0 = automatic */

/* Human readable description of selected kernels, e.g. "AVX2+BMI2 / VPCLMULQDQ / AES-NI". */
const char *gz_dispatch_inflate_name(void);
const char *gz_dispatch_crc_name(void);
const char *gz_dispatch_aes_name(void);

#endif
