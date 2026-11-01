/*
 * 고깃ZIP - CPU feature detection & kernel dispatch
 *
 * Every SIMD kernel is compiled with a GCC target attribute, so the binary
 * itself only requires an i586 (Pentium) CPU. At start-up we probe CPUID and
 * the OS register-state mask (XGETBV) and pick the fastest kernels:
 *
 *   AVX/AVX2 kernels are only chosen when the OS saves YMM state, which on
 *   Windows means Windows 7 SP1 or newer. Older systems (2000/XP/Vista) still
 *   get MMX/SSE/SSE2/SSE4.1/PCLMULQDQ/AES-NI kernels when the CPU has them.
 */
#include "cpu.h"
#include "crc32.h"
#include "inflate.h"
#include "crypto.h"

#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#endif

gz_cpu_info g_cpu;

static int cpuid(u32 leaf, u32 sub, u32 r[4])
{
#if defined(__i386__) || defined(__x86_64__)
    return __get_cpuid_count(leaf, sub, &r[0], &r[1], &r[2], &r[3]);
#else
    (void)leaf; (void)sub; r[0] = r[1] = r[2] = r[3] = 0; return 0;
#endif
}

static u64 xgetbv0(void)
{
#if defined(__i386__) || defined(__x86_64__)
    u32 lo, hi;
    __asm__ volatile(".byte 0x0f, 0x01, 0xd0" : "=a"(lo), "=d"(hi) : "c"(0));
    return ((u64)hi << 32) | lo;
#else
    return 0;
#endif
}

static void trim_brand(char *s)
{
    char *p = s, *d = s;
    while (*p == ' ') p++;
    while (*p) {
        if (*p == ' ' && (p[1] == ' ' || p[1] == 0)) { p++; continue; }
        *d++ = *p++;
    }
    *d = 0;
}

void gz_cpu_detect(void)
{
    u32 r[4], maxleaf, maxext, f = 0;
    __builtin_memset(&g_cpu, 0, sizeof(g_cpu));

    if (!cpuid(0, 0, r)) {          /* no CPUID: i486 or older */
        g_cpu.tier = g_cpu.active = GZ_TIER_X86;
        __builtin_memcpy(g_cpu.brand, "x86", 4);
        return;
    }
    f |= CPUF_CPUID;
    maxleaf = r[0];
    __builtin_memcpy(g_cpu.vendor + 0, &r[1], 4);
    __builtin_memcpy(g_cpu.vendor + 4, &r[3], 4);
    __builtin_memcpy(g_cpu.vendor + 8, &r[2], 4);
    g_cpu.vendor[12] = 0;

    if (maxleaf >= 1) {
        cpuid(1, 0, r);
        u32 ecx = r[2], edx = r[3];
        g_cpu.stepping = r[0] & 15;
        g_cpu.model = (r[0] >> 4) & 15;
        g_cpu.family = (r[0] >> 8) & 15;
        if (g_cpu.family == 15) g_cpu.family += (r[0] >> 20) & 0xff;
        if (g_cpu.family >= 6) g_cpu.model |= ((r[0] >> 16) & 15) << 4;

        if (edx & (1u << 15)) f |= CPUF_CMOV;
        if (edx & (1u << 23)) f |= CPUF_MMX;
        if (edx & (1u << 25)) f |= CPUF_SSE;
        if (edx & (1u << 26)) f |= CPUF_SSE2;
        if (ecx & (1u << 0))  f |= CPUF_SSE3;
        if (ecx & (1u << 1))  f |= CPUF_PCLMUL;
        if (ecx & (1u << 9))  f |= CPUF_SSSE3;
        if (ecx & (1u << 19)) f |= CPUF_SSE41;
        if (ecx & (1u << 20)) f |= CPUF_SSE42;
        if (ecx & (1u << 23)) f |= CPUF_POPCNT;
        if (ecx & (1u << 25)) f |= CPUF_AESNI;

        int os_ymm = 0, os_zmm = 0;
        if ((ecx & (1u << 27)) && (ecx & (1u << 28))) {   /* OSXSAVE + AVX */
            u64 xcr0 = xgetbv0();
            f |= CPUF_AVX_HW;
            os_ymm = (xcr0 & 6) == 6;                    /* XMM + YMM state */
            os_zmm = (xcr0 & 0xe6) == 0xe6;              /* + opmask/ZMM    */
        } else if (ecx & (1u << 28)) {
            f |= CPUF_AVX_HW;
        }
        if (os_ymm) f |= CPUF_AVX;

        if (maxleaf >= 7) {
            cpuid(7, 0, r);
            u32 ebx7 = r[1], ecx7 = r[2];
            if (ebx7 & (1u << 3)) f |= CPUF_BMI1;
            if (ebx7 & (1u << 8)) f |= CPUF_BMI2;
            if (ebx7 & (1u << 29)) f |= CPUF_SHA;
            if (os_ymm) {
                if (ebx7 & (1u << 5)) f |= CPUF_AVX2;
                if (ecx7 & (1u << 10)) f |= CPUF_VPCLMUL;
                if (ecx7 & (1u << 9)) f |= CPUF_VAES;
            }
            if (os_zmm && (ebx7 & (1u << 16)) && (ebx7 & (1u << 30)) && (ebx7 & (1u << 31)))
                f |= CPUF_AVX512;
        }
    }

    cpuid(0x80000000u, 0, r);
    maxext = r[0];
    if (maxext >= 0x80000004u) {
        u32 *b = (u32 *)g_cpu.brand;
        cpuid(0x80000002u, 0, b + 0);
        cpuid(0x80000003u, 0, b + 4);
        cpuid(0x80000004u, 0, b + 8);
        g_cpu.brand[48] = 0;
        trim_brand(g_cpu.brand);
    }
    if (!g_cpu.brand[0]) __builtin_memcpy(g_cpu.brand, g_cpu.vendor, 13);

    g_cpu.features = f;
    int t = GZ_TIER_X86;
    if (f & CPUF_MMX) t = GZ_TIER_MMX;
    if (f & CPUF_SSE) t = GZ_TIER_SSE;
    if (f & CPUF_SSE2) t = GZ_TIER_SSE2;
    if ((f & CPUF_SSE41) && (f & CPUF_SSSE3)) t = GZ_TIER_SSE41;
    if (f & CPUF_AVX) t = GZ_TIER_AVX;
    if ((f & CPUF_AVX2) && (f & CPUF_BMI2) && (f & CPUF_BMI1)) t = GZ_TIER_AVX2;
#ifdef __x86_64__
    if (t < GZ_TIER_SSE2) t = GZ_TIER_SSE2;   /* architectural baseline */
#endif
    g_cpu.tier = g_cpu.active = t;
}

int gz_cpu_tier_supported(int tier)
{
#ifdef __x86_64__
    if (tier < GZ_TIER_SSE2) return 0;
#endif
    return tier >= 0 && tier <= g_cpu.tier;
}

const char *gz_tier_name(int tier)
{
    static const char *names[GZ_TIER_COUNT] = {
        "x86", "MMX", "SSE", "SSE2", "SSE4.1", "AVX", "AVX2"
    };
    if (tier < 0 || tier >= GZ_TIER_COUNT) return "?";
    return names[tier];
}

/* ---- kernel selection ------------------------------------------------- */

static const char *s_inf_name = "x86";
static const char *s_crc_name = "Slice-by-8";
static const char *s_aes_name = "AES (T-table)";

int gz_dispatch_init(int force)
{
    int t = g_cpu.tier;
    if (force >= 0 && force < t) t = force;
#ifdef __x86_64__
    if (t < GZ_TIER_SSE2) t = GZ_TIER_SSE2;
#endif
    g_cpu.active = t;
    u32 f = g_cpu.features;

    /* Inflate kernel */
    switch (t) {
#ifdef __i386__
    case GZ_TIER_X86:   gz_inflate_kernel = gz_inflate_x86;  s_inf_name = "x86";       break;
    case GZ_TIER_MMX:   gz_inflate_kernel = gz_inflate_mmx;  s_inf_name = "MMX";       break;
    case GZ_TIER_SSE:   gz_inflate_kernel = gz_inflate_sse;  s_inf_name = "SSE";       break;
#endif
    case GZ_TIER_SSE2:
    case GZ_TIER_SSE41: gz_inflate_kernel = gz_inflate_sse2; s_inf_name = "SSE2";      break;
    case GZ_TIER_AVX:   gz_inflate_kernel = gz_inflate_avx;  s_inf_name = "AVX";       break;
    default:            gz_inflate_kernel = gz_inflate_avx2; s_inf_name = "AVX2+BMI2"; break;
    }

    /* CRC-32 kernel */
    gz_crc32_kernel = gz_crc32_slice8; s_crc_name = "Slice-by-8";
    if (t >= GZ_TIER_SSE41 && (f & CPUF_PCLMUL)) {
        gz_crc32_kernel = gz_crc32_pclmul; s_crc_name = "PCLMULQDQ";
    }
    if (t >= GZ_TIER_AVX && (f & CPUF_PCLMUL)) {
        gz_crc32_kernel = gz_crc32_avx; s_crc_name = "AVX+PCLMULQDQ";
    }
    if (t >= GZ_TIER_AVX2 && (f & CPUF_VPCLMUL)) {
        gz_crc32_kernel = gz_crc32_vpclmul; s_crc_name = "VPCLMULQDQ";
    }

    /* AES kernel (WinZip AES archives) */
    gz_aes_ctr_kernel = gz_aes_ctr_soft; s_aes_name = "AES (T-table)";
    if (t >= GZ_TIER_SSE41 && (f & CPUF_AESNI)) {
        gz_aes_ctr_kernel = gz_aes_ctr_aesni; s_aes_name = "AES-NI";
    }
    if (t >= GZ_TIER_AVX && (f & CPUF_AESNI)) {
        gz_aes_ctr_kernel = gz_aes_ctr_aesni_avx; s_aes_name = "AES-NI (AVX)";
    }
    return t;
}

const char *gz_dispatch_inflate_name(void) { return s_inf_name; }
const char *gz_dispatch_crc_name(void) { return s_crc_name; }
const char *gz_dispatch_aes_name(void) { return s_aes_name; }
