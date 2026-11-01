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
#include "crc64.h"
#include "blake2.h"
#include "sha256.h"

#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#endif
#if defined(__aarch64__) && defined(__linux__)
#include <sys/auxv.h>
#endif

gz_cpu_info g_cpu;

__attribute__((unused)) static int cpuid(u32 leaf, u32 sub, u32 r[4])
{
#if defined(__i386__) || defined(__x86_64__)
    return __get_cpuid_count(leaf, sub, &r[0], &r[1], &r[2], &r[3]);
#else
    (void)leaf; (void)sub; r[0] = r[1] = r[2] = r[3] = 0; return 0;
#endif
}

__attribute__((unused)) static u64 xgetbv0(void)
{
#if defined(__i386__) || defined(__x86_64__)
    u32 lo, hi;
    __asm__ volatile(".byte 0x0f, 0x01, 0xd0" : "=a"(lo), "=d"(hi) : "c"(0));
    return ((u64)hi << 32) | lo;
#else
    return 0;
#endif
}

__attribute__((unused)) static void trim_brand(char *s)
{
    char *p = s, *d = s;
    while (*p == ' ') p++;
    while (*p) {
        if (*p == ' ' && (p[1] == ' ' || p[1] == 0)) { p++; continue; }
        *d++ = *p++;
    }
    *d = 0;
}

#if defined(__aarch64__)
void gz_cpu_detect(void)
{
    __builtin_memset(&g_cpu, 0, sizeof(g_cpu));
    u32 f = CPUF_NEON;
#if defined(__APPLE__)
    /* every Apple Silicon core has the ARMv8 crypto and CRC extensions */
    f |= CPUF_ARM_CRC32 | CPUF_ARM_PMULL | CPUF_ARM_AES | CPUF_ARM_SHA1 | CPUF_ARM_SHA2;
    __builtin_memcpy(g_cpu.brand, "Apple Silicon", 14);
#elif defined(__linux__)
    unsigned long hw = getauxval(AT_HWCAP);
    if (hw & (1ul << 7)) f |= CPUF_ARM_CRC32;   /* HWCAP_CRC32 */
    if (hw & (1ul << 4)) f |= CPUF_ARM_PMULL;   /* HWCAP_PMULL */
    if (hw & (1ul << 3)) f |= CPUF_ARM_AES;     /* HWCAP_AES   */
    if (hw & (1ul << 5)) f |= CPUF_ARM_SHA1;    /* HWCAP_SHA1  */
    if (hw & (1ul << 6)) f |= CPUF_ARM_SHA2;    /* HWCAP_SHA2  */
    __builtin_memcpy(g_cpu.brand, "ARM64", 6);
#else
    __builtin_memcpy(g_cpu.brand, "ARM64", 6);
#endif
    __builtin_memcpy(g_cpu.vendor, "ARM", 4);
    g_cpu.features = f;
    g_cpu.tier = g_cpu.active = 0;
}
#else
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
#endif

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
#if defined(__aarch64__)
    return tier == 0 ? "NEON" : "?";
#endif
    return names[tier];
}

/* ---- kernel selection ------------------------------------------------- */

static const char *s_inf_name = "x86";
static const char *s_crc_name = "Slice-by-8";
static const char *s_aes_name = "AES (T-table)";
static const char *s_sha_name = "SHA (C)";
static const char *s_crc64_name = "Slice-by-8";
static const char *s_b2_name = "BLAKE2sp (C)";

/* portable kernels everywhere first; the faster ones replace them below */
static void dispatch_portable(void)
{
    gz_crc32_kernel = gz_crc32_slice8;         s_crc_name = "Slice-by-8";
    gz_crc64_kernel = gz_crc64_slice8;         s_crc64_name = "Slice-by-8";
    gz_sha1_kernel = gz_sha1_blocks_c;
    gz_sha256_kernel = gz_sha256_blocks_c;     s_sha_name = "SHA (C)";
    gz_aes_ctr_kernel = gz_aes_ctr_soft;
    gz_aes_ecb_enc_kernel = gz_aes_ecb_enc_soft;
    gz_aes_ecb_dec_kernel = gz_aes_ecb_dec_soft;
    gz_aes_cbc_enc_kernel = gz_aes_cbc_enc_soft;
    gz_aes_cbc_dec_kernel = gz_aes_cbc_dec_soft; s_aes_name = "AES (T-table)";
    gz_blake2sp_kernel = gz_blake2sp_c;        s_b2_name = "BLAKE2sp (C)";
}

int gz_dispatch_init(int force)
{
    int t = g_cpu.tier;
    if (force >= 0 && force < t) t = force;
#ifdef __x86_64__
    if (t < GZ_TIER_SSE2) t = GZ_TIER_SSE2;
#endif
    g_cpu.active = t;
    u32 f = g_cpu.features;
    dispatch_portable();
#if defined(__aarch64__)
    /* AArch64: one tier; the CPUF_ARM_* bits pick the kernels (tests may clear
     * bits in g_cpu.features to force the portable paths). */
    gz_inflate_kernel = gz_inflate_neon; s_inf_name = "NEON";
    gz_blake2sp_kernel = gz_blake2sp_neon; s_b2_name = "BLAKE2sp (NEON)";
    if (f & CPUF_ARM_CRC32) {
        gz_crc32_kernel = gz_crc32_arm; s_crc_name = "ARMv8 CRC32";
        if (f & CPUF_ARM_PMULL) { gz_crc32_kernel = gz_crc32_pmull; s_crc_name = "PMULL+CRC32"; }
    }
    if (f & CPUF_ARM_PMULL) { gz_crc64_kernel = gz_crc64_pmull; s_crc64_name = "PMULL"; }
    if (f & CPUF_ARM_SHA1) gz_sha1_kernel = gz_sha1_blocks_arm;
    if (f & CPUF_ARM_SHA2) gz_sha256_kernel = gz_sha256_blocks_arm;
    if (f & (CPUF_ARM_SHA1 | CPUF_ARM_SHA2))
        s_sha_name = (f & CPUF_ARM_SHA1) && (f & CPUF_ARM_SHA2) ? "ARMv8 SHA" :
                     (f & CPUF_ARM_SHA2) ? "ARMv8 SHA2" : "ARMv8 SHA1";
    if (f & CPUF_ARM_AES) {
        gz_aes_ctr_kernel = gz_aes_ctr_arm;
        gz_aes_ecb_enc_kernel = gz_aes_ecb_enc_arm;
        gz_aes_ecb_dec_kernel = gz_aes_ecb_dec_arm;
        gz_aes_cbc_enc_kernel = gz_aes_cbc_enc_arm;
        gz_aes_cbc_dec_kernel = gz_aes_cbc_dec_arm;
        s_aes_name = "ARMv8 AES";
    }
    return 0;
#else

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

    /* CRC-32 / CRC-64 */
    if (t >= GZ_TIER_SSE41 && (f & CPUF_PCLMUL)) {
        gz_crc32_kernel = gz_crc32_pclmul; s_crc_name = "PCLMULQDQ";
        gz_crc64_kernel = gz_crc64_pclmul; s_crc64_name = "PCLMULQDQ";
    }
    if (t >= GZ_TIER_AVX && (f & CPUF_PCLMUL)) {
        gz_crc32_kernel = gz_crc32_avx; s_crc_name = "AVX+PCLMULQDQ";
    }
    if (t >= GZ_TIER_AVX2 && (f & CPUF_VPCLMUL) && (f & CPUF_PCLMUL)) {
        gz_crc32_kernel = gz_crc32_vpclmul; s_crc_name = "VPCLMULQDQ";
        gz_crc64_kernel = gz_crc64_vpclmul; s_crc64_name = "VPCLMULQDQ";
    }

    /* SHA-1 / SHA-256 */
    if (t >= GZ_TIER_SSE41 && (f & CPUF_SHA)) {
        gz_sha1_kernel = gz_sha1_blocks_shani;
        gz_sha256_kernel = gz_sha256_blocks_shani;
        s_sha_name = "SHA-NI";
    }

    /* AES (WinZip CTR, 7z/RAR CBC) */
    if (t >= GZ_TIER_SSE41 && (f & CPUF_AESNI)) {
        gz_aes_ctr_kernel = gz_aes_ctr_aesni;
        gz_aes_ecb_enc_kernel = gz_aes_ecb_enc_aesni;
        gz_aes_ecb_dec_kernel = gz_aes_ecb_dec_aesni;
        gz_aes_cbc_enc_kernel = gz_aes_cbc_enc_aesni;
        gz_aes_cbc_dec_kernel = gz_aes_cbc_dec_aesni;
        s_aes_name = "AES-NI";
    }
    if (t >= GZ_TIER_AVX && (f & CPUF_AESNI)) {
        gz_aes_ctr_kernel = gz_aes_ctr_aesni_avx;
        gz_aes_ecb_enc_kernel = gz_aes_ecb_enc_avx;
        gz_aes_ecb_dec_kernel = gz_aes_ecb_dec_avx;
        gz_aes_cbc_enc_kernel = gz_aes_cbc_enc_avx;
        gz_aes_cbc_dec_kernel = gz_aes_cbc_dec_avx;
        s_aes_name = "AES-NI (AVX)";
    }
    if (t >= GZ_TIER_AVX2 && (f & CPUF_AESNI) && (f & CPUF_VAES)) {
        gz_aes_ctr_kernel = gz_aes_ctr_vaes;
        gz_aes_cbc_dec_kernel = gz_aes_cbc_dec_vaes;
        s_aes_name = "VAES";
    }

    /* BLAKE2sp (RAR 5.0 checksums) */
    if (t >= GZ_TIER_SSE2) { gz_blake2sp_kernel = gz_blake2sp_sse2; s_b2_name = "BLAKE2sp (SSE2)"; }
    if (t >= GZ_TIER_SSE41) { gz_blake2sp_kernel = gz_blake2sp_ssse3; s_b2_name = "BLAKE2sp (SSSE3)"; }
    if (t >= GZ_TIER_AVX2) { gz_blake2sp_kernel = gz_blake2sp_avx2; s_b2_name = "BLAKE2sp (AVX2)"; }
    return t;
#endif
}

const char *gz_dispatch_inflate_name(void) { return s_inf_name; }
const char *gz_dispatch_crc_name(void) { return s_crc_name; }
const char *gz_dispatch_aes_name(void) { return s_aes_name; }
const char *gz_dispatch_sha_name(void) { return s_sha_name; }
const char *gz_dispatch_crc64_name(void) { return s_crc64_name; }
const char *gz_dispatch_blake2_name(void) { return s_b2_name; }
