/*
 * 고깃ZIP - tiny C runtime replacement
 *
 * The program does not link msvcrt.dll or any other C runtime: it talks to
 * kernel32/user32/gdi32 directly. This file provides the handful of symbols
 * the compiler may emit (memcpy, memset, memmove, memcmp), the process entry
 * point and the allocation / code-page hooks used by the portable core.
 */
#include "app.h"
#include <wincrypt.h>

/* ---------------- compiler support ---------------- */

void *memcpy(void *d, const void *s, size_t n)
{
    void *ret = d;
#if defined(__x86_64__)
    size_t q = n >> 3, r = n & 7;
    __asm__ volatile("rep movsq" : "+D"(d), "+S"(s), "+c"(q) : : "memory");
    __asm__ volatile("rep movsb" : "+D"(d), "+S"(s), "+c"(r) : : "memory");
#else
    size_t q = n >> 2, r = n & 3;
    __asm__ volatile("rep movsl" : "+D"(d), "+S"(s), "+c"(q) : : "memory");
    __asm__ volatile("rep movsb" : "+D"(d), "+S"(s), "+c"(r) : : "memory");
#endif
    return ret;
}

void *memmove(void *d, const void *s, size_t n)
{
    u8 *dd = (u8 *)d;
    const u8 *ss = (const u8 *)s;
    if (dd <= ss || dd >= ss + n) return memcpy(d, s, n);
    /* overlapping, copy backwards */
    dd += n; ss += n;
    while (n >= 8) { dd -= 8; ss -= 8; u64 v; __builtin_memcpy(&v, ss, 8); __builtin_memcpy(dd, &v, 8); n -= 8; }
    while (n--) *--dd = *--ss;
    return d;
}

void *memset(void *d, int c, size_t n)
{
    void *ret = d;
#if defined(__x86_64__)
    u64 v = (u8)c * 0x0101010101010101ULL;
    size_t q = n >> 3, r = n & 7;
    __asm__ volatile("rep stosq" : "+D"(d), "+c"(q) : "a"(v) : "memory");
    __asm__ volatile("rep stosb" : "+D"(d), "+c"(r) : "a"(v) : "memory");
#else
    u32 v = (u8)c * 0x01010101u;
    size_t q = n >> 2, r = n & 3;
    __asm__ volatile("rep stosl" : "+D"(d), "+c"(q) : "a"(v) : "memory");
    __asm__ volatile("rep stosb" : "+D"(d), "+c"(r) : "a"(v) : "memory");
#endif
    return ret;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const u8 *x = (const u8 *)a, *y = (const u8 *)b;
    for (size_t i = 0; i < n; i++)
        if (x[i] != y[i]) return (int)x[i] - (int)y[i];
    return 0;
}

/* GCC may turn byte loops in the core into strlen/memchr calls */
size_t strlen(const char *s)
{
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

void *memchr(const void *s, int c, size_t n)
{
    const u8 *p = (const u8 *)s;
    for (size_t i = 0; i < n; i++)
        if (p[i] == (u8)c) return (void *)(p + i);
    return 0;
}

/* ---------------- memory ---------------- */

static HANDLE s_heap;
static HANDLE heap(void)
{
    if (!s_heap) s_heap = GetProcessHeap();
    return s_heap;
}

void *gz_alloc(size_t n) { return HeapAlloc(heap(), HEAP_ZERO_MEMORY, n ? n : 1); }
void *gz_realloc(void *p, size_t n)
{
    if (!p) return gz_alloc(n);
    return HeapReAlloc(heap(), HEAP_ZERO_MEMORY, p, n ? n : 1);
}
void gz_free(void *p) { if (p) HeapFree(heap(), 0, p); }
void *gz_alloc_big(size_t n) { return VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); }
void gz_free_big(void *p, size_t n) { (void)n; if (p) VirtualFree(p, 0, MEM_RELEASE); }
void *mem_alloc(size_t n) { return gz_alloc(n); }
void mem_free(void *p) { gz_free(p); }

wchar_t *wdup(const wchar_t *s)
{
    if (!s) return 0;
    size_t n = gz_wcslen(s) + 1;
    wchar_t *d = (wchar_t *)gz_alloc(n * sizeof(wchar_t));
    if (d) __builtin_memcpy(d, s, n * sizeof(wchar_t));
    return d;
}

/* ---------------- code page hooks for the core ---------------- */

int gz_plat_mb2wc(int cp, const u8 *s, int n, gzch *out, int cap)
{
    if (n <= 0) return 0;
    return MultiByteToWideChar((UINT)cp, 0, (LPCSTR)s, n, out, cap);
}

int gz_plat_wc2mb(int cp, const gzch *s, int n, u8 *out, int cap)
{
    if (n <= 0) return 0;
    BOOL lossy = FALSE;
    /* the default-char check is not allowed for UTF-8 (and is a Windows 2000+ flag set anyway) */
    int r = WideCharToMultiByte((UINT)cp, 0, s, n, (LPSTR)out, cap, NULL, cp == 65001 ? NULL : &lossy);
    return lossy ? 0 : r;
}

int gz_plat_case_fold(void) { return 1; }

/* CryptoAPI is available from Windows 2000 on (RtlGenRandom only from XP). */
int gz_plat_random(void *buf, size_t n)
{
    HCRYPTPROV prov;
    if (!CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) return GZ_E_IO;
    BOOL ok = CryptGenRandom(prov, (DWORD)n, (BYTE *)buf);
    CryptReleaseContext(prov, 0);
    return ok ? GZ_OK : GZ_E_IO;
}

int gz_plat_acp(void)
{
    UINT acp = GetACP();
    if (acp == 932 || acp == 936 || acp == 949 || acp == 950) return (int)acp;
    if ((g_set.lang == 1 || PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_KOREAN) &&
        IsValidCodePage(949))
        return 949;
    return (int)GetOEMCP();
}

int gz_plat_oemcp(void) { return (int)GetOEMCP(); }

int gz_plat_mb_valid(int cp, const u8 *s, int n)
{
    if (n <= 0) return 1;
    /* MB_ERR_INVALID_CHARS: Windows 2000 SP4+ for DBCS code pages; older systems
     * simply report "valid" and the caller falls back to its other evidence. */
    return MultiByteToWideChar((UINT)cp, MB_ERR_INVALID_CHARS, (LPCSTR)s, n, NULL, 0) > 0;
}
int gz_plat_cp_valid(int cp) { return cp == 65001 || IsValidCodePage((UINT)cp); }

/* ---------------- entry point ---------------- */

int app_main(void);

__attribute__((force_align_arg_pointer, used))
void __cdecl gz_start(void)
{
    ExitProcess((UINT)app_main());
}
