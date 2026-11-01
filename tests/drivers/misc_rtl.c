/*
 * misc_rtl - Windows helper of tests/cases/codec_misc.py, built there with MinGW and run
 * under Wine (not with build_driver): decodes LZNT1 buffers with ntdll's
 * RtlDecompressBuffer, the reference for NTFS / Windows semantics.
 *
 *   misc_rtl.exe <jobs>     each line "<in> <out> <out_cap>"; for every job prints
 *                           "status=<NTSTATUS hex> out=<final size>" and writes <out>
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef LONG (WINAPI *decomp_fn)(USHORT fmt, PUCHAR out, ULONG out_n, PUCHAR in, ULONG in_n, PULONG final);

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    decomp_fn dec = (decomp_fn)(void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlDecompressBuffer");
    FILE *j = fopen(argv[1], "r");
    if (!dec || !j) return 2;
    char in_name[260], out_name[260];
    unsigned long cap;
    while (fscanf(j, "%259s %259s %lu", in_name, out_name, &cap) == 3) {
        FILE *f = fopen(in_name, "rb");
        if (!f) return 2;
        fseek(f, 0, SEEK_END);
        long n = ftell(f);
        fseek(f, 0, SEEK_SET);
        unsigned char *in = malloc((size_t)n + 1), *out = malloc(cap + 1);
        if (!in || !out || fread(in, 1, (size_t)n, f) != (size_t)n) return 2;
        fclose(f);
        ULONG got = 0;
        LONG st = dec(2 /* COMPRESSION_FORMAT_LZNT1 */, out, cap, in, (ULONG)n, &got);
        if (st) got = 0;
        printf("status=%08lx out=%lu\n", (unsigned long)st, (unsigned long)got);
        f = fopen(out_name, "wb");
        if (!f) return 2;
        fwrite(out, 1, got, f);
        fclose(f);
        free(in);
        free(out);
    }
    fclose(j);
    return 0;
}
