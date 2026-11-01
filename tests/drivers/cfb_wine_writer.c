/*
 * cfb_wine_writer - writes compound files through the Windows structured storage API
 * (ole32 StgCreateStorageEx), run under Wine by tests/cases/fmt_cfb.py so the reader is
 * checked against an independent writer modelled on Windows.
 *
 *   cfb_wine_writer.exe <out.doc> <sector size 512|4096>
 *
 * Contents are deterministic (see fill()); the test compares with 7-Zip's extraction.
 * Built with MinGW: x86_64-w64-mingw32-gcc -O2 -o cfb_wine_writer.exe cfb_wine_writer.c -lole32 -luuid
 */
#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <stdio.h>

static void fill(BYTE *p, DWORD n, DWORD seed)
{
    DWORD x = seed * 2654435761u + 1;
    for (DWORD i = 0; i < n; i++) {
        x = x * 1103515245u + 12345u;
        p[i] = (BYTE)(x >> 16);
    }
}

static int put(IStorage *st, const WCHAR *name, DWORD size, DWORD seed)
{
    IStream *s;
    if (FAILED(IStorage_CreateStream(st, name, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, 0, &s)))
        return 1;
    BYTE *b = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size + 1);
    fill(b, size, seed);
    ULONG w = 0;
    HRESULT hr = size ? IStream_Write(s, b, size, &w) : S_OK;
    HeapFree(GetProcessHeap(), 0, b);
    IStream_Release(s);
    return FAILED(hr) || w != size;
}

static IStorage *sub(IStorage *st, const WCHAR *name)
{
    IStorage *c = 0;
    IStorage_CreateStorage(st, name, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, 0, &c);
    return c;
}

int wmain(int argc, WCHAR **argv)
{
    if (argc < 3) return 2;
    STGOPTIONS opt = { 0 };
    opt.usVersion = 1;
    opt.ulSectorSize = (ULONG)_wtoi(argv[2]);
    IStorage *root = 0;
    HRESULT hr = StgCreateStorageEx(argv[1], STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE | STGM_DIRECT,
                                    STGFMT_DOCFILE, 0, &opt, 0, &IID_IStorage, (void **)&root);
    if (FAILED(hr)) { printf("create failed %08lx\n", (unsigned long)hr); return 1; }
    int bad = 0;
    bad |= put(root, L"\x05SummaryInformation", 400, 1);
    bad |= put(root, L"WordDocument", 150000, 2);
    bad |= put(root, L"1Table", 4096, 3);
    bad |= put(root, L"Data", 4095, 4);
    bad |= put(root, L"empty", 0, 5);
    bad |= put(root, L"\xD55C\xAE00 \xC774\xB984.txt", 3000, 6);       /* "한글 이름.txt" */
    IStorage *op = sub(root, L"ObjectPool");
    IStorage *ob = op ? sub(op, L"_1234567") : 0;
    if (!ob) return 1;
    bad |= put(ob, L"\x01Ole", 20, 7);
    bad |= put(ob, L"\x03ObjInfo", 6, 8);
    bad |= put(ob, L"Contents", 70000, 9);
    for (int i = 0; i < 40; i++) {
        WCHAR nm[32];
        wsprintfW(nm, L"s%03d", i);
        bad |= put(ob, nm, 100 + i * 397, 100 + i);
    }
    IStorage_Release(ob);
    IStorage_Release(op);
    IStorage_Release(root);
    printf(bad ? "WRITE_FAIL\n" : "WRITE_OK\n");
    return bad;
}
