/*
 * 고깃ZIP - Explorer integration (per-user, HKCU only: no admin rights needed)
 *
 *   Windows 7 - 11 : cascading "고깃ZIP ▸" menu via SystemFileAssociations
 *   Windows XP/Vista: flat "고깃ZIP: ..." verbs via SystemFileAssociations
 *   Windows 2000    : verbs on the extension's current ProgID (merged view)
 *   Optional file association: .zip/.tar/.gz/.tgz -> GogitZIP.Archive
 */
#include "app.h"
#include <shlwapi.h>

#define PROGID L"GogitZIP.Archive"
#define CLS    L"Software\\Classes\\"

static const wchar_t *k_exts[] = { L".zip", L".tar", L".gz", L".tgz" };

static int set_str(const wchar_t *key, const wchar_t *name, const wchar_t *val)
{
    HKEY k;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, key, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) != ERROR_SUCCESS) return 0;
    LONG r = RegSetValueExW(k, name, 0, REG_SZ, (const BYTE *)val, (DWORD)((wlen(val) + 1) * sizeof(wchar_t)));
    RegCloseKey(k);
    return r == ERROR_SUCCESS;
}

static int get_str(HKEY root, const wchar_t *key, const wchar_t *name, wchar_t *out, DWORD cap)
{
    HKEY k;
    out[0] = 0;
    if (RegOpenKeyExW(root, key, 0, KEY_READ, &k) != ERROR_SUCCESS) return 0;
    DWORD t, sz = cap * sizeof(wchar_t);
    LONG r = RegQueryValueExW(k, name, NULL, &t, (BYTE *)out, &sz);
    RegCloseKey(k);
    out[cap - 1] = 0;
    if (r != ERROR_SUCCESS || t != REG_SZ) { out[0] = 0; return 0; }
    return 1;
}

static int key_exists(const wchar_t *key)
{
    HKEY k;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, key, 0, KEY_READ, &k) != ERROR_SUCCESS) return 0;
    RegCloseKey(k);
    return 1;
}

static void cmdline(wchar_t *o, const wchar_t *sw)
{
    wfmt(o, L"\"%s\" %s\"%%1\"", g_exe_path, sw);
}

typedef struct { const wchar_t *key, *sw; int sid; } verb;
static const verb k_verbs[] = {
    { L"1smart", L"/smart ", S_V_SMART },
    { L"2here", L"/here ", S_V_HERE },
    { L"3extract", L"/extract ", S_V_EXTRACT },
    { L"4test", L"/test ", S_V_TEST },
    { L"5open", L"", S_V_OPEN },
};

static void add_flat_verbs(const wchar_t *shellkey)
{
    wchar_t k[512], c[MAX_PATH * 2 + 32], t[160], ic[MAX_PATH * 2 + 8];
    wfmt(ic, L"\"%s\",0", g_exe_path);
    for (u32 i = 0; i < GZ_COUNTOF(k_verbs); i++) {
        wfmt(k, L"%s\\GogitZIP.%s", shellkey, k_verbs[i].key);
        if (k_verbs[i].sid == S_V_OPEN) wcopy(t, S(S_V_OPEN), 160);
        else wfmt(t, L"%s: %s", S(S_APP), S(k_verbs[i].sid));
        set_str(k, NULL, t);
        set_str(k, L"Icon", ic);
        wcat(k, L"\\command", 512);
        cmdline(c, k_verbs[i].sw);
        set_str(k, NULL, c);
    }
}

static void del_flat_verbs(const wchar_t *shellkey)
{
    wchar_t k[512];
    for (u32 i = 0; i < GZ_COUNTOF(k_verbs); i++) {
        wfmt(k, L"%s\\GogitZIP.%s", shellkey, k_verbs[i].key);
        SHDeleteKeyW(HKEY_CURRENT_USER, k);
    }
}

int shell_register(int assoc)
{
    wchar_t k[512], v[MAX_PATH * 2 + 32];
    int win7 = g_os.major > 6 || (g_os.major == 6 && g_os.minor >= 1);
    int xp = g_os.major > 5 || (g_os.major == 5 && g_os.minor >= 1);

    /* ProgID */
    set_str(CLS PROGID, NULL, S(S_V_DESC));
    wfmt(v, L"\"%s\",1", g_exe_path);
    set_str(CLS PROGID L"\\DefaultIcon", NULL, v);
    set_str(CLS PROGID L"\\shell", NULL, L"open");
    set_str(CLS PROGID L"\\shell\\open", NULL, S(S_V_OPEN));
    cmdline(v, L"");
    set_str(CLS PROGID L"\\shell\\open\\command", NULL, v);
    add_flat_verbs(CLS PROGID L"\\shell");

    for (u32 i = 0; i < GZ_COUNTOF(k_exts); i++) {
        const wchar_t *e = k_exts[i];
        int assoc_this = assoc;       /* per extension: never leaks into later ones */
        wfmt(k, CLS L"%s\\OpenWithProgids", e);
        set_str(k, PROGID, L"");
        if (win7) {
            wfmt(k, CLS L"SystemFileAssociations\\%s\\shell\\GogitZIP", e);
            set_str(k, L"MUIVerb", S(S_V_MENU));
            set_str(k, L"SubCommands", L"");
            wfmt(v, L"\"%s\",0", g_exe_path);
            set_str(k, L"Icon", v);
            for (u32 j = 0; j < GZ_COUNTOF(k_verbs); j++) {
                wchar_t kk[512], c[MAX_PATH * 2 + 32];
                wfmt(kk, L"%s\\shell\\%s", k, k_verbs[j].key);
                set_str(kk, L"MUIVerb", S(k_verbs[j].sid));
                wcat(kk, L"\\command", 512);
                cmdline(c, k_verbs[j].sw);
                set_str(kk, NULL, c);
            }
        } else if (xp) {
            wfmt(k, CLS L"SystemFileAssociations\\%s\\shell", e);
            add_flat_verbs(k);
        } else {
            /* Windows 2000: attach verbs to whatever ProgID the extension uses */
            wchar_t prog[128];
            if (get_str(HKEY_CLASSES_ROOT, e, NULL, prog, 128) && prog[0] && wicmp(prog, PROGID)) {
                wfmt(k, CLS L"%s\\shell", prog);
                add_flat_verbs(k);
                wfmt(k, GZ_REGKEY L"\\Win2kVerbs");
                set_str(k, e, prog);
            } else {
                assoc_this = 1;
            }
        }
        if (assoc_this) {
            wchar_t prev[128];
            wfmt(k, CLS L"%s", e);
            if (get_str(HKEY_CURRENT_USER, k, NULL, prev, 128) && prev[0] && wicmp(prev, PROGID))
                set_str(GZ_REGKEY L"\\PrevAssoc", e, prev);
            set_str(k, NULL, PROGID);
        }
    }
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
    return 1;
}

int shell_unregister(void)
{
    wchar_t k[512];
    for (u32 i = 0; i < GZ_COUNTOF(k_exts); i++) {
        const wchar_t *e = k_exts[i];
        wfmt(k, CLS L"SystemFileAssociations\\%s\\shell\\GogitZIP", e);
        SHDeleteKeyW(HKEY_CURRENT_USER, k);
        wfmt(k, CLS L"SystemFileAssociations\\%s\\shell", e);
        del_flat_verbs(k);
        wchar_t prog[128];
        if (get_str(HKEY_CURRENT_USER, GZ_REGKEY L"\\Win2kVerbs", e, prog, 128) && prog[0]) {
            wfmt(k, CLS L"%s\\shell", prog);
            del_flat_verbs(k);
        }
        wfmt(k, CLS L"%s\\OpenWithProgids", e);
        HKEY hk;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, k, 0, KEY_WRITE, &hk) == ERROR_SUCCESS) {
            RegDeleteValueW(hk, PROGID);
            RegCloseKey(hk);
        }
        wfmt(k, CLS L"%s", e);
        wchar_t cur[128];
        if (get_str(HKEY_CURRENT_USER, k, NULL, cur, 128) && !wicmp(cur, PROGID)) {
            wchar_t prev[128];
            if (get_str(HKEY_CURRENT_USER, GZ_REGKEY L"\\PrevAssoc", e, prev, 128) && prev[0]) set_str(k, NULL, prev);
            else if (RegOpenKeyExW(HKEY_CURRENT_USER, k, 0, KEY_WRITE, &hk) == ERROR_SUCCESS) {
                RegDeleteValueW(hk, NULL);
                RegCloseKey(hk);
            }
        }
    }
    SHDeleteKeyW(HKEY_CURRENT_USER, CLS PROGID);
    SHDeleteKeyW(HKEY_CURRENT_USER, GZ_REGKEY L"\\Win2kVerbs");
    SHDeleteKeyW(HKEY_CURRENT_USER, GZ_REGKEY L"\\PrevAssoc");
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
    return 1;
}

/* bit 0: context menu present, bit 1: .zip associated with us */
int shell_is_registered(void)
{
    int r = 0;
    if (key_exists(CLS L"SystemFileAssociations\\.zip\\shell\\GogitZIP") ||
        key_exists(CLS L"SystemFileAssociations\\.zip\\shell\\GogitZIP.1smart") ||
        key_exists(CLS PROGID L"\\shell\\GogitZIP.1smart"))
        r |= 1;
    wchar_t cur[128];
    if (get_str(HKEY_CURRENT_USER, CLS L".zip", NULL, cur, 128) && !wicmp(cur, PROGID)) r |= 2;
    return r;
}
