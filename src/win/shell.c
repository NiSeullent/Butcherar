/*
 * 고깃ZIP - Explorer integration (per-user, HKCU only: no admin rights needed)
 *
 * Archive types come from the registered formats (gz_formats[i]->exts), grouped
 * for the association dialog; the user's choice is g_set.assoc.
 *
 *   Windows 7 - 11 : cascading "고깃ZIP ▸" menus via SubCommands
 *   Windows XP/Vista: flat "고깃ZIP: ..." verbs (SystemFileAssociations)
 *   Windows 2000    : flat verbs on the extension's current ProgID (merged view)
 *   every version   : "압축하기..." / "<이름>.zip" / "<이름>.7z" verbs on files
 *                     (HKCU\Software\Classes\*) and folders (Directory)
 *   optional        : file association of the chosen types -> GogitZIP.Archive
 */
#include "app.h"
#include <shlwapi.h>

#define PROGID L"GogitZIP.Archive"
#define CLS    L"Software\\Classes\\"

/* ---------------- extension groups ---------------- */

static const struct { const char *ext; u8 group, on; } k_known[] = {
    { "zip", AG_ZIP, 1 }, { "zipx", AG_ZIP, 1 },
    { "7z", AG_7Z, 1 },
    { "rar", AG_RAR, 1 }, { "r00", AG_RAR, 1 },
    { "alz", AG_ALZ, 1 }, { "egg", AG_ALZ, 1 },
    { "tar", AG_TAR, 1 }, { "tgz", AG_TAR, 1 }, { "gz", AG_TAR, 1 }, { "gzip", AG_TAR, 1 }, { "taz", AG_TAR, 1 },
    { "tpz", AG_TAR, 1 }, { "bz2", AG_TAR, 1 }, { "bzip2", AG_TAR, 1 }, { "tbz2", AG_TAR, 1 }, { "tbz", AG_TAR, 1 },
    { "xz", AG_TAR, 1 }, { "txz", AG_TAR, 1 }, { "lzma", AG_TAR, 1 }, { "tlz", AG_TAR, 1 }, { "lz", AG_TAR, 1 },
    { "zst", AG_TAR, 1 }, { "tzst", AG_TAR, 1 }, { "zstd", AG_TAR, 1 }, { "lz4", AG_TAR, 1 }, { "tlz4", AG_TAR, 1 },
    { "z", AG_TAR, 1 }, { "lzo", AG_TAR, 1 }, { "tzo", AG_TAR, 1 }, { "br", AG_TAR, 1 }, { "cpio", AG_TAR, 1 },
    { "rpm", AG_TAR, 1 }, { "deb", AG_TAR, 1 },
    { "iso", AG_ISO, 1 }, { "img", AG_ISO, 1 }, { "udf", AG_ISO, 1 }, { "ima", AG_ISO, 1 }, { "vfd", AG_ISO, 1 },
    { "flp", AG_ISO, 1 },
    { "vhd", AG_DISK, 1 }, { "vhdx", AG_DISK, 1 }, { "avhdx", AG_DISK, 1 }, { "vmdk", AG_DISK, 1 }, { "vdi", AG_DISK, 1 },
    { "qcow", AG_DISK, 1 }, { "qcow2", AG_DISK, 1 }, { "qcow2c", AG_DISK, 1 }, { "simg", AG_DISK, 1 }, { "dmg", AG_DISK, 1 },
    { "mbr", AG_DISK, 0 }, { "gpt", AG_DISK, 0 }, { "bin", AG_DISK, 0 }, { "raw", AG_DISK, 0 }, { "dsk", AG_DISK, 0 },
    { "hdd", AG_DISK, 0 }, { "ext", AG_DISK, 0 }, { "ext2", AG_DISK, 0 }, { "ext3", AG_DISK, 0 }, { "ext4", AG_DISK, 0 },
    { "fat", AG_DISK, 0 }, { "exfat", AG_DISK, 0 },
    { "cab", AG_OTHER, 1 }, { "arj", AG_OTHER, 1 }, { "lzh", AG_OTHER, 1 }, { "lha", AG_OTHER, 1 }, { "wim", AG_OTHER, 1 },
    { "swm", AG_OTHER, 1 }, { "esd", AG_OTHER, 1 }, { "squashfs", AG_OTHER, 1 }, { "xar", AG_OTHER, 1 },
    { "arc", AG_OTHER, 1 }, { "zoo", AG_OTHER, 1 }, { "ace", AG_OTHER, 1 },
    /* programs, installers and documents built on archive formats: off by default */
    { "exe", AG_EXE, 0 }, { "dll", AG_EXE, 0 }, { "sys", AG_EXE, 0 }, { "msi", AG_EXE, 0 }, { "msp", AG_EXE, 0 },
    { "mst", AG_EXE, 0 }, { "msm", AG_EXE, 0 }, { "doc", AG_EXE, 0 }, { "xls", AG_EXE, 0 }, { "ppt", AG_EXE, 0 },
    { "msg", AG_EXE, 0 }, { "chm", AG_EXE, 0 }, { "chi", AG_EXE, 0 }, { "chq", AG_EXE, 0 }, { "chw", AG_EXE, 0 },
    { "jar", AG_EXE, 0 }, { "war", AG_EXE, 0 }, { "ear", AG_EXE, 0 }, { "apk", AG_EXE, 0 }, { "xpi", AG_EXE, 0 },
    { "ipa", AG_EXE, 0 }, { "appx", AG_EXE, 0 }, { "nupkg", AG_EXE, 0 }, { "whl", AG_EXE, 0 }, { "odt", AG_EXE, 0 },
    { "ods", AG_EXE, 0 }, { "odp", AG_EXE, 0 }, { "docx", AG_EXE, 0 }, { "xlsx", AG_EXE, 0 }, { "pptx", AG_EXE, 0 },
    { "epub", AG_EXE, 0 }, { "pkg", AG_EXE, 0 }, { "mpkg", AG_EXE, 0 },
};

static int astr_eq(const char *a, const char *b)
{
    while (*a && *a == *b) a++, b++;
    return *a == *b;
}

static int known(const char *e)
{
    for (u32 i = 0; i < GZ_COUNTOF(k_known); i++) if (astr_eq(k_known[i].ext, e)) return (int)i;
    return -1;
}

int assoc_default_on(const char *ext)
{
    int k = known(ext);
    return k >= 0 && k_known[k].on;
}

int assoc_list(assoc_ext *out, int cap)
{
    int n = 0;
    for (int f = 0; gz_formats[f]; f++) {
        const char *p = gz_formats[f]->exts;
        while (p && *p) {
            while (*p == ' ') p++;
            char e[16];
            int k = 0;
            while (*p && *p != ' ') { if (k < 15) e[k++] = *p; p++; }
            e[k] = 0;
            if (!k || k >= 15) continue;
            int dup = 0;
            for (int i = 0; i < n && !dup; i++) dup = astr_eq(out[i].ext, e);
            if (dup || n >= cap) continue;
            int x = known(e);
            __builtin_memcpy(out[n].ext, e, (size_t)k + 1);
            out[n].group = x >= 0 ? k_known[x].group : AG_OTHER;
            out[n].def_on = x >= 0 ? k_known[x].on : 0;
            n++;
        }
    }
    /* stable order by group (insertion sort: a few dozen entries) */
    for (int i = 1; i < n; i++) {
        assoc_ext t = out[i];
        int j = i;
        while (j > 0 && out[j - 1].group > t.group) { out[j] = out[j - 1]; j--; }
        out[j] = t;
    }
    return n;
}

int assoc_wanted(const char *ext)
{
    if (!g_set.assoc[0]) return assoc_default_on(ext);
    for (const wchar_t *p = g_set.assoc; *p;) {
        while (*p == ' ') p++;
        const wchar_t *s = p;
        while (*p && *p != ' ') p++;
        size_t k = 0;
        while (s + k < p && ext[k] && s[k] == (wchar_t)(u8)ext[k]) k++;
        if (s + k == p && !ext[k] && p > s) return 1;
    }
    return 0;
}

/* ---------------- registry helpers ---------------- */

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

static void del_value(const wchar_t *key, const wchar_t *name)
{
    HKEY hk;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, key, 0, KEY_WRITE, &hk) != ERROR_SUCCESS) return;
    RegDeleteValueW(hk, name);
    RegCloseKey(hk);
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
static const verb k_cverbs[] = {
    { L"1add", L"/add ", S_V_ADD },
    { L"2zip", L"/zip ", S_V_ZIP },
    { L"3sz", L"/7z ", S_V_7Z },
};
static const wchar_t *const k_ckeys[] = { CLS L"*\\shell", CLS L"Directory\\shell" };

static void add_flat_verbs(const wchar_t *shellkey, const verb *vb, u32 nv)
{
    wchar_t k[512], c[MAX_PATH * 2 + 32], t[160], ic[MAX_PATH * 2 + 8];
    wfmt(ic, L"\"%s\",0", g_exe_path);
    for (u32 i = 0; i < nv; i++) {
        wfmt(k, L"%s\\GogitZIP.%s", shellkey, vb[i].key);
        if (vb[i].sid == S_V_OPEN) wcopy(t, S(S_V_OPEN), 160);
        else wfmt(t, L"%s: %s", S(S_APP), S(vb[i].sid));
        set_str(k, NULL, t);
        set_str(k, L"Icon", ic);
        wcat(k, L"\\command", 512);
        cmdline(c, vb[i].sw);
        set_str(k, NULL, c);
    }
}

static void del_flat_verbs(const wchar_t *shellkey, const verb *vb, u32 nv)
{
    wchar_t k[512];
    for (u32 i = 0; i < nv; i++) {
        wfmt(k, L"%s\\GogitZIP.%s", shellkey, vb[i].key);
        SHDeleteKeyW(HKEY_CURRENT_USER, k);
    }
}

/* Windows 7+: one "고깃ZIP" entry with a submenu */
static void add_cascade(const wchar_t *key, const wchar_t *title, const verb *vb, u32 nv)
{
    wchar_t v[MAX_PATH * 2 + 32];
    set_str(key, L"MUIVerb", title);
    set_str(key, L"SubCommands", L"");
    wfmt(v, L"\"%s\",0", g_exe_path);
    set_str(key, L"Icon", v);
    for (u32 j = 0; j < nv; j++) {
        wchar_t kk[512], c[MAX_PATH * 2 + 32];
        wfmt(kk, L"%s\\shell\\%s", key, vb[j].key);
        set_str(kk, L"MUIVerb", S(vb[j].sid));
        wcat(kk, L"\\command", 512);
        cmdline(c, vb[j].sw);
        set_str(kk, NULL, c);
    }
}

/* remove every trace of us from one extension (menu, association, OpenWithProgids) */
static void unregister_ext(const wchar_t *e)
{
    wchar_t k[512];
    wfmt(k, CLS L"SystemFileAssociations\\%s\\shell\\GogitZIP", e);
    SHDeleteKeyW(HKEY_CURRENT_USER, k);
    wfmt(k, CLS L"SystemFileAssociations\\%s\\shell", e);
    del_flat_verbs(k, k_verbs, GZ_COUNTOF(k_verbs));
    wchar_t prog[128];
    if (get_str(HKEY_CURRENT_USER, GZ_REGKEY L"\\Win2kVerbs", e, prog, 128) && prog[0]) {
        wfmt(k, CLS L"%s\\shell", prog);
        del_flat_verbs(k, k_verbs, GZ_COUNTOF(k_verbs));
        del_value(GZ_REGKEY L"\\Win2kVerbs", e);
    }
    wfmt(k, CLS L"%s\\OpenWithProgids", e);
    del_value(k, PROGID);
    wfmt(k, CLS L"%s", e);
    wchar_t cur[128];
    if (get_str(HKEY_CURRENT_USER, k, NULL, cur, 128) && !wicmp(cur, PROGID)) {
        wchar_t prev[128];
        if (get_str(HKEY_CURRENT_USER, GZ_REGKEY L"\\PrevAssoc", e, prev, 128) && prev[0]) set_str(k, NULL, prev);
        else del_value(k, NULL);
    }
    del_value(GZ_REGKEY L"\\PrevAssoc", e);
}

static void dot_ext(wchar_t *o, const char *e)
{
    int i = 0;
    o[i++] = '.';
    for (; *e && i < 15; e++) o[i++] = (wchar_t)(u8)*e;
    o[i] = 0;
}

static void unregister_all_exts(void)
{
    assoc_ext *l = (assoc_ext *)mem_alloc(512 * sizeof(assoc_ext));
    if (!l) return;
    int n = assoc_list(l, 512);
    for (int i = 0; i < n; i++) {
        wchar_t e[18];
        dot_ext(e, l[i].ext);
        unregister_ext(e);
    }
    for (u32 i = 0; i < GZ_COUNTOF(k_known); i++) {    /* types of formats removed since */
        wchar_t e[18];
        dot_ext(e, k_known[i].ext);
        unregister_ext(e);
    }
    mem_free(l);
}

int shell_register(int assoc)
{
    wchar_t k[512], v[MAX_PATH * 2 + 32];
    int win7 = g_os.major > 6 || (g_os.major == 6 && g_os.minor >= 1);
    int xp = g_os.major > 5 || (g_os.major == 5 && g_os.minor >= 1);

    unregister_all_exts();
    /* ProgID */
    set_str(CLS PROGID, NULL, S(S_V_DESC));
    wfmt(v, L"\"%s\",1", g_exe_path);
    set_str(CLS PROGID L"\\DefaultIcon", NULL, v);
    set_str(CLS PROGID L"\\shell", NULL, L"open");
    set_str(CLS PROGID L"\\shell\\open", NULL, S(S_V_OPEN));
    cmdline(v, L"");
    set_str(CLS PROGID L"\\shell\\open\\command", NULL, v);
    add_flat_verbs(CLS PROGID L"\\shell", k_verbs, GZ_COUNTOF(k_verbs));

    /* compress verbs on every file and folder */
    for (u32 i = 0; i < GZ_COUNTOF(k_ckeys); i++) {
        if (win7) {
            wfmt(k, L"%s\\GogitZIP.compress", k_ckeys[i]);
            wfmt(v, L"%s: %s", S(S_APP), S(S_TB_NEW));
            add_cascade(k, v, k_cverbs, GZ_COUNTOF(k_cverbs));
        } else {
            add_flat_verbs(k_ckeys[i], k_cverbs, GZ_COUNTOF(k_cverbs));
        }
    }

    assoc_ext *l = (assoc_ext *)mem_alloc(512 * sizeof(assoc_ext));
    int n = l ? assoc_list(l, 512) : 0;
    for (int i = 0; i < n; i++) {
        if (!assoc_wanted(l[i].ext)) continue;
        wchar_t e[18];
        dot_ext(e, l[i].ext);
        int assoc_this = assoc;       /* per extension: never leaks into later ones */
        wfmt(k, CLS L"%s\\OpenWithProgids", e);
        set_str(k, PROGID, L"");
        if (win7) {
            wfmt(k, CLS L"SystemFileAssociations\\%s\\shell\\GogitZIP", e);
            add_cascade(k, S(S_V_MENU), k_verbs, GZ_COUNTOF(k_verbs));
        } else if (xp) {
            wfmt(k, CLS L"SystemFileAssociations\\%s\\shell", e);
            add_flat_verbs(k, k_verbs, GZ_COUNTOF(k_verbs));
        } else {
            /* Windows 2000: attach verbs to whatever ProgID the extension uses */
            wchar_t prog[128];
            if (get_str(HKEY_CLASSES_ROOT, e, NULL, prog, 128) && prog[0] && wicmp(prog, PROGID)) {
                wfmt(k, CLS L"%s\\shell", prog);
                add_flat_verbs(k, k_verbs, GZ_COUNTOF(k_verbs));
                set_str(GZ_REGKEY L"\\Win2kVerbs", e, prog);
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
    mem_free(l);
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
    return 1;
}

int shell_unregister(void)
{
    wchar_t k[512];
    unregister_all_exts();
    for (u32 i = 0; i < GZ_COUNTOF(k_ckeys); i++) {
        wfmt(k, L"%s\\GogitZIP.compress", k_ckeys[i]);
        SHDeleteKeyW(HKEY_CURRENT_USER, k);
        del_flat_verbs(k_ckeys[i], k_cverbs, GZ_COUNTOF(k_cverbs));
    }
    SHDeleteKeyW(HKEY_CURRENT_USER, CLS PROGID);
    SHDeleteKeyW(HKEY_CURRENT_USER, GZ_REGKEY L"\\Win2kVerbs");
    SHDeleteKeyW(HKEY_CURRENT_USER, GZ_REGKEY L"\\PrevAssoc");
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
    return 1;
}

/* bit 0: context menu present, bit 1: some archive type is associated with us */
int shell_is_registered(void)
{
    int r = 0;
    if (key_exists(CLS L"*\\shell\\GogitZIP.compress") || key_exists(CLS L"*\\shell\\GogitZIP.1add") ||
        key_exists(CLS L"SystemFileAssociations\\.zip\\shell\\GogitZIP") ||
        key_exists(CLS L"SystemFileAssociations\\.zip\\shell\\GogitZIP.1smart") ||
        key_exists(CLS PROGID L"\\shell\\GogitZIP.1smart"))
        r |= 1;
    wchar_t cur[128];
    static const wchar_t *const probe[] = { CLS L".zip", CLS L".7z", CLS L".rar", CLS L".tar", CLS L".gz" };
    for (u32 i = 0; i < GZ_COUNTOF(probe) && !(r & 2); i++)
        if (get_str(HKEY_CURRENT_USER, probe[i], NULL, cur, 128) && !wicmp(cur, PROGID)) r |= 2;
    return r;
}
