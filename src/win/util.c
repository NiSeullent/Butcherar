/*
 * 고깃ZIP - string formatting, paths, settings, OS detection
 */
#include "app.h"

gz_settings g_set;
gz_osver g_os;
int g_dpi = 96;

/* ---------------- strings ---------------- */

size_t wlen(const wchar_t *s) { return s ? gz_wcslen(s) : 0; }

void wcopy(wchar_t *d, const wchar_t *s, size_t cap)
{
    size_t i = 0;
    if (!cap) return;
    if (s) while (s[i] && i + 1 < cap) { d[i] = s[i]; i++; }
    d[i] = 0;
}

void wcat(wchar_t *d, const wchar_t *s, size_t cap)
{
    size_t n = wlen(d);
    if (n < cap) wcopy(d + n, s, cap - n);
}

int wcmp(const wchar_t *a, const wchar_t *b) { return gz_wcscmp(a, b); }
int wicmp(const wchar_t *a, const wchar_t *b) { return lstrcmpiW(a, b); }

wchar_t *wfmtn(wchar_t *buf, size_t cap, const wchar_t *fmt, ...)
{
    wchar_t tmp[1025];
    va_list ap;
    va_start(ap, fmt);
    int n = wvsprintfW(tmp, fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    if (n > 1024) n = 1024;
    tmp[n] = 0;
    wcopy(buf, tmp, cap);
    return buf;
}

/* Same folding as the archive's folder hash (ASCII letters only), so a
 * folder prefix matches every entry that was merged into that folder. */
int prefix_ieq(const wchar_t *s, const wchar_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        wchar_t x = s[i], y = p[i];
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y || !x) return 0;
    }
    return 1;
}

void fmt_u64(wchar_t *o, u64 v)
{
    wchar_t t[24];
    int n = 0;
    do { t[n++] = (wchar_t)('0' + (int)(v % 10)); v /= 10; } while (v);
    while (n) *o++ = t[--n];
    *o = 0;
}

void fmt_thousands(wchar_t *o, u64 v)
{
    wchar_t t[32];
    int n = 0, g = 0;
    do {
        if (g == 3) { t[n++] = ','; g = 0; }
        t[n++] = (wchar_t)('0' + (int)(v % 10));
        v /= 10;
        g++;
    } while (v);
    while (n) *o++ = t[--n];
    *o = 0;
}

void fmt_size(wchar_t *o, u64 v)
{
    static const wchar_t *units[] = { L"B", L"KB", L"MB", L"GB", L"TB" };
    if (v < 1024) { fmt_u64(o, v); wcat(o, L" B", 32); return; }
    int u = 0;
    u64 whole = v, frac10;
    u64 div = 1;
    while (whole >= 1024 && u < 4) { whole /= 1024; div *= 1024; u++; }
    /* one or two decimals depending on magnitude */
    u64 x100 = (v * 100 + div / 2) / div;
    if (v > (u64)-1 / 100) x100 = (v / div) * 100;
    wchar_t num[32];
    if (x100 >= 10000) { fmt_u64(num, (x100 + 50) / 100); }
    else if (x100 >= 1000) {
        frac10 = (x100 + 5) / 10;
        fmt_u64(num, frac10 / 10);
        wchar_t f[4] = { '.', (wchar_t)('0' + (int)(frac10 % 10)), 0 };
        wcat(num, f, 32);
    } else {
        fmt_u64(num, x100 / 100);
        wchar_t f[5] = { '.', (wchar_t)('0' + (int)((x100 / 10) % 10)), (wchar_t)('0' + (int)(x100 % 10)), 0 };
        wcat(num, f, 32);
    }
    wcopy(o, num, 32);
    wcat(o, L" ", 40);
    wcat(o, units[u], 40);
}

void fmt_speed(wchar_t *o, u64 bps)
{
    fmt_size(o, bps);
    wcat(o, L"/s", 48);
}

void fmt_duration(wchar_t *o, u32 s)
{
    if (s >= 3600) wfmt(o, L"%d:%02d:%02d", s / 3600, (s / 60) % 60, s % 60);
    else wfmt(o, L"%02d:%02d", s / 60, s % 60);
}

void fmt_filetime(wchar_t *o, u64 ft)
{
    FILETIME u, l;
    SYSTEMTIME st;
    o[0] = 0;
    if (!ft) return;
    u.dwLowDateTime = (DWORD)ft;
    u.dwHighDateTime = (DWORD)(ft >> 32);
    if (!FileTimeToLocalFileTime(&u, &l) || !FileTimeToSystemTime(&l, &st)) return;
    wfmt(o, L"%04d-%02d-%02d %02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
}

u64 entry_filetime(const gz_entry *e)
{
    if (e->mtime_kind == GZ_MT_FILETIME) return e->mtime;
    if (e->mtime_kind == GZ_MT_DOS) {
        FILETIME l, u;
        WORD date = (WORD)(e->mtime >> 16), time = (WORD)e->mtime;
        if (!date) return 0;
        if (!DosDateTimeToFileTime(date, time, &l)) return 0;
        if (!LocalFileTimeToFileTime(&l, &u)) return 0;
        return ((u64)u.dwHighDateTime << 32) | u.dwLowDateTime;
    }
    return 0;
}

/* ---------------- paths ---------------- */

const wchar_t *path_base(const wchar_t *p)
{
    const wchar_t *b = p;
    for (; *p; p++) if (*p == '\\' || *p == '/') b = p + 1;
    return b;
}

void path_dir(wchar_t *dir, const wchar_t *path, size_t cap)
{
    wcopy(dir, path, cap);
    wchar_t *b = (wchar_t *)path_base(dir);
    if (b > dir) b[-1] = 0;
    if (wlen(dir) == 2 && dir[1] == ':') wcat(dir, L"\\", cap);
}

void path_join(wchar_t *o, const wchar_t *a, const wchar_t *b, size_t cap)
{
    if (o != a) wcopy(o, a, cap);
    size_t n = wlen(o);
    if (n && o[n - 1] != '\\' && o[n - 1] != '/') wcat(o, L"\\", cap);
    wcat(o, b, cap);
}

int path_is_dir(const wchar_t *p)
{
    DWORD a = GetFileAttributesW(p);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

int path_exists(const wchar_t *p) { return GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES; }

int scale(int px) { return MulDiv(px, g_dpi, 96); }

/* ---------------- settings (HKCU\Software\GogitZIP) ---------------- */

static int reg_int(HKEY k, const wchar_t *name, int def)
{
    DWORD v, t, sz = sizeof v;
    if (RegQueryValueExW(k, name, NULL, &t, (BYTE *)&v, &sz) == ERROR_SUCCESS && t == REG_DWORD) return (int)v;
    return def;
}

static void reg_str(HKEY k, const wchar_t *name, wchar_t *out, DWORD cap)
{
    DWORD t, sz = cap * sizeof(wchar_t);
    out[0] = 0;
    if (RegQueryValueExW(k, name, NULL, &t, (BYTE *)out, &sz) != ERROR_SUCCESS || t != REG_SZ) out[0] = 0;
    out[cap - 1] = 0;
}

static void reg_set_int(HKEY k, const wchar_t *name, int v)
{
    DWORD d = (DWORD)v;
    RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE *)&d, sizeof d);
}

static void reg_set_str(HKEY k, const wchar_t *name, const wchar_t *v)
{
    RegSetValueExW(k, name, 0, REG_SZ, (const BYTE *)v, (DWORD)((wlen(v) + 1) * sizeof(wchar_t)));
}

void settings_load(void)
{
    HKEY k = 0;
    g_set.codepage = 0;
    g_set.overwrite = GZ_OW_ASK;
    g_set.c_format = GZ_WF_ZIP;
    g_set.c_level = 5;
    g_set.c_enc = GZ_WE_AES256;
    g_set.c_solid = 1;
    g_set.open_folder = 1;
    g_set.smart_folder = 1;
    g_set.threads = 0;
    g_set.cpu_tier = -1;
    g_set.lang = 0;
    g_set.show_tree = 1;
    g_set.win_w = g_set.win_h = 0;
    g_set.split = 0;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, GZ_REGKEY, 0, KEY_READ, &k) != ERROR_SUCCESS) return;
    g_set.codepage = reg_int(k, L"CodePage", 0);
    g_set.overwrite = reg_int(k, L"Overwrite", GZ_OW_ASK);
    if (g_set.overwrite < 0 || g_set.overwrite > GZ_OW_NEWER) g_set.overwrite = GZ_OW_ASK;
    g_set.c_format = reg_int(k, L"CFormat", GZ_WF_ZIP);
    g_set.c_level = reg_int(k, L"CLevel", 5);
    g_set.c_method = reg_int(k, L"CMethod", 0);
    g_set.c_enc = reg_int(k, L"CEncryption", GZ_WE_AES256);
    g_set.c_solid = reg_int(k, L"CSolid", 1);
    g_set.c_encnames = reg_int(k, L"CEncryptNames", 0);
    if (g_set.c_level < 0 || g_set.c_level > 9) g_set.c_level = 5;
    if (g_set.c_method < 0 || g_set.c_method >= GZ_WM_COUNT) g_set.c_method = 0;
    reg_str(k, L"Associations", g_set.assoc, GZ_COUNTOF(g_set.assoc));
    g_set.open_folder = reg_int(k, L"OpenFolder", 1);
    g_set.smart_folder = reg_int(k, L"SmartFolder", 1);
    g_set.threads = reg_int(k, L"Threads", 0);
    g_set.cpu_tier = reg_int(k, L"CpuTier", -1);
    g_set.lang = reg_int(k, L"Language", 0);
    g_set.show_tree = reg_int(k, L"ShowTree", 1);
    g_set.win_x = reg_int(k, L"WinX", 0);
    g_set.win_y = reg_int(k, L"WinY", 0);
    g_set.win_w = reg_int(k, L"WinW", 0);
    g_set.win_h = reg_int(k, L"WinH", 0);
    g_set.win_max = reg_int(k, L"WinMax", 0);
    g_set.split = reg_int(k, L"Split", 0);
    g_set.dest_mode = reg_int(k, L"DestMode", 0);
    reg_str(k, L"Dest", g_set.dest, MAX_PATH);
    for (int i = 0; i < 6; i++) {
        wchar_t n[16];
        wfmt(n, L"Recent%d", i);
        reg_str(k, n, g_set.recent[i], MAX_PATH);
    }
    for (int i = 0; i < 8; i++) {
        wchar_t n[16];
        wfmt(n, L"Col%d", i);
        g_set.col_w[i] = reg_int(k, n, 0);
    }
    RegCloseKey(k);
}

void settings_save(void)
{
    HKEY k;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, GZ_REGKEY, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) != ERROR_SUCCESS)
        return;
    reg_set_int(k, L"CodePage", g_set.codepage);
    reg_set_int(k, L"Overwrite", g_set.overwrite);
    reg_set_int(k, L"OpenFolder", g_set.open_folder);
    reg_set_int(k, L"SmartFolder", g_set.smart_folder);
    reg_set_int(k, L"Threads", g_set.threads);
    reg_set_int(k, L"CpuTier", g_set.cpu_tier);
    reg_set_int(k, L"Language", g_set.lang);
    reg_set_int(k, L"ShowTree", g_set.show_tree);
    reg_set_int(k, L"WinX", g_set.win_x);
    reg_set_int(k, L"WinY", g_set.win_y);
    reg_set_int(k, L"WinW", g_set.win_w);
    reg_set_int(k, L"WinH", g_set.win_h);
    reg_set_int(k, L"WinMax", g_set.win_max);
    reg_set_int(k, L"Split", g_set.split);
    reg_set_int(k, L"DestMode", g_set.dest_mode);
    reg_set_str(k, L"Dest", g_set.dest);
    reg_set_int(k, L"CFormat", g_set.c_format);
    reg_set_int(k, L"CLevel", g_set.c_level);
    reg_set_int(k, L"CMethod", g_set.c_method);
    reg_set_int(k, L"CEncryption", g_set.c_enc);
    reg_set_int(k, L"CSolid", g_set.c_solid);
    reg_set_int(k, L"CEncryptNames", g_set.c_encnames);
    reg_set_str(k, L"Associations", g_set.assoc);
    for (int i = 0; i < 6; i++) {
        wchar_t n[16];
        wfmt(n, L"Recent%d", i);
        reg_set_str(k, n, g_set.recent[i]);
    }
    for (int i = 0; i < 8; i++) {
        wchar_t n[16];
        wfmt(n, L"Col%d", i);
        reg_set_int(k, n, g_set.col_w[i]);
    }
    RegCloseKey(k);
}

void settings_add_recent(const wchar_t *path)
{
    int i, found = 5;
    for (i = 0; i < 6; i++) if (!wicmp(g_set.recent[i], path)) { found = i; break; }
    for (i = found; i > 0; i--) wcopy(g_set.recent[i], g_set.recent[i - 1], MAX_PATH);
    wcopy(g_set.recent[0], path, MAX_PATH);
}

/* ---------------- OS / CPU ---------------- */

typedef LONG (WINAPI *RtlGetVersion_t)(OSVERSIONINFOW *);

void os_detect(void)
{
    OSVERSIONINFOEXW v;
    __builtin_memset(&v, 0, sizeof v);
    v.dwOSVersionInfoSize = sizeof v;
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    RtlGetVersion_t rgv = nt ? (RtlGetVersion_t)(void *)GetProcAddress(nt, "RtlGetVersion") : 0;
    if (!rgv || rgv((OSVERSIONINFOW *)&v) != 0) {
        v.dwOSVersionInfoSize = sizeof v;
        if (!GetVersionExW((OSVERSIONINFOW *)&v)) {
            v.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);
            GetVersionExW((OSVERSIONINFOW *)&v);
        }
    }
    g_os.major = v.dwMajorVersion;
    g_os.minor = v.dwMinorVersion;
    g_os.build = v.dwBuildNumber & 0xffff;
    g_os.sp = v.wServicePackMajor;
}

const wchar_t *os_name(wchar_t *buf)
{
    const wchar_t *n = L"Windows";
    u32 v = g_os.major * 100 + g_os.minor;
    if (v == 500) n = L"Windows 2000";
    else if (v == 501) n = L"Windows XP";
    else if (v == 502) n = L"Windows XP x64 / Server 2003";
    else if (v == 600) n = L"Windows Vista";
    else if (v == 601) n = L"Windows 7";
    else if (v == 602) n = L"Windows 8";
    else if (v == 603) n = L"Windows 8.1";
    else if (g_os.major >= 10) n = g_os.build >= 22000 ? L"Windows 11" : L"Windows 10";
    if (g_os.sp) wfmt(buf, L"%s SP%d (%d.%d.%d)", n, g_os.sp, g_os.major, g_os.minor, g_os.build);
    else wfmt(buf, L"%s (%d.%d.%d)", n, g_os.major, g_os.minor, g_os.build);
    return buf;
}

int cpu_threads(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    int n = (int)si.dwNumberOfProcessors;
    return n < 1 ? 1 : n;
}
