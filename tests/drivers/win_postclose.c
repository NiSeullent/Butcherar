/*
 * win_postclose - post WM_CLOSE to the Windows UI's main window, the way
 * "taskkill /im <exe>" without /f, close-window tools and installers do
 *
 *   win_postclose.exe [delay_ms]
 *       waits delay_ms, then posts WM_CLOSE to the window of class "GogitZIPMain".
 *       Exit status: 10 posted while the main window was enabled (no modal operation),
 *       11 posted while it was disabled (a modal dialog / operation was running),
 *       2 no main window, 1 PostMessage failed.
 *
 * Built with MinGW (-mwindows) by tests/cases/regress_windows_ui.py and run under Wine.
 */
#include <windows.h>

int WINAPI WinMain(HINSTANCE hi, HINSTANCE hp, LPSTR cmd, int show)
{
    DWORD delay = 0;
    (void)hi; (void)hp; (void)show;
    for (const char *p = cmd; *p >= '0' && *p <= '9'; p++) delay = delay * 10 + (DWORD)(*p - '0');
    if (delay) Sleep(delay);
    HWND w = FindWindowW(L"GogitZIPMain", NULL);
    if (!w) return 2;
    BOOL enabled = IsWindowEnabled(w);
    if (!PostMessageW(w, WM_CLOSE, 0, 0)) return 1;
    return enabled ? 10 : 11;
}
