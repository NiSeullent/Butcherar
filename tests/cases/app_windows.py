"""Windows front end (build/GogitZip.exe) under Wine + Xvfb, Korean locale.

  - import table: only functions that exist on Windows 2000 (list below = the
    imports of the exe before the portable engine + documented additions)
  - /to extraction of zip, tar.gz (and 7z when a 7z reader is registered) through
    the portable engine and os_win.c: data, folders, Korean names, reserved
    names / trailing dots, read-only attribute, modification times
  - /test of a good and of a damaged archive (the result window is closed with Enter)
  - /add: the create-archive dialog accepted with Enter, the archive checked with 7z
  - /zip and /7z next to the input folder when those writers are registered
  - screenshots of the main window and the create-archive dialog
    (copied to web/assets/screens/ only with GZ_UPDATE_SCREENS=1)

Skipped when wine, Xvfb or xdotool are missing. The exe is (re)built with make
when the MinGW cross compiler is available.
"""
import os, shutil, subprocess, time, zipfile, tarfile, io, random

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TITLE_RESULT = "작업 결과"
TITLE_CREATE = "새로 압축"
TITLE_PASSWORD = "비밀번호 입력"
TITLE_VOLUME = "분할 압축 파일"

# Imports of build/GogitZip.exe before this change (all present on Windows 2000) ...
BASE_IMPORTS = """
advapi32 CryptAcquireContextW CryptGenRandom CryptReleaseContext RegCloseKey RegCreateKeyExW RegDeleteValueW
advapi32 RegOpenKeyExW RegQueryValueExW RegSetValueExW
comctl32 ImageList_Draw InitCommonControlsEx
comdlg32 GetOpenFileNameW
gdi32 BitBlt CreateCompatibleBitmap CreateCompatibleDC CreateDIBSection CreateFontIndirectW CreateSolidBrush
gdi32 DeleteDC DeleteObject EnumFontFamiliesExW ExtTextOutW GetDeviceCaps GetObjectW GetTextExtentPoint32W
gdi32 GetTextMetricsW SelectObject SetBkColor SetBkMode SetTextColor
kernel32 CloseHandle CompareStringW CreateDirectoryW CreateEventW CreateFileW CreateThread
kernel32 DeleteCriticalSection DeleteFileW DosDateTimeToFileTime EnterCriticalSection ExitProcess
kernel32 FileTimeToLocalFileTime FileTimeToSystemTime FindClose FindFirstFileW FindNextFileW FindResourceW
kernel32 GetACP GetCommandLineW GetCurrentProcessId GetFileAttributesExW GetFileAttributesW GetFileSizeEx
kernel32 GetFullPathNameW GetLastError GetModuleFileNameW GetModuleHandleW GetOEMCP GetProcAddress
kernel32 GetProcessHeap GetSystemInfo GetTempPathW GetTickCount GetUserDefaultUILanguage GetVersionExW
kernel32 HeapAlloc HeapFree HeapReAlloc InitializeCriticalSection IsValidCodePage LeaveCriticalSection
kernel32 LoadLibraryW LoadResource LocalFileTimeToFileTime LocalFree LockResource MulDiv MultiByteToWideChar
kernel32 OpenProcess QueryPerformanceCounter QueryPerformanceFrequency ReadFile RemoveDirectoryW ResetEvent
kernel32 SetErrorMode SetEvent SetFileAttributesW SetFileTime SizeofResource VirtualAlloc VirtualFree
kernel32 WaitForMultipleObjects WaitForSingleObject WideCharToMultiByte WriteFile lstrcmpiW lstrlenW
msimg32 AlphaBlend
ole32 CoCreateInstance CoTaskMemFree OleInitialize OleUninitialize
shell32 CommandLineToArgvW DragAcceptFiles DragFinish DragQueryFileW SHBrowseForFolderW SHChangeNotify
shell32 SHGetFileInfoW SHGetPathFromIDListW SHGetSpecialFolderPathW ShellExecuteW
shlwapi SHDeleteKeyW
user32 AppendMenuW BeginPaint CallWindowProcW CharUpperBuffW CheckDlgButton CheckMenuItem ClientToScreen
user32 CreateAcceleratorTableW CreateMenu CreatePopupMenu CreateWindowExW DefWindowProcW DeleteMenu
user32 DestroyMenu DestroyWindow DialogBoxIndirectParamW DispatchMessageW DrawFocusRect DrawTextW
user32 EnableMenuItem EnableWindow EndDialog EndPaint EnumChildWindows GetClassNameW GetClientRect
user32 GetCursorPos GetDC GetDlgCtrlID GetDlgItem GetDlgItemTextW GetMenuItemCount GetMessageW GetMonitorInfoW
user32 GetParent GetPropW GetSystemMetrics GetWindow GetWindowLongPtrW GetWindowLongW GetWindowPlacement
user32 GetWindowRect GetWindowTextW InflateRect InvalidateRect IsDlgButtonChecked IsIconic IsWindowEnabled
user32 IsWindowVisible KillTimer LoadCursorW LoadImageW MapDialogRect MapWindowPoints MessageBeep MessageBoxW
user32 MonitorFromRect MoveWindow PostMessageW PostQuitMessage PtInRect RegisterClassExW ReleaseCapture
user32 ReleaseDC RemovePropW ScreenToClient SendDlgItemMessageW SendMessageW SetCapture SetCursor
user32 SetDlgItemTextW SetFocus SetForegroundWindow SetMenuDefaultItem SetPropW SetRect SetRectEmpty SetTimer
user32 SetWindowLongPtrW SetWindowLongW SetWindowPos SetWindowTextW ShowWindow SystemParametersInfoW
user32 TrackMouseEvent TrackPopupMenu TranslateAcceleratorW TranslateMessage UpdateWindow wvsprintfW
"""
# ... plus what the portable engine, os_win.c and the new dialogs use (MSDN: Windows 2000)
ADDED_IMPORTS = """
comctl32 ImageList_ReplaceIcon
comdlg32 GetSaveFileNameW
kernel32 CreateHardLinkW CreateMutexW CreateSemaphoreW ReleaseSemaphore GetCurrentDirectoryW
kernel32 GetFileInformationByHandle GetSystemTimeAsFileTime GetVersion MoveFileExW SetFilePointerEx Sleep
user32 DestroyIcon FindWindowExW GetKeyState MsgWaitForMultipleObjects PeekMessageW SendMessageTimeoutW
"""
# Vista+ (or later) functions that must never be imported statically
FORBIDDEN = {"GetTickCount64", "InitializeSRWLock", "AcquireSRWLockExclusive", "InitializeConditionVariable",
             "SleepConditionVariableCS", "WakeConditionVariable", "CreateSymbolicLinkW", "GetFileInformationByHandleEx",
             "SetFileInformationByHandle", "GetFinalPathNameByHandleW", "CompareStringEx", "LCIDToLocaleName",
             "CancelIoEx", "SHCreateItemFromParsingName", "SHGetKnownFolderPath", "GetDpiForWindow",
             "SetProcessDPIAware", "TaskDialogIndirect", "FlsAlloc", "InitOnceExecuteOnce"}


def allowed_imports():
    s = set()
    for line in (BASE_IMPORTS + ADDED_IMPORTS).split("\n"):
        w = line.split()
        if len(w) > 1:
            for f in w[1:]:
                s.add((w[0].lower() + ".dll", f))
    return s


def pe_imports(objdump, exe):
    r = subprocess.run([objdump, "-p", exe], capture_output=True, text=True)
    out, dll = set(), None
    for line in r.stdout.splitlines():
        if "DLL Name:" in line:
            dll = line.split("DLL Name:")[1].strip().lower()
            continue
        w = line.split()
        if dll and len(w) >= 3 and w[0] != "vma:" and all(c in "0123456789abcdef" for c in w[0]) and w[1].isdigit():
            out.add((dll, w[2]))
        elif not line.strip():
            dll = None                 # end of this DLL's table
    return out


def winpath(p):
    return "Z:" + os.path.abspath(p).replace("/", "\\")


class Wine:
    def __init__(self, t, exe):
        self.t, self.exe = t, exe
        # kept between runs (creating one takes a minute); 32-bit only: the tested exe is
        # 32-bit and a WoW64 prefix is twice the size (about 1.3 GB)
        self.prefix = os.environ.get("GZ_WINEPREFIX") or os.path.join(os.path.dirname(t.gzt), "wine-gzt32")
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("MAKE")}
        self.env.update(WINEPREFIX=self.prefix, WINEARCH="win32", WINEDEBUG="-all", LANG="ko_KR.UTF-8",
                        LC_ALL="ko_KR.UTF-8", WINEDLLOVERRIDES="mscoree,mshtml=")
        self.xvfb = None
        for n in range(91, 160):
            if not os.path.exists("/tmp/.X%d-lock" % n) and not os.path.exists("/tmp/.X11-unix/X%d" % n):
                self.xvfb = subprocess.Popen(["Xvfb", ":%d" % n, "-screen", "0", "1400x900x24", "-nolisten", "tcp"],
                                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.env["DISPLAY"] = ":%d" % n
                for _ in range(100):
                    if os.path.exists("/tmp/.X11-unix/X%d" % n):
                        break
                    time.sleep(0.05)
                break
        if not self.xvfb:
            t.skip("no free X display")
        self.server_kill()
        if not os.path.isdir(os.path.join(self.prefix, "drive_c")):
            subprocess.run(["wineboot", "-i"], env=self.env, capture_output=True, timeout=600)
        # menus and message boxes use the system font: link a Korean font to it (as Windows does)
        for face in ("Tahoma", "MS Shell Dlg", "MS Shell Dlg 2", "Microsoft Sans Serif", "Segoe UI"):
            self.reg(r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\FontLink\SystemLink", face,
                     "REG_MULTI_SZ", "NanumBarunGothic.ttf,NanumBarunGothic")

    def reg(self, key, name, typ, value):
        subprocess.run(["wine", "reg", "add", key, "/v", name, "/t", typ, "/d", str(value), "/f"], env=self.env,
                       capture_output=True, timeout=120)

    def settings(self, **kv):
        for k, v in kv.items():
            if isinstance(v, int):
                self.reg(r"HKCU\Software\GogitZIP", k, "REG_DWORD", v)
            else:
                self.reg(r"HKCU\Software\GogitZIP", k, "REG_SZ", v)

    def server_kill(self):
        subprocess.run(["wineserver", "-k"], env=self.env, capture_output=True, timeout=60)

    def run(self, args, timeout=180):
        """run the exe, None on timeout"""
        try:
            r = subprocess.run(["wine", self.exe] + args, env=self.env, capture_output=True, timeout=timeout)
            return r.returncode
        except subprocess.TimeoutExpired:
            self.server_kill()
            return None

    def start(self, args):
        return subprocess.Popen(["wine", self.exe] + args, env=self.env, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)

    def find_window(self, name, timeout=60):
        end = time.time() + timeout
        while time.time() < end:
            r = subprocess.run(["xdotool", "search", "--name", name], env=self.env, capture_output=True, text=True)
            ids = [x for x in r.stdout.split() if x.isdigit()]
            if ids:
                return ids[-1]
            time.sleep(0.3)
        return None

    def key(self, win, *keys):
        subprocess.run(["xdotool", "key", "--window", win] + list(keys), env=self.env, capture_output=True)

    def size(self, win):
        r = subprocess.run(["xdotool", "getwindowgeometry", win], env=self.env, capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if "Geometry:" in line:
                a, b = line.split("Geometry:")[1].strip().split("x")
                return int(a), int(b)
        return 0, 0

    def click(self, win, x, y, double=False, shift=False):
        """real (XTEST) clicks: Wine routes them like a user's"""
        cmd = ["xdotool"] + (["keydown", "shift"] if shift else []) + ["mousemove", "--window", win, str(x), str(y),
               "click"] + (["--repeat", "2", "--delay", "80"] if double else []) + ["1"] + \
              (["keyup", "shift"] if shift else [])
        subprocess.run(cmd, env=self.env, capture_output=True)

    def shot(self, win, path):
        subprocess.run(["import", "-window", win, path], env=self.env, capture_output=True, timeout=60)
        return os.path.exists(path)

    def wait(self, p, timeout=120):
        try:
            return p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.server_kill()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
            return None

    def close(self):
        self.server_kill()
        if self.xvfb:
            self.xvfb.terminate()
            try:
                self.xvfb.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.xvfb.kill()


def blob(n, seed):
    rnd = random.Random(seed)
    words = [b"gogi ", b"samgyeopsal ", b"zip ", b"\xea\xb3\xa0\xea\xb8\xb0 ", b"archive\n"]
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(words) if seed % 2 else bytes([rnd.getrandbits(8)])
    return bytes(out[:n])


FILES = {
    "top/readme.txt": blob(4000, 1),
    "top/문서/보고서.txt": blob(90000, 3),
    "top/문서/사진/고기.jpg": blob(50000, 2),
    "top/deep/a/b/c.bin": blob(200000, 5),
    "top/empty.txt": b"",
}
DIRS = ["top/빈 폴더"]
MT = 1700000000


def make_tree(t, name):
    root = t.write_tree(t.path(name), dict(FILES, **{d: None for d in DIRS}))
    for i, rel in enumerate(sorted(FILES)):
        os.utime(os.path.join(root, rel), (MT + 1000 * i, MT + 1000 * i))
    return root


def tree_eq(t, a, b):
    """files (content) and folders of two trees; returns list of differences"""
    def walk(r):
        files, dirs = {}, set()
        for dp, dns, fns in os.walk(r):
            for d in dns:
                dirs.add(os.path.relpath(os.path.join(dp, d), r))
            for f in fns:
                files[os.path.relpath(os.path.join(dp, f), r)] = open(os.path.join(dp, f), "rb").read()
        return files, dirs
    fa, da = walk(a)
    fb, db = walk(b)
    diff = ["missing " + k for k in fa if k not in fb] + ["extra " + k for k in fb if k not in fa]
    diff += ["data " + k for k in fa if k in fb and fa[k] != fb[k]]
    diff += ["dir " + k for k in da ^ db]
    return diff


def run(t):
    t.need("wine", "Xvfb", "xdotool")
    bdir = os.path.dirname(t.gzt)
    exe = os.path.join(bdir, "GogitZip.exe")
    if shutil.which("i686-w64-mingw32-gcc") and os.path.dirname(os.path.abspath(bdir)) == ROOT:
        env = {k: v for k, v in os.environ.items() if not k.startswith("MAKE")}
        r = subprocess.run(["make", "-C", ROOT, "-j4", os.path.relpath(exe, ROOT)], env=env, capture_output=True,
                           timeout=1800)
        if r.returncode:
            return t.record(False, "build GogitZip.exe", r.stderr.decode(errors="replace")[-800:])
    if not os.path.exists(exe):
        t.skip("build/GogitZip.exe not built (no MinGW)")

    # ---------- import table: Windows 2000 functions only ----------
    objdump = shutil.which("i686-w64-mingw32-objdump") or shutil.which("objdump")
    if objdump:
        imp = pe_imports(objdump, exe)
        allow = allowed_imports()
        extra = sorted("%s!%s" % x for x in imp - allow)
        bad = sorted("%s!%s" % x for x in imp if x[1] in FORBIDDEN)
        t.record(bool(imp) and not extra and not bad, "imports: Windows 2000 only (%d functions)" % len(imp),
                 "not on the list: %s %s" % (extra, bad))
        exe64 = os.path.join(bdir, "GogitZip64.exe")
        if os.path.exists(exe64):
            imp64 = pe_imports(shutil.which("x86_64-w64-mingw32-objdump") or objdump, exe64)
            extra = sorted("%s!%s" % x for x in imp64 - allow)
            t.record(bool(imp64) and not extra, "imports x64: same list (%d functions)" % len(imp64), str(extra))

    w = Wine(t, exe)
    try:
        run_wine(t, w)
    finally:
        w.close()


def run_wine(t, w):
    w.settings(OpenFolder=0, Overwrite=1, SmartFolder=1, Threads=0, CFormat=1, CLevel=5)
    src = make_tree(t, "src")

    # ---------- /to: zip ----------
    zp = t.path("tree.zip")
    if os.path.exists(zp):
        os.remove(zp)
    subprocess.run(["zip", "-qr", "-X", zp, "top"], cwd=src, check=True)
    with zipfile.ZipFile(zp, "a") as z:             # Windows naming rules + read-only attribute
        zi = zipfile.ZipInfo("odd/con.txt", (2024, 5, 6, 7, 8, 10)); z.writestr(zi, b"reserved")
        zi = zipfile.ZipInfo("odd/trailing. ", (2024, 5, 6, 7, 8, 10)); z.writestr(zi, b"trail")
        zi = zipfile.ZipInfo("odd/readonly.txt", (2024, 5, 6, 7, 8, 10))
        zi.external_attr = 0x01 | 0x20; zi.create_system = 0
        z.writestr(zi, b"ro")
    out = t.path("out_zip")
    shutil.rmtree(out, ignore_errors=True)
    rc = w.run(["/to", winpath(out), winpath(zp)])
    d = tree_eq(t, os.path.join(src, "top"), os.path.join(out, "top")) if rc == 0 else ["rc=%s" % rc]
    t.record(not d, "/to zip: files, folders, Korean names", "; ".join(d[:6]))
    odd = os.path.join(out, "odd")
    names = sorted(os.listdir(odd)) if os.path.isdir(odd) else []
    t.record(names == ["_con.txt", "readonly.txt", "trailing._"], "/to zip: reserved name and trailing space renamed",
             str(names))
    ro = os.path.join(odd, "readonly.txt")
    t.record(os.path.exists(ro) and not (os.stat(ro).st_mode & 0o222), "/to zip: read-only attribute kept",
             oct(os.stat(ro).st_mode) if os.path.exists(ro) else "missing")
    mt = os.path.join(out, "top", "readme.txt")
    t.record(os.path.exists(mt) and abs(os.stat(mt).st_mtime - os.stat(os.path.join(src, "top", "readme.txt")).st_mtime) <= 2,
             "/to zip: modification time restored", "")

    # ---------- /to: tar.gz (solid single pass) ----------
    tp = t.path("tree.tar.gz")
    with tarfile.open(tp, "w:gz") as tf:
        tf.add(os.path.join(src, "top"), "top")
    out = t.path("out_tgz")
    shutil.rmtree(out, ignore_errors=True)
    rc = w.run(["/to", winpath(out), winpath(tp)])
    d = tree_eq(t, os.path.join(src, "top"), os.path.join(out, "top")) if rc == 0 else ["rc=%s" % rc]
    t.record(not d, "/to tar.gz", "; ".join(d[:6]))

    # ---------- /to: 7z when a 7z reader is registered ----------
    if shutil.which("7z"):
        sp = t.path("tree.7z")
        if os.path.exists(sp):
            os.remove(sp)
        subprocess.run(["7z", "a", "-bd", "-y", sp, "top"], cwd=src, capture_output=True, check=True)
        r, typ, rows = t.listing(sp)
        if r.returncode == 0 and rows:
            out = t.path("out_7z")
            shutil.rmtree(out, ignore_errors=True)
            rc = w.run(["/to", winpath(out), winpath(sp)])
            d = tree_eq(t, os.path.join(src, "top"), os.path.join(out, "top")) if rc == 0 else ["rc=%s" % rc]
            t.record(not d, "/to 7z", "; ".join(d[:6]))

    # Wine without a window manager blocks in EndDialog of a dialog that was visible while a
    # nested dialog came and went (the pre-engine build does the same): the two tests below
    # check the result on disk and then end Wine instead of waiting for the process.

    # ---------- password: wrong one first, the retry message, then the right one ----------
    if shutil.which("zip"):
        pz = t.path("secret.zip")
        if os.path.exists(pz):
            os.remove(pz)
        subprocess.run(["zip", "-qr", "-P", "gogi1234", pz, "top"], cwd=src, check=True)
        out = t.path("out_pw")
        shutil.rmtree(out, ignore_errors=True)
        p = w.start(["/to", winpath(out), winpath(pz)])
        asked, seen = 0, set()
        for pw in ("wrong", "gogi1234"):
            win = None
            end = time.time() + 60
            while time.time() < end and not win:
                cand = w.find_window(TITLE_PASSWORD, 5)
                if cand and cand not in seen:
                    win = cand
            if not win:
                break
            seen.add(win)
            asked += 1
            time.sleep(0.8)
            subprocess.run(["xdotool", "type", "--window", win, pw], env=w.env, capture_output=True)
            w.key(win, "Return")
        d = ["not extracted"]
        end = time.time() + 60
        while time.time() < end and d:
            time.sleep(1)
            if os.path.isdir(os.path.join(out, "top")):
                d = tree_eq(t, os.path.join(src, "top"), os.path.join(out, "top"))
        w.server_kill()
        w.wait(p, 30)
        t.record(asked == 2 and not d, "/to encrypted zip: wrong password asked again, then extracted",
                 "asked=%d %s" % (asked, "; ".join(d[:4])))

    # ---------- missing volume: asked for, found again after "다시 찾기" ----------
    if shutil.which("qemu-img") and shutil.which("mkfs.vfat") and shutil.which("mcopy"):
        vd = t.path("vol")
        shutil.rmtree(vd, ignore_errors=True)
        os.makedirs(vd)
        raw = os.path.join(vd, "raw.img")
        with open(raw, "wb") as f:
            f.truncate(4 << 20)
        hello = os.path.join(vd, "hello.txt")
        open(hello, "wb").write(b"volume test " * 100)
        ok_fx = subprocess.run(["mkfs.vfat", raw], capture_output=True).returncode == 0 and \
            subprocess.run(["mcopy", "-i", raw, hello, "::/hello.txt"], capture_output=True).returncode == 0 and \
            subprocess.run(["qemu-img", "convert", "-f", "raw", "-O", "vmdk", "-o", "subformat=monolithicFlat", raw,
                            os.path.join(vd, "disk.vmdk")], capture_output=True).returncode == 0
        flat = os.path.join(vd, "disk-flat.vmdk")
        if ok_fx and os.path.exists(flat):
            hidden = os.path.join(vd, "elsewhere.bin")
            os.rename(flat, hidden)
            out = t.path("out_vol")
            shutil.rmtree(out, ignore_errors=True)
            p = w.start(["/to", winpath(out), winpath(os.path.join(vd, "disk.vmdk"))])
            win = w.find_window(TITLE_VOLUME, 60)
            got = None
            if win:
                time.sleep(1.0)
                os.rename(hidden, flat)
                ww, wh = w.size(win)              # "다시 찾기": template 300x114 DLU, button at (188..238, 94..109)
                w.click(win, ww * 213 // 300, wh * 101 // 114)
                end = time.time() + 60
                res = os.path.join(out, "hello.txt")
                while time.time() < end and got is None:
                    time.sleep(1)
                    if os.path.exists(res) and os.path.getsize(res) == 1200:
                        got = open(res, "rb").read()
            w.server_kill()
            w.wait(p, 30)
            t.record(win is not None and got == b"volume test " * 100,
                     "missing volume: asked, found after it reappeared, extracted", "window=%s got=%s" %
                     (win, got is not None))

    # ---------- /test: good and damaged (result window closed with Enter) ----------
    for label, path, want in (("good", zp, 0), ("damaged", None, 1)):
        if path is None:
            data = bytearray(open(zp, "rb").read())
            i = data.find(b"PK\x03\x04", 1000)          # some entry after the first: damage its data
            i = i if i > 0 else 100
            for k in range(i + 60, min(i + 90, len(data) - 30)):
                data[k] ^= 0x5A
            path = t.path("damaged.zip")
            open(path, "wb").write(bytes(data))
        p = w.start(["/test", winpath(path)])
        win = w.find_window(TITLE_RESULT, 90)
        if win:
            time.sleep(0.5)
            w.key(win, "Return")
        rc = w.wait(p, 60)
        t.record(win is not None and rc == want, "/test %s archive" % label, "window=%s rc=%s" % (win, rc))

    # ---------- /add: create-archive dialog, accepted with Enter ----------
    shots = t.path("screens")
    os.makedirs(shots, exist_ok=True)
    addsrc = make_tree(t, "addsrc")
    before = set(os.listdir(addsrc))
    p = w.start(["/add", winpath(os.path.join(addsrc, "top"))])
    win = w.find_window(TITLE_CREATE, 90)
    shot_ok = False
    if win:
        time.sleep(1.5)
        shot_ok = w.shot(win, os.path.join(shots, "create.png"))
        w.key(win, "Return")
    rc = w.wait(p, 180)
    made = sorted(set(os.listdir(addsrc)) - before)
    ok = win is not None and rc == 0 and len(made) == 1
    detail = "window=%s rc=%s made=%s" % (win, rc, made)
    if ok and shutil.which("7z"):
        arc = os.path.join(addsrc, made[0])
        r = subprocess.run(["7z", "t", "-bd", arc], capture_output=True)
        ok = r.returncode == 0
        if ok:
            chk = t.path("add_check")
            shutil.rmtree(chk, ignore_errors=True)
            subprocess.run(["7z", "x", "-bd", "-y", "-o" + chk, arc], capture_output=True)
            dd = tree_eq(t, os.path.join(src, "top"), os.path.join(chk, "top"))
            ok = not dd
            detail += " " + "; ".join(dd[:4])
        else:
            detail += " 7z t: " + r.stdout.decode(errors="replace")[-200:]
    t.record(ok, "/add dialog -> archive verified by 7z", detail)
    t.record(shot_ok, "screenshot: create-archive dialog", "")

    # ---------- /zip and /7z next to the folder (when the writers exist) ----------
    for sw, ext, wf in (("/zip", ".zip", "ZIP"), ("/7z", ".7z", "7Z")):
        probe = t.path("probe" + ext)
        if os.path.exists(probe):
            os.remove(probe)
        pr = t.run_gzt(["c", ext[1:], probe, "1", "-", src, "top/readme.txt"])
        if pr.returncode or not os.path.exists(probe):
            continue                                   # writer not registered in this build
        d = make_tree(t, "direct" + ext[1:])
        target = os.path.join(d, "top" + ext)
        rc = w.run([sw, winpath(os.path.join(d, "top"))], timeout=300)
        ok = rc == 0 and os.path.exists(target)
        detail = "rc=%s" % rc
        if ok and shutil.which("7z"):
            r = subprocess.run(["7z", "t", "-bd", target], capture_output=True)
            ok = r.returncode == 0
            chk = t.path("direct_check" + ext[1:])
            shutil.rmtree(chk, ignore_errors=True)
            subprocess.run(["7z", "x", "-bd", "-y", "-o" + chk, target], capture_output=True)
            dd = tree_eq(t, os.path.join(src, "top"), os.path.join(chk, "top"))
            ok = ok and not dd
            detail += " " + "; ".join(dd[:4])
        t.record(ok, "%s folder -> top%s verified by 7z t" % (sw, ext), detail)

    # ---------- Explorer selection of several items: one process collects, one dialog ----------
    multi = t.write_tree(t.path("multi"), {"a.txt": b"aaa" * 100, "b.txt": b"bbb" * 100, "c 다.txt": b"ccc" * 100})
    ps = [w.start(["/add", winpath(os.path.join(multi, n))]) for n in ("a.txt", "b.txt", "c 다.txt")]
    win = w.find_window(TITLE_CREATE, 90)
    if win:
        time.sleep(1.5)
        w.key(win, "Return")
    rcs = [w.wait(p, 120) for p in ps]
    made = sorted(f for f in os.listdir(multi) if not f.endswith(".txt"))
    names = []
    if len(made) == 1 and made[0].endswith(".tar"):
        with tarfile.open(os.path.join(multi, made[0])) as tf:
            names = sorted(tf.getnames())
    elif len(made) == 1 and made[0].endswith(".zip"):          # default format once a ZIP writer exists
        with zipfile.ZipFile(os.path.join(multi, made[0])) as zf:
            names = sorted(zf.namelist())
    elif len(made) == 1 and made[0].endswith(".7z") and shutil.which("7z"):    # ... or a 7z writer
        lst = subprocess.run(["7z", "l", "-slt", os.path.join(multi, made[0])], capture_output=True)
        body = lst.stdout.decode("utf-8", "replace").split("\n----------\n", 1)[-1]
        names = sorted(l[7:].strip() for l in body.splitlines() if l.startswith("Path = "))
    t.record(win is not None and rcs == [0, 0, 0] and names == ["a.txt", "b.txt", "c 다.txt"],
             "/add from 3 processes (Explorer multi-selection) -> one archive", "rc=%s made=%s names=%s" %
             (rcs, made, names))

    # ---------- Explorer integration (HKCU only) ----------
    def query(key):
        r = subprocess.run(["wine", "reg", "query", key], env=w.env, capture_output=True, timeout=120)
        return r.returncode, r.stdout.decode("utf-8", "replace")
    cls = r"HKCU\Software\Classes"
    rc = w.run(["/register", "/assoc"])
    menu = [query(cls + k) for k in (r"\*\shell\GogitZIP.compress\shell\2zip\command",
                                     r"\Directory\shell\GogitZIP.compress\shell\1add\command",
                                     r"\*\shell\GogitZIP.2zip\command")]
    has_menu = (menu[0][0] == 0 and "/zip" in menu[0][1] and menu[1][0] == 0) or menu[2][0] == 0
    zip_assoc = query(cls + r"\.zip")
    tgz_assoc = query(cls + r"\.tgz")
    exe_assoc = query(cls + r"\.exe")
    doc_assoc = query(cls + r"\.docx")
    ok = rc == 0 and has_menu and "GogitZIP.Archive" in zip_assoc[1] and "GogitZIP.Archive" in tgz_assoc[1] and \
        "GogitZIP.Archive" not in exe_assoc[1] and "GogitZIP.Archive" not in doc_assoc[1]
    t.record(ok, "/register /assoc: compress verbs, archive types only (not .exe/.docx)",
             "rc=%s menu=%s zip=%r" % (rc, [m[0] for m in menu], zip_assoc[1][-120:]))
    rc = w.run(["/unregister"])
    gone = query(cls + r"\*\shell\GogitZIP.compress")[0] != 0 and query(cls + r"\*\shell\GogitZIP.1add")[0] != 0
    zip_assoc = query(cls + r"\.zip")
    t.record(rc == 0 and gone and "GogitZIP.Archive" not in zip_assoc[1], "/unregister removes menu and association",
             "rc=%s gone=%s" % (rc, gone))

    # ---------- main window: screenshot, nested archive and back ----------
    demo = t.path("demo")
    shutil.rmtree(demo, ignore_errors=True)
    os.makedirs(demo)
    dz = os.path.join(demo, "2026 고기 축제 자료.zip")
    base = "2026 고기 축제/"
    when = (2026, 10, 24, 18, 30, 0)

    def put(z, name, data):
        zi = zipfile.ZipInfo(name, when)
        zi.compress_type = zipfile.ZIP_DEFLATED if data else zipfile.ZIP_STORED
        z.writestr(zi, data)
    with zipfile.ZipFile(dz, "w") as z:
        for sub in ("레시피", "메뉴판", "사진", "정산"):
            put(z, base + sub + "/", b"")
            put(z, base + sub + "/메모.txt", blob(3000, 7))
        put(z, base + "참가 신청서.pdf", blob(212000, 2))
        put(z, base + "포스터.png", blob(1453000, 4))
        put(z, base + "행사 안내.txt", blob(23000, 9))
        inner = io.BytesIO()
        with tarfile.open(fileobj=inner, mode="w:gz") as tf:
            for k in range(3):
                ti = tarfile.TarInfo("작년 행사/사진 %d.jpg" % (k + 1))
                data = blob(40000 + k, 6)
                ti.size = len(data)
                ti.mtime = 1729762200
                tf.addfile(ti, io.BytesIO(data))
        put(z, base + "작년 행사.tar.gz", inner.getvalue())
    # outer size; without a window manager the capture is the client area + menu: 1192x666 as on the web page
    w.settings(WinX=20, WinY=20, WinW=1200, WinH=700, WinMax=0, ShowTree=1, Split=0)
    p = w.start([winpath(dz)])
    win = w.find_window("고기 축제 자료.zip - ", 90)
    shot_ok = nested = back = False
    if win:
        # layout at 96 DPI: tree item of the folder, then the file rows (17 px apart)
        time.sleep(1.5)
        w.click(win, 95, 157)                       # tree: "2026 고기 축제"
        time.sleep(1.0)
        w.click(win, 300, 252)                      # 참가 신청서.pdf
        time.sleep(0.3)
        w.click(win, 300, 269, shift=True)          # .. 포스터.png
        time.sleep(1.0)
        shot_ok = w.shot(win, os.path.join(shots, "main.png"))
        w.click(win, 300, 235, double=True)         # 작년 행사.tar.gz: opens inside, breadcrumb
        nested = w.find_window("» 작년 행사.tar.gz - ", 30) is not None
        if nested:
            time.sleep(1.0)
            w.shot(win, os.path.join(shots, "nested.png"))
            w.click(win, 20, 105)                   # up button at the root of the inner archive
            back = w.find_window("^2026 고기 축제 자료.zip - ", 30) is not None
    w.server_kill()
    w.wait(p, 30)
    t.record(shot_ok, "screenshot: main window", "")
    t.record(nested, "double-click on an inner archive opens it (breadcrumb)", "")
    t.record(back, "up button at the inner root returns to the outer archive", "")

    if os.environ.get("GZ_UPDATE_SCREENS") == "1":
        dst = os.path.join(ROOT, "web", "assets", "screens")
        for f in ("main.png", "create.png"):
            if not os.path.exists(os.path.join(shots, f)):
                continue
            try:                                   # palette PNG like the other screenshots
                from PIL import Image
                im = Image.open(os.path.join(shots, f)).convert("RGB")
                im.quantize(256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(
                    os.path.join(dst, f), optimize=True)
            except ImportError:
                shutil.copy(os.path.join(shots, f), os.path.join(dst, f))
