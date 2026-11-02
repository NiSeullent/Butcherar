"""고깃ZIP GTK 3 front end (src/gtk, src/app/strings.c, data/linux).

* UI strings driver (both languages complete, same placeholders, formatting helpers)
* every src/gtk/*.c and src/app/strings.c compiles with -Werror against gtk+-3.0
* make build/linux/gogitzip-gtk, data/linux checks, make install into a staging folder
* an Xvfb session drives the real app with xdotool:
    main window + extract dialog screenshots (web/assets/screens/linux-main.png,
    linux-extract.png: written when missing or with GZ_UPDATE_SCREENS=1), extraction of a
    selection through the dialog, test, info, nested archive, viewing a file through the
    per-process temporary folder (a test viewer is the default application), questions
    (overwrite with cancel, wrong then right password), a 100,000-entry listing,
    a damaged archive, clean exits and temporary folder removal
* command line modes: --extract-to/-here/-smart, --test, --compress (with --yes and through
  the dialog), replace question, usage errors, --set-default-apps (user mimeapps.list)
"""
import os, io, re, sys, time, shutil, signal, random, tarfile, zipfile, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DT = (2026, 10, 24, 18, 30, 0)
PASSWORD = "meat2026"


def blob(n, text=False, seed=1):
    rnd = random.Random(seed * 1000003 + n)
    if text:
        words = ["고기 ", "축제 ", "삼겹살 ", "목살 ", "안내 ", "zip ", "\n"]
        out = "".join(rnd.choice(words) for _ in range(n // 4))
        return out.encode()[:n]
    return bytes(rnd.getrandbits(8) for _ in range(n))


FEST = [
    ("2026 고기 축제/", None),
    ("2026 고기 축제/레시피/", None),
    ("2026 고기 축제/레시피/양념 갈비.txt", blob(4000, True, 1)),
    ("2026 고기 축제/레시피/수육.txt", blob(3000, True, 2)),
    ("2026 고기 축제/메뉴판/", None),
    ("2026 고기 축제/메뉴판/메뉴판.pdf", blob(90000, False, 3)),
    ("2026 고기 축제/사진/", None),
    ("2026 고기 축제/사진/현장 1.jpg", blob(150000, False, 4)),
    ("2026 고기 축제/사진/현장 2.jpg", blob(140000, False, 5)),
    ("2026 고기 축제/정산/", None),
    ("2026 고기 축제/정산/정산표.xlsx", blob(30000, False, 6)),
    ("2026 고기 축제/참가 신청서.pdf", blob(212000, False, 7)),
    ("2026 고기 축제/포스터.png", blob(400000, False, 8)),
    ("2026 고기 축제/행사 안내.txt", blob(23000, True, 9)),
]
FEST_FILES = {n: d for n, d in FEST if d is not None}


def make_zip(path, entries):
    with zipfile.ZipFile(path, "w") as z:
        for n, d in entries:
            zi = zipfile.ZipInfo(n, DT)
            if d is None:
                zi.external_attr = (0o40755 << 16) | 0x10
                z.writestr(zi, b"")
            else:
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = 0o100644 << 16
                z.writestr(zi, d)


def tree_files(root):
    out = {}
    for dp, dns, fns in os.walk(root):
        for fn in fns:
            fp = os.path.join(dp, fn)
            out[os.path.relpath(fp, root).replace(os.sep, "/")] = open(fp, "rb").read()
    return out


class Session:
    """Xvfb display + the app's environment (HOME, XDG folders, TMPDIR in the work dir)."""

    def __init__(self, t, app, work):
        self.t, self.app, self.work = t, app, work
        self.x = subprocess.Popen(["Xvfb", "-displayfd", "1", "-screen", "0", "1400x900x24", "-nolisten", "tcp"],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        line = b""
        end = time.time() + 20
        while not line.endswith(b"\n") and time.time() < end:
            ch = self.x.stdout.read(1)
            if not ch:
                break
            line += ch
        self.display = ":" + line.decode().strip()
        self.home = os.path.join(work, "home")
        self.tmp = os.path.join(work, "tmp")
        for d in (self.home, self.tmp):
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(d)
        locs = subprocess.run(["locale", "-a"], capture_output=True, text=True).stdout.lower().split()
        self.lang = "ko_KR.UTF-8" if ("ko_kr.utf8" in locs or "ko_kr.utf-8" in locs) else "C.UTF-8"
        self.procs = []

    def env(self, **extra):
        e = {k: v for k, v in os.environ.items() if not k.startswith(("LC_", "XDG_", "DBUS_", "GTK_", "LANG"))}
        e.update(DISPLAY=self.display, HOME=self.home, TMPDIR=self.tmp, LANG=self.lang, LC_ALL=self.lang,
                 XDG_CONFIG_HOME=os.path.join(self.home, ".config"),
                 XDG_DATA_HOME=os.path.join(self.home, ".local", "share"),
                 XDG_CACHE_HOME=os.path.join(self.home, ".cache"), NO_AT_BRIDGE="1", GTK_THEME="Adwaita",
                 GDK_BACKEND="x11", GSETTINGS_BACKEND="memory", GTK_A11Y="none",
                 ASAN_OPTIONS="detect_leaks=0:" + os.environ.get("ASAN_OPTIONS", ""))
        e.update(extra)
        return e

    def settings(self, **kw):
        d = os.path.join(self.home, ".config", "gogitzip")
        os.makedirs(d, exist_ok=True)
        s = {"general": {"language": 1, "threads": 0},
             "extract": {"overwrite": 0, "smart": 1, "open_folder": 0, "paths": 0, "dest_mode": 0},
             "window": {"width": 1192, "height": 666, "tree": 1, "pane": 240, "maximized": 0}}
        for k, v in kw.items():
            g, key = k.split("__")
            s.setdefault(g, {})[key] = v
        with open(os.path.join(d, "settings.ini"), "w") as f:
            for g, kv in s.items():
                f.write("[%s]\n" % g)
                for k, v in kv.items():
                    f.write("%s=%s\n" % (k, v))

    def start(self, args, log):
        args = list(args)
        if self.lang == "C.UTF-8":
            args = ["--lang", "ko"] + args
        p = subprocess.Popen([self.app] + args, env=self.env(), stdout=open(log + ".out", "wb"),
                             stderr=open(log + ".err", "wb"), start_new_session=True)
        p.gz_log = log
        self.procs.append(p)
        return p

    def run(self, args, log, timeout=60):
        p = self.start(args, log)
        return self.finish(p, timeout)

    def finish(self, p, timeout=30):
        try:
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
            rc = "timeout"
        err = open(p.gz_log + ".err", "rb").read().decode("utf-8", "replace")
        if "Sanitizer" in err or "runtime error" in err:
            self.t.record(False, "sanitizer: " + os.path.basename(p.gz_log), err[-1500:])
        return rc

    def xdo(self, *args):
        return subprocess.run(["xdotool"] + list(args), env=self.env(), capture_output=True, text=True, timeout=30)

    def windows(self, name):
        r = self.xdo("search", "--onlyvisible", "--name", name)
        return [w for w in r.stdout.split() if w.isdigit()]

    def wait_window(self, name, timeout=20, count=1, proc=None):
        end = time.time() + timeout
        while time.time() < end:
            w = self.windows(name)
            if len(w) >= count:
                time.sleep(0.4)          # let it draw
                return w[-1]
            if proc is not None and proc.poll() is not None:
                return None
            time.sleep(0.15)
        return None

    def gone(self, wid, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            r = self.xdo("getwindowname", wid)
            if r.returncode != 0 or wid not in self.windows("."):
                return True
            time.sleep(0.15)
        return False

    def keys(self, wid, *keys):
        self.xdo("windowfocus", wid)
        time.sleep(0.15)
        for k in keys:
            self.xdo("key", "--delay", "40", k)
            time.sleep(0.08)

    def type(self, wid, text):
        self.xdo("windowfocus", wid)
        time.sleep(0.15)
        self.xdo("type", "--delay", "30", text)

    def shot(self, wid, path):
        self.xdo("mousemove", "1399", "899")      # no hover effects or tooltips in the picture
        time.sleep(0.3)
        tmp = path + ".raw.png"
        r = subprocess.run(["import", "-window", wid, tmp], env=self.env(), capture_output=True, timeout=60)
        if r.returncode:
            return None
        subprocess.run(["convert", tmp, "-strip", "-define", "png:exclude-chunks=date,time", "+dither",
                        "-colors", "256", "PNG8:" + path],
                       capture_output=True, timeout=60)
        os.remove(tmp)
        r = subprocess.run(["identify", "-format", "%w %h", path], capture_output=True, text=True, timeout=30)
        try:
            return tuple(int(x) for x in r.stdout.split())
        except ValueError:
            return None

    def quit(self, wid, p, label):
        """File menu -> Quit, through the keyboard like a user (again if a slow menu missed the key)."""
        for attempt in range(3):
            self.keys(wid, "Escape", "alt+f")
            time.sleep(0.6 + attempt * 0.6)
            self.xdo("key", "x")
            try:
                p.wait(timeout=6 + attempt * 4)
                break
            except subprocess.TimeoutExpired:
                continue
        rc = self.finish(p, 10)
        err = open(p.gz_log + ".err", "rb").read().decode("utf-8", "replace")
        self.t.record(rc == 0, label + ": quit through the menu, exit 0", "rc=%s %s" % (rc, err[-600:]))
        return rc

    def close(self):
        for p in self.procs:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except OSError:
                    pass
                p.wait()
        self.x.terminate()
        try:
            self.x.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.x.kill()


def temp_left(s):
    """per-process temporary folders still present under TMPDIR/gogitzip-<uid>"""
    par = os.path.join(s.tmp, "gogitzip-%d" % os.getuid())
    return sorted(os.listdir(par)) if os.path.isdir(par) else []


def check_static(t):
    # UI strings
    drv = t.build_driver("tests/drivers/app_ui_strings.c")
    r = t.sh([drv], check=False)
    out = r.stdout.decode("utf-8", "replace")
    t.record(r.returncode == 0 and out.startswith("OK"), "ui strings driver", out[-800:])

    # generated desktop data up to date, launcher and MIME package well formed
    r = t.sh([sys.executable, "-I", os.path.join(ROOT, "tools", "gen_linux_data.py"), "--check"], check=False)
    t.record(r.returncode == 0, "data/linux generated files up to date",
             (r.stdout + r.stderr).decode("utf-8", "replace")[-500:])
    import xml.etree.ElementTree as ET
    for fn in ("gogitzip-mime.xml", "gogitzip.metainfo.xml"):
        try:
            ET.parse(os.path.join(ROOT, "data", "linux", fn))
            t.record(True, "well-formed " + fn)
        except Exception as e:
            t.record(False, "well-formed " + fn, str(e))
    desk = open(os.path.join(ROOT, "data", "linux", "gogitzip.desktop"), encoding="utf-8").read()
    t.record("Exec=gogitzip-gtk %F" in desk and "application/zip;" in desk and "application/x-tar;" in desk,
             "desktop entry: Exec and MIME types")
    if shutil.which("desktop-file-validate"):
        r = t.sh(["desktop-file-validate", os.path.join(ROOT, "data", "linux", "gogitzip.desktop")], check=False)
        t.record(r.returncode == 0, "desktop-file-validate", (r.stdout + r.stderr).decode()[-500:])
    for d in ("nautilus", "dolphin", "thunar"):
        t.record(os.path.isdir(os.path.join(ROOT, "data", "linux", d)), "file manager integration: " + d)
    for s in (16, 32, 48, 128, 256):
        p = os.path.join(ROOT, "data", "linux", "icons", "hicolor", "%dx%d" % (s, s), "apps", "gogitzip.png")
        ok = os.path.exists(p) and open(p, "rb").read(8) == b"\x89PNG\r\n\x1a\n"
        t.record(ok, "hicolor icon %d" % s)


def check_compile(t, cc):
    cf = subprocess.run(["pkg-config", "--cflags", "gtk+-3.0"], capture_output=True, text=True).stdout.split()
    warn = ["-Wall", "-Wextra", "-Wno-unused-parameter", "-Wno-missing-field-initializers",
            "-Wno-cast-function-type", "-Werror"]
    inc = ["-I" + os.path.join(ROOT, d) for d in ("src/core", "src/codec", "src/fmt", "src/app", "src/posix")]
    srcs = sorted(os.path.join("src/gtk", f) for f in os.listdir(os.path.join(ROOT, "src/gtk")) if f.endswith(".c"))
    for src in srcs + ["src/app/strings.c"]:
        r = subprocess.run([cc, "-std=gnu11", "-O2", "-fsyntax-only", "-pthread", "-finput-charset=UTF-8"] + warn +
                           inc + cf + [os.path.join(ROOT, src)], capture_output=True, cwd=ROOT)
        t.record(r.returncode == 0, "-Werror: " + src, r.stderr.decode("utf-8", "replace")[-1500:])


def run(t):
    if os.environ.get("GZ_TEST_EXEC"):
        t.skip("GUI tests run on the build machine only")
    bdir = os.path.dirname(t.gzt)
    in_tree = os.path.realpath(bdir) == os.path.realpath(os.path.join(ROOT, "build"))
    if in_tree:      # engine + strings objects (build/host/app) for the driver; `make build/gzt` leaves them out
        r = subprocess.run(["make", "-C", ROOT, "--no-print-directory", "build/gogitzip"], capture_output=True,
                           timeout=900)
        t.record(r.returncode == 0, "make build/gogitzip", (r.stdout + r.stderr).decode("utf-8", "replace")[-800:])
    if not os.path.exists(os.path.join(bdir, "host", "app", "strings.o")):
        t.skip("build/host/app objects missing: run make build/gogitzip")
    check_static(t)
    if subprocess.run(["pkg-config", "--exists", "gtk+-3.0"]).returncode:
        t.skip("gtk+-3.0 development files missing")
    cc = os.environ.get("HOSTCC", "cc")
    check_compile(t, cc)

    # build (the app links the host objects that `make build/gzt` made with the same HOST_CFLAGS)
    app = os.path.join(bdir, "linux", "gogitzip-gtk")
    if in_tree:
        r = subprocess.run(["make", "-C", ROOT, "--no-print-directory", "build/linux/gogitzip-gtk"],
                           capture_output=True, timeout=900)
        log = (r.stdout + r.stderr).decode("utf-8", "replace")
        t.record(r.returncode == 0 and "warning:" not in log, "make build/linux/gogitzip-gtk (no warnings)",
                 log[-2000:])
        st = os.path.join(t.work, "stage")
        shutil.rmtree(st, ignore_errors=True)
        r = subprocess.run(["make", "-C", ROOT, "--no-print-directory", "install", "PREFIX=/usr", "DESTDIR=" + st],
                           capture_output=True, timeout=900)
        want = ["usr/bin/gogitzip-gtk", "usr/bin/gogitzip", "usr/share/applications/gogitzip.desktop",
                "usr/share/mime/packages/gogitzip.xml", "usr/share/icons/hicolor/48x48/apps/gogitzip.png",
                "usr/share/metainfo/gogitzip.metainfo.xml"]
        miss = [w for w in want if not os.path.exists(os.path.join(st, w))]
        t.record(r.returncode == 0 and not miss, "make install DESTDIR (staging)",
                 (r.stdout + r.stderr).decode("utf-8", "replace")[-800:] + " missing: %s" % miss)
    if not os.path.exists(app):
        t.skip("%s not built" % app)
    t.need("Xvfb", "xdotool", "import", "convert", "identify")

    work = t.work
    fx = os.path.join(work, "fx")
    shutil.rmtree(fx, ignore_errors=True)
    os.makedirs(fx)
    fest = os.path.join(fx, "2026 고기 축제 자료.zip")
    make_zip(fest, FEST)

    s = Session(t, app, work)
    try:
        gui_main(t, s, fest)
        gui_nested_view(t, s, fx)
        gui_questions(t, s, fx)
        gui_big_and_bad(t, s, fx)
        gui_hostile_names(t, s, fx)
        cli_modes(t, s, fx, fest)
    finally:
        s.close()


# ---------------------------------------------------------------- GUI: main window

def gui_main(t, s, fest):
    s.settings()
    # a home like a user's: the archive in ~/Downloads, XDG user folders for the quick buttons
    dirs = {"DESKTOP": "Desktop", "DOCUMENTS": "Documents", "DOWNLOAD": "Downloads"}
    with open(os.path.join(s.home, ".config", "user-dirs.dirs"), "w") as f:
        for k, v in dirs.items():
            os.makedirs(os.path.join(s.home, v), exist_ok=True)
            f.write('XDG_%s_DIR="$HOME/%s"\n' % (k, v))
    fest = shutil.copy(fest, os.path.join(s.home, "Downloads"))
    p = s.start([fest], os.path.join(t.work, "main"))
    wid = s.wait_window("자료.zip - 고깃ZIP", 30, proc=p)
    if not t.record(wid is not None, "main window with the archive"):
        s.finish(p, 1)
        return
    s.keys(wid, "Return")                                  # into "2026 고기 축제"
    time.sleep(0.5)
    s.keys(wid, "Down", "Down", "Down", "Down", "Down", "shift+Down")   # 정산 + 참가 신청서.pdf
    time.sleep(0.5)
    shot = os.path.join(t.work, "linux-main.png")
    size = s.shot(wid, shot)
    t.record(size == (1192, 666), "main window screenshot 1192x666", "size %s" % (size,))

    s.keys(wid, "ctrl+e")
    did = s.wait_window("^압축 풀기$", 15)
    if t.record(did is not None, "extract dialog (Ctrl+E)"):
        shot2 = os.path.join(t.work, "linux-extract.png")
        size2 = s.shot(did, shot2)
        t.record(size2 is not None and 400 <= size2[0] <= 760 and 260 <= size2[1] <= 520,
                 "extract dialog screenshot", "size %s" % (size2,))
        update = os.environ.get("GZ_UPDATE_SCREENS") == "1"
        for src, name in ((shot, "linux-main.png"), (shot2, "linux-extract.png")):
            dst = os.path.join(ROOT, "web", "assets", "screens", name)
            if os.path.exists(src) and (update or not os.path.exists(dst)):
                shutil.copyfile(src, dst)
        # extract the two selected items (smart folder: two top-level items -> "2026 고기 축제 자료/")
        s.keys(did, "Return")
        out = os.path.join(os.path.dirname(fest), "2026 고기 축제 자료")
        want = {"정산/정산표.xlsx": FEST_FILES["2026 고기 축제/정산/정산표.xlsx"],
                "참가 신청서.pdf": FEST_FILES["2026 고기 축제/참가 신청서.pdf"]}
        end = time.time() + 20
        while time.time() < end and (not os.path.isdir(out) or tree_files(out) != want):
            time.sleep(0.2)
        got = tree_files(out) if os.path.isdir(out) else {}
        t.record(got == want, "dialog extraction of the selection (stripped, smart folder)", str(sorted(got)))

    s.keys(wid, "ctrl+t")                                  # test -> result dialog
    rid = s.wait_window("작업 결과", 20)
    if t.record(rid is not None, "test result dialog (Ctrl+T)"):
        s.shot(rid, os.path.join(t.work, "linux-test.png"))
        s.keys(rid, "Return")
        t.record(s.gone(rid), "result dialog closes")
    s.keys(wid, "alt+Return")                              # archive information
    iid = s.wait_window("압축 파일 정보", 15)
    if t.record(iid is not None, "info dialog (Alt+Enter)"):
        s.shot(iid, os.path.join(t.work, "linux-info.png"))
        s.keys(iid, "Escape")
        t.record(s.gone(iid), "info dialog closes")
    s.keys(wid, "BackSpace")                               # up to the root folder
    time.sleep(0.3)
    s.quit(wid, p, "main window")
    t.record(temp_left(s) == [], "no temporary folder left", str(temp_left(s)))


# ---------------------------------------------------------------- GUI: nested archive, viewing a file

def gui_nested_view(t, s, fx):
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w") as tf:
        data = b"inner file\n" * 50
        ti = tarfile.TarInfo("a.txt")
        ti.size = len(data)
        ti.mtime = 1700000000
        tf.addfile(ti, io.BytesIO(data))
    doc = "문서 내용\n".encode() * 100
    nested = os.path.join(fx, "nested.zip")
    make_zip(nested, [("doc.txt", doc), ("inner.tar", inner.getvalue())])
    # a test viewer as the default program for text: copies what it is given
    viewed = os.path.join(t.work, "viewed.txt")
    if os.path.exists(viewed):
        os.remove(viewed)
    viewer = os.path.join(t.work, "viewer.sh")
    with open(viewer, "w") as f:
        f.write('#!/bin/sh\ncp "$1" "%s"\n' % viewed)
    os.chmod(viewer, 0o755)
    apps = os.path.join(s.home, ".local", "share", "applications")
    os.makedirs(apps, exist_ok=True)
    with open(os.path.join(apps, "gz-test-viewer.desktop"), "w") as f:
        f.write("[Desktop Entry]\nType=Application\nName=GZ test viewer\nExec=%s %%f\nMimeType=text/plain;\n"
                "NoDisplay=true\n" % viewer)
    cfg = os.path.join(s.home, ".config")
    os.makedirs(cfg, exist_ok=True)
    with open(os.path.join(cfg, "mimeapps.list"), "w") as f:
        f.write("[Default Applications]\ntext/plain=gz-test-viewer.desktop\n")

    p = s.start([nested], os.path.join(t.work, "nested"))
    wid = s.wait_window("nested.zip - 고깃ZIP", 30, proc=p)
    if not t.record(wid is not None, "nested.zip opened"):
        s.finish(p, 1)
        return
    s.keys(wid, "Return")                                  # doc.txt -> temp folder -> default program
    end = time.time() + 20
    while time.time() < end and not os.path.exists(viewed):
        time.sleep(0.2)
    time.sleep(0.3)
    t.record(os.path.exists(viewed) and open(viewed, "rb").read() == doc, "double-click opens a file with the "
             "default program (via the temporary folder)")
    tmpd = os.path.join(s.tmp, "gogitzip-%d" % os.getuid(), str(p.pid))
    t.record(os.path.isdir(tmpd), "per-process temporary folder exists while running", tmpd)
    s.keys(wid, "Down", "Return")                          # inner.tar opens inside the app
    nid = s.wait_window("nested.zip/inner.tar - 고깃ZIP", 20)
    t.record(nid is not None, "nested archive opens in the app")
    s.keys(wid, "BackSpace")                               # back to the outer archive
    end = time.time() + 10
    back = False
    while time.time() < end and not back:
        back = bool(s.windows("^nested.zip - 고깃ZIP$"))
        time.sleep(0.2)
    t.record(back, "Backspace returns to the outer archive")
    s.quit(wid, p, "nested")
    t.record(not os.path.exists(tmpd), "temporary folder removed at exit", tmpd)


# ---------------------------------------------------------------- GUI: questions

def gui_questions(t, s, fx):
    out = os.path.join(t.work, "q_out")
    shutil.rmtree(out, ignore_errors=True)
    fest = os.path.join(fx, "2026 고기 축제 자료.zip")
    rc = s.run(["--extract-to", out, "--yes", fest], os.path.join(t.work, "q0"))
    t.record(rc == 0, "first extraction", "rc=%s" % rc)
    for dp, dns, fns in os.walk(out):
        for fn in fns:
            with open(os.path.join(dp, fn), "wb") as f:
                f.write(b"OLD")
    s.settings(extract__overwrite=0, general__threads=1)
    p = s.start(["--extract-to", out, fest], os.path.join(t.work, "q1"))
    ow = s.wait_window("파일 덮어쓰기 확인", 20, proc=p)
    if t.record(ow is not None, "overwrite question"):
        s.shot(ow, os.path.join(t.work, "linux-overwrite.png"))
        s.keys(ow, "Return")                               # replace this one
        ow2 = None
        end = time.time() + 15
        while time.time() < end and p.poll() is None:
            w = s.windows("파일 덮어쓰기 확인")
            if w and w[-1] != ow:
                ow2 = w[-1]
                break
            time.sleep(0.15)
        if ow2:
            time.sleep(0.3)
            s.keys(ow2, "Escape")                          # cancel the rest
    rc = s.finish(p, 30)
    files = tree_files(out)
    restored = [k for k, v in files.items() if v != b"OLD"]
    t.record(rc == 255 and len(restored) == 1 and files[restored[0]] == FEST_FILES[restored[0]],
             "replace one file, then cancel (exit 255)", "rc=%s restored=%s" % (rc, restored))

    # password: wrong one first, then the right one
    try:
        import pyzipper
    except ImportError:
        t.record(True, "password dialog skipped (no pyzipper)")
        return
    aes = os.path.join(fx, "secret.zip")
    secret = "비밀 문서\n".encode() * 300
    with pyzipper.AESZipFile(aes, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(PASSWORD.encode())
        z.writestr("비밀.txt", secret)
    out = os.path.join(t.work, "pw_out")
    shutil.rmtree(out, ignore_errors=True)
    p = s.start(["--extract-to", out, aes], os.path.join(t.work, "pw"))
    pw = s.wait_window("비밀번호 입력", 20, proc=p)
    if t.record(pw is not None, "password question"):
        s.type(pw, "wrong")
        s.keys(pw, "Return")
        pw2 = None
        end = time.time() + 15
        while time.time() < end and p.poll() is None:
            w = s.windows("비밀번호 입력")
            if w and w[-1] != pw:
                pw2 = w[-1]
                break
            time.sleep(0.15)
        if t.record(pw2 is not None, "asked again after a wrong password"):
            time.sleep(0.3)
            s.shot(pw2, os.path.join(t.work, "linux-password.png"))
            s.type(pw2, PASSWORD)
            s.keys(pw2, "Return")
    rc = s.finish(p, 30)
    got = tree_files(out) if os.path.isdir(out) else {}
    t.record(rc == 0 and got == {"비밀.txt": secret}, "AES archive extracted with the typed password",
             "rc=%s %s" % (rc, sorted(got)))


# ---------------------------------------------------------------- GUI: 100k entries, damaged archive

def gui_big_and_bad(t, s, fx):
    big = os.path.join(fx, "big.zip")
    n = 100000
    with zipfile.ZipFile(big, "w") as z:
        for i in range(n):
            z.writestr(zipfile.ZipInfo("files/f%06d.txt" % i, DT), b"")
    s.settings()
    t0 = time.time()
    p = s.start([big], os.path.join(t.work, "big"))
    wid = s.wait_window("big.zip - 고깃ZIP", 90, proc=p)
    dt = time.time() - t0
    if t.record(wid is not None, "100,000-entry archive opens", "%.1f s" % dt):
        t.record(dt < 30, "100,000 entries listed in %.1f s" % dt)
        t1 = time.time()
        s.keys(wid, "Return", "End", "ctrl+a", "Home")        # into the folder, scroll, select all
        time.sleep(0.5)
        # sort by size, type and method (header clicks: tree 240 px + name column 270 px ...)
        for x in (555, 735, 1050, 360, 360):
            s.xdo("mousemove", str(x), "148", "click", "1")
            time.sleep(0.3)
        size = s.shot(wid, os.path.join(t.work, "linux-big.png"))
        t.record(size is not None, "responsive with 100,000 rows", "%.1f s" % (time.time() - t1))
        s.quit(wid, p, "big")
    else:
        s.finish(p, 1)

    bad = os.path.join(fx, "damaged.zip")
    data = bytearray(open(os.path.join(fx, "2026 고기 축제 자료.zip"), "rb").read())
    rnd = random.Random(5)
    for _ in range(64):
        data[rnd.randrange(len(data))] ^= 0xFF
    open(bad, "wb").write(bytes(data[: len(data) // 2]))
    p = s.start([bad], os.path.join(t.work, "bad"))
    msg = s.wait_window("^고깃ZIP$", 60, count=2, proc=p)   # generous: CI and loaded machines
    main = s.windows("^고깃ZIP$")
    if t.record(msg is not None and p.poll() is None, "damaged archive: message, app keeps running"):
        s.keys(msg, "Return")
        time.sleep(0.5)
        main = s.windows("^고깃ZIP$")
        if main:
            s.quit(main[0], p, "damaged")
    else:
        s.finish(p, 1)


# ---------------------------------------------------------------- GUI: hostile names

def gui_hostile_names(t, s, fx):
    """deep nesting, very long / control / undecodable / escaping / duplicate names in the views"""
    path = os.path.join(fx, "names.zip")
    deep = "/".join("d%d" % i for i in range(300)) + "/deep.txt"
    entries = [(deep, b"deep"), ("long_" + "가" * 1500 + ".txt", b"long"), ("ctl\x01\x02\x7f\n.txt", b"c"),
               ("../../evil.txt", b"e"), ("/abs/root.txt", b"r"), ("dup.txt", b"1"), ("dup.txt", b"2"),
               ("MARKERMARKER.txt", b"x"), ("a/./b/../c.txt", b"y"), ("trail/", None), ("//", None),
               ("x" * 255 + "/" + "y" * 255 + ".bin", b"z")]
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        make_zip(path, entries)
    bad = b"\xff\xfe\xc0\x80\xed\xa0\x80bad!!"             # not UTF-8 nor CP949: same length as the marker
    data = open(path, "rb").read().replace(b"MARKERMARKER", bad)
    open(path, "wb").write(data)
    s.settings()
    p = s.start([path], os.path.join(t.work, "names"))
    wid = s.wait_window("names.zip - 고깃ZIP", 30, proc=p)
    if not t.record(wid is not None, "hostile names: archive opens"):
        s.finish(p, 1)
        return
    s.keys(wid, "Home")
    s.type(wid, "d0")                                      # type-ahead to the deep chain
    s.keys(wid, "Escape", "Return")
    for _ in range(25):                                    # 25 levels down: ".." is row 0, "dN" row 1
        s.keys(wid, "Down", "Return")
    s.keys(wid, "ctrl+a", "Home", "End")
    time.sleep(0.3)
    s.keys(wid, "alt+Return")
    iid = s.wait_window("압축 파일 정보", 15)
    if iid:
        s.keys(iid, "Escape")
        s.gone(iid)
    t.record(p.poll() is None, "hostile names: navigation 25 levels deep, select all, info")
    s.quit(wid, p, "hostile names")
    out = os.path.join(t.work, "names_out")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    rc = s.run(["--extract-to", out, "--yes", path], os.path.join(t.work, "names_x"))
    escaped = [f for f in ("evil.txt", "root.txt") if os.path.exists(os.path.join(t.work, f))]
    t.record(rc in (0, 1, 2) and not escaped and os.path.exists(os.path.join(out, "evil.txt")),
             "hostile names: --extract-to keeps everything inside", "rc=%s escaped=%s" % (rc, escaped))


# ---------------------------------------------------------------- command line modes

def cli_modes(t, s, fx, fest):
    s.settings()
    d = os.path.join(t.work, "cli")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    out = os.path.join(d, "to")
    rc = s.run(["--extract-to", out, fest, "--yes"], os.path.join(d, "to"))
    t.record(rc == 0 and tree_files(out) == FEST_FILES, "--extract-to: byte-exact", "rc=%s" % rc)

    here = os.path.join(d, "here")
    os.makedirs(here)
    shutil.copy(fest, here)
    rc = s.run(["--extract-here", os.path.join(here, os.path.basename(fest))], os.path.join(d, "here"))
    got = {k: v for k, v in tree_files(here).items() if not k.endswith(".zip")}
    t.record(rc == 0 and got == FEST_FILES, "--extract-here", "rc=%s" % rc)

    smart = os.path.join(d, "smart")
    os.makedirs(smart)
    one = os.path.join(smart, "loose.zip")
    make_zip(one, [("a.txt", b"A" * 10), ("b/c.txt", b"C" * 20)])
    rc = s.run(["--extract-smart", one], os.path.join(d, "smart"))
    got = tree_files(os.path.join(smart, "loose")) if os.path.isdir(os.path.join(smart, "loose")) else {}
    t.record(rc == 0 and got == {"a.txt": b"A" * 10, "b/c.txt": b"C" * 20},
             "--extract-smart: folder named after the archive", "rc=%s %s" % (rc, sorted(os.listdir(smart))))
    shutil.copy(fest, smart)
    rc = s.run(["--extract-smart", os.path.join(smart, os.path.basename(fest))], os.path.join(d, "smart2"))
    t.record(rc == 0 and os.path.isdir(os.path.join(smart, "2026 고기 축제")) and
             not os.path.exists(os.path.join(smart, "2026 고기 축제 자료")),
             "--extract-smart: single top folder used as is", "rc=%s" % rc)

    rc = s.run(["--test", "--yes", fest], os.path.join(d, "test"))
    t.record(rc == 0, "--test ok", "rc=%s" % rc)
    rc = s.run(["--test", "--yes", os.path.join(fx, "damaged.zip")], os.path.join(d, "test_bad"))
    t.record(rc == 2, "--test damaged archive: exit 2", "rc=%s" % rc)
    rc = s.run(["--extract-to"], os.path.join(d, "usage"))
    t.record(rc == 7, "usage error: exit 7", "rc=%s" % rc)

    # compress: direct, then through the dialog, then the replace question
    src = os.path.join(d, "src")
    t.write_tree(src, {"a.txt": b"hello\n", "sub/b.bin": blob(70000, False, 11), "sub/빈 폴더": None,
                       "한글.txt": "가나다\n".encode()})
    arc = os.path.join(d, "c1.tar")
    rc = s.run(["--compress", src, "--output", arc, "--yes"], os.path.join(d, "c1"))
    names = []
    if os.path.exists(arc):
        with tarfile.open(arc) as tf:
            names = sorted(tf.getnames())
            ok = tf.extractfile("src/sub/b.bin").read() == blob(70000, False, 11)
    else:
        ok = False
    t.record(rc == 0 and ok and "src/한글.txt" in names and "src/sub/빈 폴더" in names, "--compress --yes (TAR)",
             "rc=%s %s" % (rc, names))
    p = s.start(["--compress", src, "--format", "tar"], os.path.join(d, "c2"))
    cw = s.wait_window("^새로 압축$", 20, proc=p)
    if t.record(cw is not None, "create dialog"):
        s.shot(cw, os.path.join(t.work, "linux-create.png"))
        s.keys(cw, "Return")
    rc = s.finish(p, 30)
    dflt = os.path.join(d, "src.tar")
    ok = False
    if os.path.exists(dflt):
        with tarfile.open(dflt) as tf:
            ok = "src/a.txt" in tf.getnames()
    t.record(rc == 0 and ok, "--compress through the dialog (default name src.tar)", "rc=%s" % rc)
    before = open(dflt, "rb").read() if os.path.exists(dflt) else b""
    p = s.start(["--compress", src, "--output", dflt, "--format", "tar"], os.path.join(d, "c3"))
    cw = s.wait_window("^새로 압축$", 20, proc=p)
    if cw:
        s.keys(cw, "Return")
        q = s.wait_window("파일 덮어쓰기 확인", 20, proc=p)
        if t.record(q is not None, "replace question for an existing archive"):
            s.keys(q, "Escape")
    rc = s.finish(p, 30)
    t.record(rc == 255 and open(dflt, "rb").read() == before, "replace declined: archive untouched, exit 255",
             "rc=%s" % rc)

    # file associations for this user only
    r = subprocess.run([s.app, "--set-default-apps"], env=s.env(), capture_output=True, timeout=60)
    ml = os.path.join(s.home, ".config", "mimeapps.list")
    txt = open(ml, encoding="utf-8").read() if os.path.exists(ml) else ""
    t.record(r.returncode == 0 and "application/x-tar=gogitzip.desktop" in txt.replace(";", "") and
             "application/zip=gogitzip.desktop" in txt.replace(";", ""),
             "--set-default-apps writes the user's mimeapps.list",
             "rc=%s out=%s" % (r.returncode, r.stdout.decode()[-200:]))
