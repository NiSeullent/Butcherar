"""Regressions of the GTK / macOS front ends and the desktop integration data (gtk-mac-1..8).

Everywhere:
* gtk-mac-2  the Nautilus scripts end the options with "--": selected names starting with
             "-" ("-y", "-o", "-photos.zip") reach gogitzip-gtk as file names (stub program)
* gtk-mac-7  every readable extension is mapped to a MIME type or deliberately left out
             (gen_linux_data.py --check fails otherwise); ALZ / EGG are in the launcher,
             the file manager menus and the --set-default-apps table
* gtk-mac-3/4/5/1/8 (source checks): no g_main_context_invoke() for questions; gzPathW sizes
             its buffer for the decomposed file system representation; no NSString "%s"
             (system encoding, not UTF-8) in src/mac; the macOS extract sheet and create dialog
             keep to the archive / --output they were opened for
With gtk+-3.0, Xvfb and xdotool, the real GTK app:
* gtk-mac-1  an archive dropped on the main window while the extract dialog is open is refused,
             and confirming the dialog extracts the selection of the archive it was opened for
             (formerly: the other archive's entries, through a heap over-read of the old mask)
* gtk-mac-3  a password asked before the UI thread enters gtk_main() (header-encrypted 7z,
             gtk_main() delayed by an LD_PRELOAD shim) is shown by the UI thread only
* gtk-mac-8  --compress --output OTHER (without --yes) creates OTHER, in the format of its
             extension, after the create dialog
* gtk-mac-2  the "extract here" script extracts "-photos.zip" (formerly: usage error, exit 7)
* gtk-mac-6  --set-default-apps from a folder named Bob's "$x" `y` \\apps (and one with a '%')
             writes a launcher GIO can start (formerly shell quoting: "Desktop file didn't
             specify Exec field")
"""
import os, re, sys, glob, time, shutil, signal, zipfile, importlib.util, subprocess, unicodedata

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(ROOT, "data", "linux", "nautilus")
APP_NAME = "gogitzip" + "-gtk"
SIG_7Z = b"7z\xbc\xaf\x27\x1c"


def load_app_gtk():
    """the Xvfb session and helpers of tests/cases/app_gtk.py"""
    spec = importlib.util.spec_from_file_location("regress_app_gtk", os.path.join(HERE, "app_gtk.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def src(rel):
    return open(os.path.join(ROOT, rel), encoding="utf-8").read()


def c_function(text, signature):
    """body of the function / method whose definition starts with signature (brace matching)"""
    i = text.find(signature)
    if i < 0:
        return ""
    j = text.find("{", i)
    depth = 0
    for k in range(j, len(text)):
        depth += {"{": 1, "}": -1}.get(text[k], 0)
        if depth == 0:
            return text[i:k + 1]
    return text[i:]


# ---------------------------------------------------------------- gtk-mac-2: Nautilus scripts

def check_nautilus_args(t):
    scripts = sorted(glob.glob(os.path.join(SCRIPTS, "*")))
    t.record(len(scripts) == 4, "four Nautilus scripts", str([os.path.basename(s) for s in scripts]))
    stub_dir = t.path("stub", "bin", "x")[:-2]
    stub = os.path.join(stub_dir, APP_NAME)
    log = t.path("stub", "argv.txt")
    with open(stub, "w") as f:
        f.write('#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a"; done > "$GZ_ARGV_LOG"\n')
    os.chmod(stub, 0o755)
    sel = ["-y", "-o", "x.zip", "--level", "-photos.zip", "--", "plain.zip"]
    for s in scripts:
        mode = re.search(r"exec \S+ (--[a-z-]+)", open(s, encoding="utf-8").read())
        if os.path.exists(log):
            os.remove(log)
        env = dict(os.environ, PATH=stub_dir + os.pathsep + os.environ.get("PATH", ""), GZ_ARGV_LOG=log)
        r = subprocess.run(["sh", s] + sel, env=env, capture_output=True, timeout=30)
        got = open(log).read().split("\n")[:-1] if os.path.exists(log) else None
        want = [mode.group(1) if mode else "?", "--"] + sel
        t.record(r.returncode == 0 and got == want, "nautilus %s: names after \"--\"" % os.path.basename(s),
                 "got %r" % (got,))


# ---------------------------------------------------------------- gtk-mac-7: desktop data

def check_linux_data(t):
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    try:
        import gen_linux_data as g
    finally:
        sys.path.pop(0)
    readable = g.readable_exts()
    t.record({"alz", "egg"} <= readable, "ALZ and EGG readers present", " ".join(sorted(readable))[:300])
    missing = sorted(readable - {e for e, _ in g.EXT_MIME} - set(g.DOCS))
    t.record(not missing, "every readable extension mapped or deliberately left out", " ".join(missing))
    r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "tools", "gen_linux_data.py"), "--check"],
                       capture_output=True, timeout=120)
    t.record(r.returncode == 0, "gen_linux_data.py --check", (r.stdout + r.stderr).decode()[-400:])
    # a reader with an unclassified extension makes --check fail (it used to print a note only)
    probe = ("import sys; sys.path.insert(0, %r); import gen_linux_data as g; "
             "old = g.readable_exts; g.readable_exts = lambda: old() | {'zzqq'}; "
             "sys.argv = ['gen_linux_data.py', '--check']; g.main()" % os.path.join(ROOT, "tools"))
    r = subprocess.run([sys.executable, "-I", "-c", probe], capture_output=True, timeout=120)
    t.record(r.returncode == 1 and b"zzqq" in r.stdout, "--check fails on an unmapped readable extension",
             "rc=%s %s" % (r.returncode, (r.stdout + r.stderr).decode()[-300:]))

    desk = src("data/linux/gogitzip.desktop")
    mt = re.search(r"^MimeType=(.*)$", desk, re.M)
    types = set(mt.group(1).split(";")) if mt else set()
    t.record({"application/x-alz", "application/x-egg"} <= types, "launcher MimeType has ALZ and EGG")
    hdr = src("src/gtk/mimetypes.h")
    t.record('{ "alz", "application/x-alz" }' in hdr and '{ "egg", "application/x-egg" }' in hdr,
             "--set-default-apps table (mimetypes.h) has ALZ and EGG")
    xml = src("data/linux/gogitzip-mime.xml")
    m = re.search(r'<mime-type type="application/x-egg">(.*?)</mime-type>', xml, re.S)
    t.record(bool(m) and '<glob pattern="*.egg"/>' in m.group(1), "MIME package defines application/x-egg (*.egg)")
    thunar = src("data/linux/thunar/uca-gogitzip.xml")
    t.record("*.alz" in thunar and "*.egg" in thunar and "*.ALZ" in thunar, "Thunar actions match .alz / .egg")
    dol = src("data/linux/dolphin/gogitzip-extract.desktop")
    t.record("application/x-alz;" in dol and "application/x-egg;" in dol, "Dolphin menu offered for ALZ / EGG")


# ---------------------------------------------------------------- source checks

def check_sources(t):
    run_c = src("src/gtk/run.c")
    t.record(not re.search(r"g_main_context_invoke\w*\s*\(", re.sub(r"/\*.*?\*/", "", run_c, flags=re.S)),
             "gtk-mac-3: questions are queued to the UI thread (no g_main_context_invoke)")
    mw = src("src/gtk/mainwnd.c")
    ce = c_function(mw, "static void cmd_extract(int mode)")
    t.record("M.gen != gen" in ce and "M.h != h" in ce, "gtk-mac-1: cmd_extract drops a mask built for another archive")
    drop = c_function(mw, "static void on_drop(")
    t.record("gtk_grab_get_current()" in drop and "busy()" in drop,
             "gtk-mac-1: drops refused while a modal dialog or a job runs")

    util = src("src/mac/util.m")
    pw = c_function(util, "gzch *gzPathW(NSString *path)")
    t.record("CFStringGetMaximumSizeOfFileSystemRepresentation" in pw and "maximumLengthOfBytesUsingEncoding" not in pw,
             "gtk-mac-4: gzPathW sizes the buffer for the decomposed representation",
             re.sub(r"\s+", " ", pw)[:240])
    # why: the HFS+ decomposition of precomposed Hangul needs up to 9 bytes per UTF-16 unit
    samples = ["/Users/kim/문서/프로젝트/고객사 납품용 설계 도면 모음.7z", "/Users/kim/Desktop/압축파일/한글이름압축파일입.zip",
               "/Users/kim/Downloads/" + "가" * 30 + ".zip"]
    rows = []
    for p in samples:
        n16 = len(p.encode("utf-16-le")) // 2
        need = len(unicodedata.normalize("NFD", p).encode()) + 1
        rows.append((3 * n16 + 16 < need, need <= 9 * n16 + 1))
    t.record(all(a for a, b in rows) and all(b for a, b in rows),
             "gtk-mac-4 model: 3*len+16 too small for Korean NFC paths, CF's 9*len+1 enough", str(rows))

    bad = []
    for p in sorted(glob.glob(os.path.join(ROOT, "src", "mac", "*.[mh]"))):
        text = open(p, encoding="utf-8").read()
        for m in re.finditer(r'@"((?:[^"\\]|\\.)*)"', text):
            if re.search(r"%(?:[-+ #0]*\d*(?:\.\d+)?)l?s", m.group(1)):
                bad.append("%s:%d" % (os.path.basename(p), text.count("\n", 0, m.start()) + 1))
    t.record(not bad, "gtk-mac-5: no NSString %s formats in src/mac (UTF-8 goes through gzU8 and %@)", " ".join(bad))

    mwm = src("src/mac/mainwnd.m")
    em = c_function(mwm, "- (void)extractMode:(int)mode")
    t.record("self->_gen == gen" in em and "self->_h == h" in em,
             "gtk-mac-1 (macOS): the extract sheet's mask is used only for the archive it was built for")
    mm = c_function(src("src/mac/main.m"), "- (void)compressFromCommandLine")
    t.record(bool(re.search(r"dlgCreate\(nil, paths, _output\.length \? absPath\(_output\) : nil, _format,", mm)),
             "gtk-mac-8 (macOS): the create dialog proposes --output / --format")
    dm = c_function(src("src/mac/dialogs.m"), "void dlgCreate(")
    t.record("output.length ? output : defaultArchiveName" in dm, "gtk-mac-8 (macOS): dlgCreate shows the given name")


# ---------------------------------------------------------------- GTK app

def build_helpers(t):
    cf = subprocess.run(["pkg-config", "--cflags", "--libs", "gtk+-3.0"], capture_output=True, text=True).stdout.split()
    cc = os.environ.get("HOSTCC", "cc")
    drag = t.path("helpers", "gtk_dragsrc")
    r = subprocess.run([cc, "-O1", "-o", drag, os.path.join(ROOT, "tests", "drivers", "gtk_dragsrc.c")] + cf,
                       capture_output=True, timeout=300)
    t.record(r.returncode == 0, "build tests/drivers/gtk_dragsrc.c", r.stderr.decode()[-600:])
    shim = t.path("helpers", "gtk_thread_shim.so")
    r2 = subprocess.run([cc, "-shared", "-fPIC", "-O1", "-o", shim,
                         os.path.join(ROOT, "tests", "drivers", "gtk_thread_shim.c"), "-ldl", "-pthread"],
                        capture_output=True, timeout=300)
    t.record(r2.returncode == 0, "build tests/drivers/gtk_thread_shim.c", r2.stderr.decode()[-600:])
    return (drag if r.returncode == 0 else None), (shim if r2.returncode == 0 else None)


def txt_files(root):
    out = []
    for dp, dns, fns in os.walk(root):
        out += [f for f in fns if f.endswith(".txt")]
    return sorted(out)


def gui_drop_during_extract(t, s, drag):
    d = t.path("drop", "data", "x")[:-2]
    for f in os.listdir(d):
        p = os.path.join(d, f)
        shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
    small, big = os.path.join(d, "small.zip"), os.path.join(d, "big.zip")
    with zipfile.ZipFile(small, "w") as z:
        for i in range(3):
            z.writestr("small%d.txt" % i, "x" * 10)
    with zipfile.ZipFile(big, "w") as z:
        for i in range(4000):
            z.writestr("big%05d.txt" % i, "y")
    s.settings()
    p = s.start([small], os.path.join(t.work, "drop_app"))
    wid = s.wait_window("^small.zip - 고깃ZIP$", 30, proc=p)
    if not t.record(wid is not None, "gtk-mac-1: small.zip open"):
        s.finish(p, 1)
        return
    s.keys(wid, "ctrl+a")
    time.sleep(0.3)
    s.keys(wid, "ctrl+e")
    dlg = s.wait_window("^압축 풀기$", 15, proc=p)
    if not t.record(dlg is not None, "gtk-mac-1: extract dialog over the selection"):
        s.finish(p, 1)
        return
    dp = subprocess.Popen([drag, big], env=s.env(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    s.procs.append(dp)
    sw = s.wait_window("^gz-dragsrc$", 15)
    ended = False
    if t.record(sw is not None, "gtk-mac-1: drag source window"):
        def geom(w):
            g = {}
            for line in s.xdo("getwindowgeometry", "--shell", w).stdout.split():
                k, _, v = line.partition("=")
                if v.lstrip("-").isdigit():
                    g[k] = int(v)
            return g
        sg, mg = geom(sw), geom(wid)
        sx, sy = sg.get("X", 0) + 40, sg.get("Y", 0) + 40
        tx, ty = mg.get("X", 0) + 60, mg.get("Y", 0) + mg.get("HEIGHT", 600) - 80   # folder tree, beside the dialog
        s.xdo("mousemove", str(sx), str(sy))
        time.sleep(0.3)
        s.xdo("mousedown", "1")
        time.sleep(0.2)
        for k in range(1, 21):
            s.xdo("mousemove", str(sx + (tx - sx) * k // 20), str(sy + (ty - sy) * k // 20))
            time.sleep(0.05)
        time.sleep(0.5)
        s.xdo("mouseup", "1")
        # the drag is over when the source says so; then give a wrongly accepted drop time to open
        import select
        end = time.time() + 15
        while time.time() < end and not ended:
            rd, _, _ = select.select([dp.stdout], [], [], 0.5)
            if rd:
                line = dp.stdout.readline()
                ended = line.startswith(b"end") or not line
        t.record(ended, "gtk-mac-1: the drag finished")
        time.sleep(3)
    replaced = bool(s.windows("^big.zip - 고깃ZIP$"))
    t.record(not replaced and bool(s.windows("^small.zip - 고깃ZIP$")),
             "gtk-mac-1: drop refused while the extract dialog is open (small.zip still shown)")
    s.keys(dlg, "Return")                                 # confirm: extract the 3 selected entries
    end = time.time() + 30
    got = []
    while time.time() < end:
        got = txt_files(d)
        if len(got) >= 3 and not s.windows("^압축 풀기$"):
            time.sleep(1.0)                               # a wrong extraction would still be adding files
            got = txt_files(d)
            break
        time.sleep(0.2)
    t.record(got == ["small0.txt", "small1.txt", "small2.txt"],
             "gtk-mac-1: the dialog extracts the selection of the archive it was opened for",
             "%d files: %s" % (len(got), got[:6]))
    if dp.poll() is None:
        dp.kill()
        dp.wait()
    s.quit(wid, p, "gtk-mac-1")


def gui_ask_before_main_loop(t, s, shim):
    cli = os.path.join(os.path.dirname(t.gzt), "gogitzip")
    w = t.path("ask", "x")[:-2]
    for f in os.listdir(w):
        p = os.path.join(w, f)
        shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
    secret = "비밀 내용\n".encode() * 50
    with open(os.path.join(w, "f.txt"), "wb") as f:
        f.write(secret)
    r = subprocess.run([cli, "a", "-bd", "-p", "meat2026", "--encrypt-names", "enc.7z", "f.txt"], cwd=w,
                       capture_output=True, timeout=120)
    os.remove(os.path.join(w, "f.txt"))
    if not t.record(r.returncode == 0, "gtk-mac-3: header-encrypted 7z made", r.stderr.decode()[-300:]):
        return
    s.settings()
    env = s.env(LD_PRELOAD=shim, GZ_SHIM_DELAY_MS="1500",
                ASAN_OPTIONS="detect_leaks=0:verify_asan_link_order=0:" + os.environ.get("ASAN_OPTIONS", ""))
    log = os.path.join(t.work, "ask_app")
    args = ["--extract-here", os.path.join(w, "enc.7z")]
    if s.lang == "C.UTF-8":
        args = ["--lang", "ko"] + args
    p = subprocess.Popen([s.app] + args, env=env, stdout=open(log + ".out", "wb"), stderr=open(log + ".err", "wb"),
                         start_new_session=True)
    p.gz_log = log
    s.procs.append(p)
    pw = s.wait_window("비밀번호 입력", 30, proc=p)
    if pw:
        s.type(pw, "meat2026")
        s.keys(pw, "Return")
    rc = s.finish(p, 60)
    err = open(log + ".err", "rb").read().decode("utf-8", "replace")
    off = [l for l in err.splitlines() if l.startswith("GZSHIM:")]
    t.record(not off, "gtk-mac-3: question UI built on the UI thread only (gtk_main delayed 1.5 s)",
             " | ".join(off[:4]))
    out = os.path.join(w, "f.txt")
    t.record(pw is not None and rc == 0 and os.path.exists(out) and open(out, "rb").read() == secret,
             "gtk-mac-3: password asked, archive extracted", "rc=%s pw=%s %s" % (rc, pw, err[-300:]))


def gui_compress_output(t, s):
    w = t.path("out8", "x")[:-2]
    shutil.rmtree(w, ignore_errors=True)
    os.makedirs(os.path.join(w, "src", "dir", "sub"))
    os.makedirs(os.path.join(w, "other"))
    with open(os.path.join(w, "src", "dir", "a.txt"), "wb") as f:
        f.write(b"hello\n" * 100)
    with open(os.path.join(w, "src", "dir", "sub", "b.txt"), "wb") as f:
        f.write("고기\n".encode() * 100)
    target = os.path.join(w, "other", "name.7z")
    s.settings()
    p = s.start(["--compress", os.path.join(w, "src", "dir"), "--output", target], os.path.join(t.work, "out8_app"))
    cw = s.wait_window("^새로 압축$", 20, proc=p)
    if t.record(cw is not None, "gtk-mac-8: create dialog"):
        s.keys(cw, "Return")
    rc = s.finish(p, 60)
    head = open(target, "rb").read(6) if os.path.exists(target) else b""
    t.record(rc == 0 and head == SIG_7Z and not os.path.exists(os.path.join(w, "src", "dir.zip")),
             "gtk-mac-8: --compress --output OTHER.7z without --yes creates OTHER.7z (7z)",
             "rc=%s head=%r files=%s" % (rc, head, sorted(os.listdir(os.path.join(w, "src")))))


def gui_nautilus_real(t, s, bindir):
    w = t.path("naut", "x")[:-2]
    shutil.rmtree(w, ignore_errors=True)
    os.makedirs(w)
    with zipfile.ZipFile(os.path.join(w, "-photos.zip"), "w") as z:
        z.writestr("a.txt", "hello")
    script = os.path.join(SCRIPTS, "고깃ZIP - 여기에 풀기")
    s.settings()
    env = s.env(PATH=bindir + os.pathsep + os.environ.get("PATH", ""))
    r = subprocess.run(["sh", script, "-photos.zip"], cwd=w, env=env, capture_output=True, timeout=60)
    a = os.path.join(w, "a.txt")
    t.record(r.returncode == 0 and os.path.exists(a) and open(a).read() == "hello",
             "gtk-mac-2: Nautilus 'extract here' of -photos.zip (relative name)",
             "rc=%s %s" % (r.returncode, r.stderr.decode("utf-8", "replace")[-300:]))


def launcher_case(t, app, name, folder, exact):
    """--set-default-apps from a copy of the app in folder (no launcher installed), then what a
    file manager does on a double click: GIO parses the user launcher and starts its Exec"""
    w = t.path("assoc", name, "x")[:-2]
    shutil.rmtree(w, ignore_errors=True)
    odd = os.path.join(w, folder)
    home = os.path.join(w, "home")
    share = os.path.join(w, "sysshare")
    for d in (odd, home, share):
        os.makedirs(d)
    os.symlink("/usr/share/mime", os.path.join(share, "mime"))          # MIME database only, no launchers
    exe = os.path.join(odd, APP_NAME)
    shutil.copy(app, exe)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("XDG_", "DBUS_", "DISPLAY", "WAYLAND", "GIO_", "GTK_"))}
    env.update(HOME=home, XDG_DATA_HOME=os.path.join(home, ".local", "share"),
               XDG_CONFIG_HOME=os.path.join(home, ".config"), XDG_DATA_DIRS=share,
               XDG_CONFIG_DIRS=os.path.join(w, "nowhere"), ASAN_OPTIONS="detect_leaks=0")
    r = subprocess.run([exe, "--set-default-apps"], env=env, capture_output=True, timeout=120)
    out = r.stdout.decode().strip()
    t.record(r.returncode == 0 and out.isdigit() and int(out) > 30,
             "gtk-mac-6 %s: --set-default-apps from %r" % (name, folder),
             "rc=%s out=%s %s" % (r.returncode, out, r.stderr.decode()[-300:]))
    rec = os.path.join(w, "launched.txt")
    os.remove(exe)                                   # the launcher now starts a recorder instead
    quoted = "'" + rec.replace("'", "'\\''") + "'"
    with open(exe, "w") as f:
        f.write('#!/bin/sh\n{ printf "%%s\\n" "$0"; for a in "$@"; do printf "%%s\\n" "$a"; done; } > %s\n' % quoted)
    os.chmod(exe, 0o755)
    arc = os.path.join(w, "t.zip")
    with zipfile.ZipFile(arc, "w") as z:
        z.writestr("a.txt", "x")
    r = subprocess.run(["gio", "open", arc], env=env, capture_output=True, timeout=60)
    end = time.time() + 15
    while time.time() < end and not os.path.exists(rec):
        time.sleep(0.2)
    time.sleep(0.3)
    got = open(rec).read().split("\n")[:-1] if os.path.exists(rec) else None
    ok = bool(got) and len(got) == 2 and got[1] == arc and \
        (got[0] == exe if exact else os.path.realpath(got[0]) == os.path.realpath(exe))
    t.record(ok, "gtk-mac-6 %s: GIO starts the user launcher with the archive" % name,
             "gio rc=%s %s got=%r" % (r.returncode, r.stderr.decode()[-300:], got))


def check_launcher_quoting(t, app):
    if not shutil.which("gio"):
        t.record(True, "gtk-mac-6: skipped (no gio)")
        return
    # quote, double quote, $, backquote, backslash and spaces: Desktop Entry quoting in Exec
    launcher_case(t, app, "quoting", "Bob's \"$x\" `y` \\apps", True)
    # a '%' cannot be written so that GIO both finds and runs the program: a link stands in
    launcher_case(t, app, "percent", "100% sure", False)


def guarded(t, fn, *args):
    """one group of checks: an exception fails the group, the next groups still run"""
    try:
        return fn(*args)
    except Exception:
        import traceback
        t.record(False, "exception in " + fn.__name__, traceback.format_exc()[-1200:])
        return None


def run(t):
    guarded(t, check_nautilus_args, t)
    guarded(t, check_linux_data, t)
    guarded(t, check_sources, t)

    if os.environ.get("GZ_TEST_EXEC"):
        t.skip("GUI tests run on the build machine only")
    if subprocess.run(["pkg-config", "--exists", "gtk+-3.0"]).returncode:
        t.skip("gtk+-3.0 development files missing")
    G = load_app_gtk()
    bdir = os.path.dirname(t.gzt)
    if os.path.realpath(bdir) == os.path.realpath(os.path.join(ROOT, "build")):
        r = G.make_locked(bdir, ["build/gogitzip", "build/linux/" + APP_NAME])
        t.record(r.returncode == 0, "make the GTK app", (r.stdout + r.stderr).decode("utf-8", "replace")[-800:])
    app = os.path.join(bdir, "linux", APP_NAME)
    if not os.path.exists(app):
        t.skip("%s not built" % app)
    guarded(t, check_launcher_quoting, t, app)
    t.need("Xvfb", "xdotool")
    drag, shim = build_helpers(t)
    s = G.Session(t, app, t.work)
    try:
        if drag:
            guarded(t, gui_drop_during_extract, t, s, drag)
        if shim and os.path.exists(os.path.join(bdir, "gogitzip")):
            guarded(t, gui_ask_before_main_loop, t, s, shim)
        guarded(t, gui_compress_output, t, s)
        guarded(t, gui_nautilus_real, t, s, os.path.dirname(app))
    finally:
        s.close()
