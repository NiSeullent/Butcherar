"""Regressions of the Windows front end (src/win): build/GogitZip.exe under Wine + Xvfb.

  windows-ui-1  archive text in run-time dialog templates. A DLGITEMTEMPLATEEX title
                that starts with 0xFFFF is an ordinal followed by extraCount bytes of
                creation data, so an archive comment starting with U+FFFF defined the
                following controls (or sent the parser past the template).
                - tests/drivers/win_dlgt.c (MinGW): texts starting with U+FFFF stay
                  strings - the template walked like the dialog manager does and the
                  created dialog have exactly the controls written
                - the archive information dialog of ZIPs whose comment starts with U+FFFF:
                  no control parsed from the comment (WINEDEBUG=+dialog), and with an
                  extraCount of 0xFFFE the dialog still opens
  windows-ui-2  WM_CLOSE posted to the disabled main window (taskkill without /f) while a
                nested archive opens or a test runs: the operation is cancelled and the
                window closes after it - no crash, exit status 0
                (tests/drivers/win_postclose.c posts the message)
  windows-ui-3  selection -> extraction mask (src/win/selmask.c, built natively by
                tests/drivers/win_selmask.c): same entries as the former per-folder prefix
                scan on random trees, linear time for 20000 selected folders; in the GUI,
                Ctrl+A then Ctrl+E on 20000 folders opens the extract dialog in seconds
  windows-ui-4  long paths: /zip next to files whose archive path is longer than
                MAX_PATH*2 makes "<name>.zip", then "<name> (2).zip" (never a shortened,
                extensionless name, never an existing archive replaced); the extract
                dialog refuses a folder whose full path does not fit instead of extracting
                to the previous one

The native part runs everywhere; the rest is skipped without wine, Xvfb, xdotool or MinGW.
"""
import os, sys, shutil, subprocess, time, zipfile, random, bz2, tarfile, warnings

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import app_windows as AW                       # Wine/Xvfb driver shared with app_windows.py

TITLE_INFO = "^압축 파일 정보$"
TITLE_EXTRACT = "^압축 풀기$"
TITLE_APP = "^고깃ZIP$"


# ---------------------------------------------------------------- windows-ui-3 (native)

def tree_zip(path, seed):
    """random folders (some with directory entries, some duplicated, some implicit), files,
    mixed case and Korean names - unique per folder ignoring ASCII case, no file named like
    a folder next to it (where the old and new rules legitimately differ)"""
    rnd = random.Random(seed)
    pool = ["a", "B", "docs", "Src", "사진", "x y", "Data", "lib", "z", "Q2", "문서", "AbC", "t.d"]
    entries = []

    def gen(prefix, depth):
        used = set()

        def pick(ext):
            for _ in range(50):
                n = rnd.choice(pool) + ext if rnd.random() < 0.7 else "n%d%s" % (rnd.randrange(1000), ext)
                if n.lower() not in used:
                    used.add(n.lower())
                    return n
            return None
        for _ in range(rnd.randint(0, 4 if depth < 3 else 0)):
            n = pick("")
            if not n:
                continue
            d = prefix + n + "/"
            if rnd.random() < 0.6:
                entries.append((d, None))
            if rnd.random() < 0.15:
                entries.append((d, None))                  # duplicate directory entry
            gen(d, depth + 1)
        for _ in range(rnd.randint(0, 5)):
            n = pick(rnd.choice([".txt", ".bin", ""]))
            if n:
                entries.append((prefix + n, b"x" * rnd.randrange(30)))
    gen("", 0)
    rnd.shuffle(entries)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")                    # "Duplicate name"
        with zipfile.ZipFile(path, "w") as z:
            for name, data in entries:
                z.writestr(name, data if data is not None else b"")
    return len(entries)


def many_folders_zip(path, nfolders, per):
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return
    with zipfile.ZipFile(path + ".tmp", "w") as z:
        for i in range(nfolders):
            for k in range(per):
                z.writestr("dir%05d/f%d.txt" % (i, k), b"")
    os.replace(path + ".tmp", path)


def selmask_native(t):
    drv = t.build_driver("tests/drivers/win_selmask.c", extra=[os.path.join(ROOT, "src", "win", "selmask.c")])
    bad = []
    for seed in range(8):
        zp = t.path("tree%d.zip" % seed)
        tree_zip(zp, seed)
        r = subprocess.run([drv, "check", zp, str(seed), "300"], capture_output=True, timeout=300)
        out = r.stdout.decode("utf-8", "replace").strip()
        if r.returncode or not out.startswith("ok"):
            bad.append("seed %d: %s" % (seed, out[-300:]))
    t.record(not bad, "selection mask = former per-folder prefix scan (8 random trees, every folder + 300 sets)",
             "; ".join(bad[:2]))
    big = t.path("folders_20k.zip")
    many_folders_zip(big, 20000, 4)
    r = subprocess.run([drv, "time", big], capture_output=True, timeout=600)
    out = r.stdout.decode().strip()
    kv = dict(x.split("=", 1) for x in out.split() if "=" in x)
    ok = r.returncode == 0 and kv.get("selected") == kv.get("entries") == "80000" and float(kv.get("ms", "1e9")) < 1000
    t.record(ok, "selection mask: 20000 folders / 80000 entries selected in well under a second", out)
    return big


# ---------------------------------------------------------------- Wine helpers

def build_exe(t):
    bdir = os.path.dirname(t.gzt)
    exe = os.path.join(bdir, "GogitZip.exe")
    if shutil.which("i686-w64-mingw32-gcc") and os.path.dirname(os.path.abspath(bdir)) == ROOT:
        env = {k: v for k, v in os.environ.items() if not k.startswith("MAKE")}
        r = subprocess.run(["make", "-C", ROOT, "-j4", os.path.relpath(exe, ROOT)], env=env, capture_output=True,
                           timeout=1800)
        if r.returncode:
            t.record(False, "build GogitZip.exe", r.stderr.decode(errors="replace")[-800:])
            return None
    return exe if os.path.exists(exe) else None


def mingw(t, src, out, extra=(), gui=False):
    cmd = ["i686-w64-mingw32-gcc", "-std=gnu11", "-O1", "-DUNICODE", "-D_UNICODE"] + \
          ["-I" + os.path.join(ROOT, d) for d in ("src/core", "src/codec", "src/fmt", "src/app")] + \
          (["-mwindows"] if gui else []) + ["-o", out, os.path.join(ROOT, src)] + \
          [os.path.join(ROOT, e) for e in extra]
    t.sh(cmd)
    return out


def start(w, args, log, debug="-all"):
    env = dict(w.env, WINEDEBUG=debug)
    return subprocess.Popen(["wine", w.exe] + args, env=env, stdout=open(log, "wb"), stderr=subprocess.STDOUT)


def wait_exit(p, timeout):
    try:
        return p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def stop(w, p):
    w.server_kill()
    w.wait(p, 30)


def logtext(log):
    try:
        return open(log, "rb").read().decode("utf-8", "replace")
    except OSError:
        return ""


def crashed(text):
    return "Unhandled page fault" in text or "Unhandled exception" in text or "unhandled exception" in text


def main_window(w, name, timeout=120):
    """the main window showing archive <name> (title "<name> - 고깃ZIP")"""
    return w.find_window("^" + name.replace(".", "\\.") + " - ", timeout)


def click_list(w, win):
    subprocess.run(["xdotool", "mousemove", "--window", win, "600", "400", "click", "1"], env=w.env,
                   capture_output=True)


# ---------------------------------------------------------------- windows-ui-1

def comment_zip(path, mode):
    """one file; the EOCD comment is UTF-8 for U+FFFF U+0041 <extraCount> ... - as an ordinal
    title it would define a whole button ("inject") or skip 64 KiB past the template ("oob")"""
    units = [0xFFFF, 0x0041, 0x0002, 0x0041]
    if mode == "inject":
        units += [0x0101, 0x0101, 0x0200, 0x0001, 0x0001, 0x5001, 0x0010, 0x0030, 0x0100, 0x0030,
                  0x0101, 0x0001, 0xFFFF, 0x0080]
        units += [ord(c) for c in "INJECTED BY ARCHIVE COMMENT"]
    else:
        units[2] = 0xFFFE
        units += [ord(c) for c in "x" * 8]
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("hello.txt", b"hello world\n")
        z.comment = "".join(chr(u) for u in units).encode("utf-8", "surrogatepass")


def check_templates(t, w):
    exe = mingw(t, "tests/drivers/win_dlgt.c", t.path("win_dlgt.exe"), extra=["src/win/dlgt.c"])
    r = subprocess.run(["wine", exe], env=w.env, capture_output=True, timeout=180)
    out = r.stdout.decode(errors="replace").strip()
    t.record(r.returncode == 0 and out.endswith("ok"),
             "dlgt: control texts starting with U+FFFF stay strings (template walk + created dialog)", out[-400:])

    for mode in ("inject", "oob"):
        zp = t.path("comment_%s.zip" % mode)
        comment_zip(zp, mode)
        log = t.path("info_%s.log" % mode)
        # Wine's dialog trace prints every control it parses from the template
        p = start(w, [AW.winpath(zp)], log, debug="+dialog")
        win = main_window(w, os.path.basename(zp), 90)
        info = None
        if win:
            time.sleep(1.5)
            w.key(win, "alt+Return")
            info = w.find_window(TITLE_INFO, 20)
        stop(w, p)
        lines = [l for l in logtext(log).splitlines() if "DIALOG_GetControl32" in l]
        ordinal = [l.strip()[-120:] for l in lines if " #00" in l and "L\"Edit\"" in l]     # the comment's control
        injected = [l.strip()[-120:] for l in lines if "INJECTED" in l]
        what = "defines no control" if mode == "inject" else "with an extraCount of 0xFFFE is no ordinal"
        t.record(info is not None and lines and not ordinal and not injected and not crashed(logtext(log)),
                 "archive information: comment starting with U+FFFF %s" % what,
                 "info=%s controls=%d ordinal=%s injected=%s" % (info, len(lines), ordinal[:1], injected[:1]))


# ---------------------------------------------------------------- windows-ui-2

def slow_tbz(path):
    """a tar.bz2 (multi-stream bzip2) of one 3 GiB file of zeros: 21 KB, seconds to list"""
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return
    K, N = 64 << 20, 48
    ti = tarfile.TarInfo("zero.bin")
    ti.size = N * K - 1024
    ti.mtime = 1700000000
    data = bz2.compress(ti.tobuf(format=tarfile.USTAR_FORMAT), 1) + bz2.compress(b"\0" * K, 1) * N
    open(path + ".tmp", "wb").write(data)
    os.replace(path + ".tmp", path)


def check_close(t, w, postclose):
    slow = t.path("slow.tar.bz2")
    slow_tbz(slow)
    outer = t.path("outer.zip")
    with zipfile.ZipFile(outer, "w") as z:
        z.write(slow, "slow.tar.bz2", compress_type=zipfile.ZIP_STORED)

    # nested open (opener thread reading the parent) when WM_CLOSE arrives
    log = t.path("close_nested.log")
    p = start(w, [AW.winpath(outer)], log)
    win = main_window(w, "outer.zip", 90)
    prc = None
    if win:
        time.sleep(1.5)
        w.click(win, 280, 150, double=True)               # the slow.tar.bz2 row: opens inside
        prc = subprocess.run(["wine", postclose, "1200"], env=w.env, capture_output=True, timeout=120).returncode
    rc = wait_exit(p, 90)
    text = logtext(log)
    if rc is None:
        stop(w, p)
    t.record(prc == 11 and rc == 0 and not crashed(text),
             "WM_CLOSE while a nested archive opens: cancelled, then closed (no crash)",
             "posted-while-disabled=%s rc=%s %s" % (prc == 11, rc, text[-300:] if crashed(text) else ""))

    # test job (engine threads using the archive) when WM_CLOSE arrives
    log = t.path("close_test.log")
    p = start(w, [AW.winpath(slow)], log)
    win = main_window(w, "slow.tar.bz2", 120)
    prc = None
    if win:
        time.sleep(1.0)
        click_list(w, win)
        time.sleep(0.5)
        w.key(win, "ctrl+t")
        prc = subprocess.run(["wine", postclose, "1500"], env=w.env, capture_output=True, timeout=120).returncode
    rc = wait_exit(p, 90)
    text = logtext(log)
    if rc is None:
        stop(w, p)
    t.record(prc == 11 and rc == 0 and not crashed(text),
             "WM_CLOSE while a test job runs: job cancelled, then closed (no crash)",
             "posted-while-disabled=%s rc=%s %s" % (prc == 11, rc, text[-300:] if crashed(text) else ""))


# ---------------------------------------------------------------- windows-ui-3 (GUI)

def check_selall(t, w, big):
    log = t.path("selall.log")
    p = start(w, [AW.winpath(big)], log)
    win = main_window(w, os.path.basename(big), 180)
    dt = None
    if win:
        time.sleep(1.5)
        click_list(w, win)
        time.sleep(0.5)
        w.key(win, "ctrl+a")
        time.sleep(1.0)
        t0 = time.time()
        w.key(win, "ctrl+e")
        if w.find_window(TITLE_EXTRACT, 60):
            dt = time.time() - t0
    stop(w, p)
    t.record(dt is not None and dt < 15, "Ctrl+A, Ctrl+E on 20000 folders: extract dialog within seconds",
             "after %s s" % (None if dt is None else round(dt, 1)))


# ---------------------------------------------------------------- windows-ui-4

def long_dir(base, length):
    """a folder whose Windows path (Z:\\...) has exactly <length> characters"""
    shutil.rmtree(base, ignore_errors=True)
    d = base
    while len(AW.winpath(d)) < length - 101:
        d = os.path.join(d, "s" * 100)
    d = os.path.join(d, "t" * (length - len(AW.winpath(d)) - 1))
    os.makedirs(d)
    return d


def zip_names(p):
    try:
        with zipfile.ZipFile(p) as z:
            return z.namelist()
    except (zipfile.BadZipFile, OSError):
        return None


def check_long_paths(t, w):
    d = long_dir(t.path("lp"), 300)
    stems = ["X" * 230 + "_first", "X" * 230 + "_second"]
    files = [os.path.join(d, s + ".txt") for s in stems]
    for f, s in zip(files, stems):
        open(f, "w").write(s + "\n")
    rcs = [w.run(["/zip", AW.winpath(f)], timeout=300) for f in files]
    first_zip = os.path.join(d, stems[0] + ".zip")
    first = open(first_zip, "rb").read() if os.path.exists(first_zip) else None
    rcs.append(w.run(["/zip", AW.winpath(files[0])], timeout=300))       # "<name>.zip" exists now
    made = sorted(n for n in os.listdir(d) if not n.endswith(".txt"))
    want = sorted([stems[0] + ".zip", stems[1] + ".zip", stems[0] + " (2).zip"])
    contents = {n: zip_names(os.path.join(d, n)) for n in made}
    ok = rcs == [0, 0, 0] and made == want and \
        all(contents[n] == [(stems[1] if "_second" in n else stems[0]) + ".txt"] for n in made) and \
        first is not None and open(first_zip, "rb").read() == first
    t.record(ok, "/zip next to files with 541-character archive paths: <name>.zip, then <name> (2).zip",
             "rc=%s made=%s" % (rcs, [("..." + n[-16:], len(n), [c[-12:] for c in contents[n] or []])
                                     for n in made]))

    # extract dialog: "\aaa..." fits the field but its full path does not fit the buffer
    src = t.write_tree(t.path("xsrc"), {})
    zp = os.path.join(src, "pick.zip")
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("inside.txt", b"inside\n")
    log = t.path("xdlg.log")
    p = start(w, ["/extract", AW.winpath(zp)], log)
    dlg = w.find_window(TITLE_EXTRACT, 90)
    box = None
    if dlg:
        time.sleep(1.0)
        w.key(dlg, "Tab", "Tab")                              # OK -> Cancel -> destination field
        time.sleep(0.3)
        subprocess.run(["xdotool", "type", "--window", dlg, "--delay", "4", "\\" + "a" * 518], env=w.env,
                       capture_output=True, timeout=120)
        time.sleep(0.5)
        w.key(dlg, "Return")
        box = w.find_window(TITLE_APP, 15)
        time.sleep(2.0)
    extracted = sorted(set(os.listdir(src)) - {"pick.zip"})
    stop(w, p)
    t.record(dlg is not None and box is not None and not extracted,
             "extract dialog: a folder whose full path does not fit is refused (not the previous folder)",
             "dialog=%s message=%s extracted=%s" % (dlg, box, extracted))


# ---------------------------------------------------------------- main

def run(t):
    big = selmask_native(t)
    t.need("wine", "Xvfb", "xdotool", "i686-w64-mingw32-gcc")
    lock = AW.prefix_lock(t)          # one Wine user of the prefix (and one exe build) at a time
    try:
        exe = build_exe(t)
        if not exe:
            t.skip("build/GogitZip.exe not built")
        postclose = mingw(t, "tests/drivers/win_postclose.c", t.path("win_postclose.exe"), gui=True)
        w = AW.Wine(t, exe)
        try:
            w.settings(OpenFolder=0, Overwrite=1, SmartFolder=1, Threads=0, ShowTree=1, Split=0, WinX=20, WinY=20,
                       WinW=1200, WinH=700, WinMax=0, DestMode=0, Dest="")
            check_templates(t, w)
            check_close(t, w, postclose)
            check_selall(t, w, big)
            check_long_paths(t, w)
        finally:
            w.close()
    finally:
        lock.close()
