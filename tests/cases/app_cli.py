"""gogitzip command line tool + portable engine: extraction (zip/tar/tgz), overwrite modes,
smart / stripped / flat extraction, link policy, permissions and times, passwords (-p and a
terminal prompt), test command, TAR creation, Korean messages, exit codes, hostile input."""
import os, io, sys, stat, time, random, shutil, select, subprocess, tarfile, zipfile

MT = 1500000000                      # base mtime of the fixtures
# optional runner for the C drivers when they are built for another CPU,
# e.g. GZ_TEST_EXEC="qemu-aarch64 -cpu max" HOSTCC=aarch64-linux-gnu-gcc
EXEC = os.environ.get("GZ_TEST_EXEC", "").split()


def blob(n, kind=0, seed=1):
    rnd = random.Random(seed * 7919 + n)
    if kind == 0:
        return bytes(rnd.getrandbits(8) for _ in range(n))
    words = ["고기", "삼겹살", "목살", "갈비", "zip", "archive", "hello", "world", "\n"]
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(words).encode() + b" "
    return bytes(out[:n])


FILES = {
    "top/readme.txt": blob(5000, 1),
    "top/문서/보고서.txt": blob(120000, 1),
    "top/문서/사진/고기.jpg": blob(70000, 0),
    "top/empty.txt": b"",
    "top/deep/a/b/c/d/e.bin": blob(300000, 1, 2),
    "top/big.bin": blob(3 << 20, 1, 3),
    "top/run.sh": b"#!/bin/sh\necho hi\n",
}
DIRS = ["top", "top/문서", "top/문서/사진", "top/deep", "top/deep/a", "top/deep/a/b", "top/deep/a/b/c",
        "top/deep/a/b/c/d", "top/빈폴더"]
MODES = {"top/run.sh": 0o755}
FMT = {k: MT + 1000 * i for i, k in enumerate(sorted(FILES))}
DMT = {k: MT - 1000 * (i + 1) for i, k in enumerate(DIRS)}


class Ctx:
    def __init__(self, t):
        self.t = t
        self.cli = os.path.join(os.path.dirname(t.gzt), "gogitzip")

    def env(self, lang="C.UTF-8", **extra):
        e = {k: v for k, v in os.environ.items() if k not in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE")}
        e["LANG"] = lang
        e.update(extra)
        return e

    def run(self, args, cwd=None, env=None, input=None, timeout=120):
        try:
            r = subprocess.run([self.cli] + list(args), cwd=cwd or self.t.work, env=env or self.env(),
                               input=input if input is not None else b"", capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return -999, "", "timeout"
        out, err = r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")
        if "Sanitizer" in err or "runtime error" in err:
            self.t.record(False, "sanitizer: " + " ".join(map(str, args))[:80], err[-1500:])
        return r.returncode, out, err

    def check(self, ok, label, detail=""):
        return self.t.record(ok, label, detail if not ok else "")

    def fresh(self, name):
        p = os.path.join(self.t.work, name)
        if os.path.lexists(p):
            if os.path.isdir(p) and not os.path.islink(p):
                for dp, dns, fns in os.walk(p):           # undo read-only folders from earlier runs
                    os.chmod(dp, 0o755)
                shutil.rmtree(p)
            else:
                os.remove(p)
        return p


def tree(root):
    """{rel: ("d",) | ("f", data, mode) | ("l", target)} (links not followed)"""
    out = {}
    for dp, dns, fns in os.walk(root):
        for n in dns + fns:
            fp = os.path.join(dp, n)
            rel = os.path.relpath(fp, root)
            st = os.lstat(fp)
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("l", os.readlink(fp))
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ("d",)
            else:
                out[rel] = ("f", open(fp, "rb").read(), stat.S_IMODE(st.st_mode))
    return out


def expect_tree(prefix=""):
    exp = {}
    for d in DIRS:
        exp[prefix + d] = ("d",)
    for k, v in FILES.items():
        exp[prefix + k] = ("f", v)
    return exp


def same_tree(got, exp, modes=None):
    """compare names/types/data (and modes for the keys given); returns list of problems"""
    probs = []
    for k, v in exp.items():
        g = got.get(k)
        if g is None:
            probs.append("missing " + k)
        elif g[0] != v[0]:
            probs.append("type " + k)
        elif v[0] == "f" and g[1] != v[1]:
            probs.append("data " + k)
        elif v[0] == "l" and g[1] != v[1]:
            probs.append("link %s -> %s (want %s)" % (k, g[1], v[1]))
    for k in got:
        if k not in exp:
            probs.append("unexpected " + k)
    for k, m in (modes or {}).items():
        if k in got and got[k][0] == "f" and got[k][2] != m:
            probs.append("mode %s %o (want %o)" % (k, got[k][2], m))
    return probs


def make_tar(path, mode="w"):
    with tarfile.open(path, mode, format=tarfile.PAX_FORMAT) as tf:
        for d in DIRS:
            ti = tarfile.TarInfo(d); ti.type = tarfile.DIRTYPE; ti.mode = 0o755; ti.mtime = DMT[d]
            tf.addfile(ti)
        for k in sorted(FILES):
            ti = tarfile.TarInfo(k); ti.size = len(FILES[k]); ti.mode = MODES.get(k, 0o644); ti.mtime = FMT[k]
            tf.addfile(ti, io.BytesIO(FILES[k]))


def make_zip(path, files=None, dirs=None, modes=None):
    files = FILES if files is None else files
    dirs = DIRS if dirs is None else dirs
    modes = MODES if modes is None else modes
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for d in dirs:
            zi = zipfile.ZipInfo(d + "/", date_time=(2017, 7, 14, 2, 40, 0))
            zi.external_attr = (0o40755 << 16) | 0x10
            zi.create_system = 3
            z.writestr(zi, b"")
        for k in sorted(files):
            zi = zipfile.ZipInfo(k, date_time=(2020, 5, 17, 13, 45, 10))
            zi.external_attr = (0o100000 | modes.get(k, 0o644)) << 16
            zi.create_system = 3
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, files[k])


def tar_member(tf, name, data=None, kind="f", target=None, mode=None, mtime=MT):
    ti = tarfile.TarInfo(name)
    ti.mtime = mtime
    if kind == "d":
        ti.type = tarfile.DIRTYPE; ti.mode = mode or 0o755; tf.addfile(ti)
    elif kind == "l":
        ti.type = tarfile.SYMTYPE; ti.linkname = target; ti.mode = 0o777; tf.addfile(ti)
    elif kind == "h":
        ti.type = tarfile.LNKTYPE; ti.linkname = target; tf.addfile(ti)
    else:
        ti.size = len(data); ti.mode = mode or 0o644; tf.addfile(ti, io.BytesIO(data))


# ---------------------------------------------------------------------------

def test_extract_basic(c, arcs):
    t = c.t
    for name, arc in arcs.items():
        out = c.fresh("x_" + name)
        rc, so, se = c.run(["x", arc, "-o", out, "-bd"])
        probs = same_tree(tree(out), expect_tree(), MODES) if rc == 0 else [se[-300:]]
        c.check(rc == 0 and not probs and "Everything is Ok" in so, "extract " + name,
                "rc=%d %s" % (rc, "; ".join(probs[:6])))
    # several threads and one thread give the same tree
    for th in ("1", "4"):
        out = c.fresh("x_threads" + th)
        rc, so, se = c.run(["x", arcs["zip"], "-o", out, "-t", th])
        c.check(rc == 0 and not same_tree(tree(out), expect_tree()), "extract zip -t " + th, se[-300:])
    # tar: modification times of files and folders (folders after their contents)
    out = os.path.join(t.work, "x_tar")
    bad = [k for k, m in FMT.items() if int(os.stat(os.path.join(out, k)).st_mtime) != m]
    bad += [d for d, m in DMT.items() if int(os.stat(os.path.join(out, d)).st_mtime) != m]
    c.check(not bad, "tar mtimes restored (files + folders)", str(bad[:5]))
    # zip: DOS times are local time
    want = time.mktime((2020, 5, 17, 13, 45, 10, 0, 0, -1))
    got = os.stat(os.path.join(t.work, "x_zip", "top/readme.txt")).st_mtime
    c.check(abs(got - want) <= 2, "zip DOS mtime restored as local time", "%s vs %s" % (got, want))
    # exec bit
    m = stat.S_IMODE(os.stat(os.path.join(t.work, "x_tgz", "top/run.sh")).st_mode)
    c.check(m & 0o111 == 0o111, "exec bit kept", oct(m))
    # --no-times / --no-perms
    out = c.fresh("x_notimes")
    rc, so, se = c.run(["x", arcs["tar"], "-o", out, "--no-times", "--no-perms"])
    m = stat.S_IMODE(os.stat(os.path.join(out, "top/run.sh")).st_mode)
    mt = os.stat(os.path.join(out, "top/readme.txt")).st_mtime
    c.check(rc == 0 and not (m & 0o100) and mt > time.time() - 3600, "--no-times --no-perms", "%o %s" % (m, mt))


def test_overwrite(c, arcs):
    arc = arcs["tar"]
    d = c.fresh("ow")
    rc, so, se = c.run(["x", arc, "-o", d])
    f = os.path.join(d, "top/readme.txt")
    orig = FILES["top/readme.txt"]
    open(f, "wb").write(b"changed")
    rc, so, se = c.run(["x", arc, "-o", d, "-n"])
    c.check(rc == 0 and open(f, "rb").read() == b"changed", "-n keeps existing", "rc=%d" % rc)
    rc, so, se = c.run(["x", arc, "-o", d])
    c.check(rc == 1 and open(f, "rb").read() == b"changed" and "already exists" in se,
            "no terminal, no -y: skip with warning (exit 1)", "rc=%d %s" % (rc, se[-200:]))
    rc, so, se = c.run(["x", arc, "-o", d, "-r"])
    r2 = os.path.join(d, "top/readme (2).txt")
    c.check(rc == 0 and open(f, "rb").read() == b"changed" and os.path.exists(r2) and open(r2, "rb").read() == orig,
            "-r renames the new file", "rc=%d %s" % (rc, os.listdir(os.path.join(d, "top"))))
    rc, so, se = c.run(["x", arc, "-o", d, "-y"])
    c.check(rc == 0 and open(f, "rb").read() == orig, "-y overwrites", "rc=%d" % rc)
    # read-only existing file is replaced too (new file, not truncated in place)
    os.chmod(f, 0o444)
    open(os.path.join(d, "top/empty.txt"), "wb").write(b"x")
    rc, so, se = c.run(["x", arc, "-o", d, "-y"])
    c.check(rc == 0 and os.path.getsize(os.path.join(d, "top/empty.txt")) == 0, "-y replaces read-only files",
            se[-200:])
    # --newer: archive entry older than the file on disk -> kept; newer -> replaced
    open(f, "wb").write(b"newer on disk")
    os.utime(f, (time.time(), time.time()))
    rc, so, se = c.run(["x", arc, "-o", d, "--newer"])
    keep = open(f, "rb").read() == b"newer on disk"
    os.utime(f, (MT - 10 ** 6, MT - 10 ** 6))
    rc2, so, se = c.run(["x", arc, "-o", d, "--newer"])
    c.check(rc == 0 and rc2 == 0 and keep and open(f, "rb").read() == orig, "--newer", "%d %d %s" % (rc, rc2, keep))
    # existing symlink at a file's place is replaced, never written through
    victim = c.fresh("ow_victim.txt")
    open(victim, "wb").write(b"victim")
    os.remove(f)
    os.symlink(victim, f)
    rc, so, se = c.run(["x", arc, "-o", d, "-y"])
    c.check(rc == 0 and open(victim, "rb").read() == b"victim" and not os.path.islink(f)
            and open(f, "rb").read() == orig, "existing link replaced, not followed", se[-200:])


def test_smart_strip(c, arcs):
    t = c.t
    d = c.fresh("smart1")
    rc, so, se = c.run(["x", arcs["zip"], "-o", d, "--smart"])
    c.check(rc == 0 and sorted(os.listdir(d)) == ["top"], "smart: single top folder -> no extra folder",
            str(os.listdir(d) if os.path.isdir(d) else rc))
    multi = c.fresh("multi.tar.gz")
    with tarfile.open(multi, "w:gz") as tf:
        tar_member(tf, "a.txt", b"A")
        tar_member(tf, "b/c.txt", b"C")
    d = c.fresh("smart2")
    rc, so, se = c.run(["x", multi, "-o", d, "--smart"])
    c.check(rc == 0 and os.listdir(d) == ["multi"] and open(os.path.join(d, "multi/b/c.txt"), "rb").read() == b"C",
            "smart: several top items -> <archive name>/", str(os.listdir(d) if os.path.isdir(d) else se))
    one = c.fresh("one.zip")
    with zipfile.ZipFile(one, "w") as z:
        z.writestr("only.txt", b"just me")
    d = c.fresh("smart3")
    rc, so, se = c.run(["x", one, "-o", d, "--smart"])
    c.check(rc == 0 and os.listdir(d) == ["only.txt"], "smart: single file -> no folder", str(rc))
    # strip a folder prefix
    d = c.fresh("strip")
    rc, so, se = c.run(["x", arcs["tar"], "-o", d, "--strip", "top/문서"])
    got = tree(d)
    exp = {"보고서.txt": ("f", FILES["top/문서/보고서.txt"]), "사진": ("d",),
           "사진/고기.jpg": ("f", FILES["top/문서/사진/고기.jpg"])}
    c.check(rc == 0 and not same_tree(got, exp), "--strip folder", str(same_tree(got, exp)[:4]))
    # e: no paths
    d = c.fresh("flat")
    rc, so, se = c.run(["e", arcs["zip"], "-o", d])
    exp = {os.path.basename(k): ("f", v) for k, v in FILES.items()}
    c.check(rc == 0 and not same_tree(tree(d), exp), "e: no paths", str(same_tree(tree(d), exp)[:4]))
    # name filters: folder and wildcard
    d = c.fresh("filter")
    rc, so, se = c.run(["x", arcs["zip"], "-o", d, "top/deep", "*.jpg"])
    got = {k for k, v in tree(d).items() if v[0] == "f"}
    c.check(rc == 0 and got == {"top/deep/a/b/c/d/e.bin", "top/문서/사진/고기.jpg"}, "name filters", str(got))
    rc, so, se = c.run(["x", arcs["zip"], "-o", d, "no/such/thing"])
    c.check(rc == 1 and "No files to process" in se, "filter without match: warning", "rc=%d" % rc)


def test_links(c):
    t = c.t
    arc = c.fresh("links.tar")
    with tarfile.open(arc, "w", format=tarfile.PAX_FORMAT) as tf:
        tar_member(tf, "d", kind="d")
        tar_member(tf, "d/file.txt", b"inside")
        tar_member(tf, "d/inner", kind="l", target="file.txt")
        tar_member(tf, "d/up", kind="l", target="../d/file.txt")
        tar_member(tf, "esc", kind="l", target="../../outside.txt")
        tar_member(tf, "abs", kind="l", target="/etc/passwd")
        tar_member(tf, "esc2", kind="l", target="later/..")         # fine now, escapes once "later" exists
        tar_member(tf, "chain/up", kind="l", target="..")           # the destination itself: fine
        tar_member(tf, "chain_esc", kind="l", target="chain/up/..")
        tar_member(tf, "later", kind="l", target="chain/up")
        tar_member(tf, "w2", kind="l", target="../outside_dir")      # then a file "through" it
        tar_member(tf, "w2/evil.txt", b"evil")
        tar_member(tf, "hard", kind="h", target="d/file.txt")
        tar_member(tf, "a/b/l", kind="l", target="../../d/file.txt")   # inside
        tar_member(tf, "hl_esc", kind="h", target="a/b/l")              # same link text one level up: outside
        tar_member(tf, "a/b/hl_ok", kind="h", target="a/b/l")
        tar_member(tf, "d/x/../../../hard_esc", kind="h", target="../../etc/passwd")
    base = c.fresh("links_box")
    os.makedirs(base)
    d = os.path.join(base, "out")
    rc, so, se = c.run(["x", arc, "-o", d])
    g = tree(d)
    ok_in = g.get("d/inner") == ("l", "file.txt") and g.get("d/up") == ("l", "../d/file.txt") \
        and g.get("chain/up") == ("l", "..") and g.get("later") == ("l", "chain/up")
    refused = [k for k in ("esc", "abs", "chain_esc", "esc2") if k in g]
    c.check(rc == 1 and ok_in and not refused, "links: inner created, escaping refused (exit 1)",
            "rc=%d in=%s refused=%s %s" % (rc, ok_in, refused, se[-400:]))
    c.check(not os.path.exists(os.path.join(base, "outside_dir")) and g.get("w2") == ("d",)
            and g.get("w2/evil.txt", ("",))[0] == "f", "file never written through a link of the archive",
            str(g.get("w2")))
    c.check(g.get("hard", ("",))[0] == "f" and g["hard"][1] == b"inside"
            and os.stat(os.path.join(d, "hard")).st_ino == os.stat(os.path.join(d, "d/file.txt")).st_ino,
            "hard link created", str(g.get("hard")))
    c.check("hard_esc" not in g or g["hard_esc"][0] != "f" or g["hard_esc"][1] != open("/etc/passwd", "rb").read(),
            "hard link to outside not created", str(g.get("hard_esc")))
    c.check("hl_esc" not in g and g.get("a/b/hl_ok") == ("l", "../../d/file.txt"),
            "hard link to a symlink checked like a symlink", str([g.get("hl_esc"), g.get("a/b/hl_ok")]))
    c.check("outside" in se or "link" in se, "link warnings reported", se[-300:])
    # unsafe links allowed by option
    d = c.fresh("links_unsafe")
    rc, so, se = c.run(["x", arc, "-o", d, "--unsafe-links"])
    g = tree(d)
    c.check(g.get("abs") == ("l", "/etc/passwd") and g.get("esc") == ("l", "../../outside.txt"),
            "--unsafe-links creates them", str([g.get("abs"), g.get("esc")]))
    # --no-links
    d = c.fresh("links_none")
    rc, so, se = c.run(["x", arc, "-o", d, "--no-links"])
    c.check(not any(v[0] == "l" for v in tree(d).values()), "--no-links", "")
    # zip symlink (target stored as data)
    zp = c.fresh("ziplink.zip")
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("t.txt", b"T")
        zi = zipfile.ZipInfo("lnk"); zi.create_system = 3; zi.external_attr = (0o120777 << 16)
        z.writestr(zi, b"t.txt")
        zi = zipfile.ZipInfo("bad"); zi.create_system = 3; zi.external_attr = (0o120777 << 16)
        z.writestr(zi, b"../../../etc/passwd")
    d = c.fresh("ziplink")
    rc, so, se = c.run(["x", zp, "-o", d])
    g = tree(d)
    c.check(g.get("lnk") == ("l", "t.txt") and "bad" not in g and rc == 1, "zip symlinks (data target)",
            "rc=%d %s" % (rc, g))
    # test mode accepts links
    rc, so, se = c.run(["t", arc])
    c.check(rc == 0, "t with links", se[-200:])


def test_modes(c):
    arc = c.fresh("modes.tar")
    with tarfile.open(arc, "w") as tf:
        tar_member(tf, "suid", b"#!/bin/sh\n", mode=0o4755)
        tar_member(tf, "ro.txt", b"ro", mode=0o444)
        tar_member(tf, "rodir", kind="d", mode=0o555)
        tar_member(tf, "rodir/f.txt", b"in a read-only folder")
    d = c.fresh("modes")
    rc, so, se = c.run(["x", arc, "-o", d])
    m = stat.S_IMODE(os.stat(os.path.join(d, "suid")).st_mode)
    dm = stat.S_IMODE(os.stat(os.path.join(d, "rodir")).st_mode)
    c.check(rc == 0 and m == 0o755 & ~current_umask() and dm == 0o555
            and open(os.path.join(d, "rodir/f.txt"), "rb").read() == b"in a read-only folder",
            "setuid dropped, read-only folder filled before its mode is set", "rc=%d %o %o %s" % (rc, m, dm, se[-200:]))
    d2 = c.fresh("modes_suid")
    rc, so, se = c.run(["x", arc, "-o", d2, "--keep-setuid"])
    m = stat.S_IMODE(os.stat(os.path.join(d2, "suid")).st_mode)
    c.check(rc == 0 and m & 0o4000, "--keep-setuid", oct(m))
    os.chmod(os.path.join(d, "rodir"), 0o755)
    os.chmod(os.path.join(d2, "rodir"), 0o755)


def current_umask():
    m = os.umask(0o22)
    os.umask(m)
    return m


def pty_run(c, args, answers, env=None, timeout=60):
    """run the CLI on a pseudo terminal; answers: [(text to wait for, reply)]"""
    m, s = os.openpty()
    p = subprocess.Popen([c.cli] + args, stdin=s, stdout=s, stderr=s, env=env or c.env(), cwd=c.t.work,
                         close_fds=True, start_new_session=True)
    os.close(s)
    out = b""
    pos = 0
    i = 0
    end = time.time() + timeout
    while True:
        if time.time() > end:
            p.kill(); p.wait(); os.close(m)
            return -999, out.decode("utf-8", "replace")
        r, _, _ = select.select([m], [], [], 0.1)
        if r:
            try:
                data = os.read(m, 65536)
            except OSError:
                data = b""
            if not data:
                break
            out += data
        if i < len(answers) and answers[i][0].encode() in out[pos:]:
            pos = len(out)
            os.write(m, answers[i][1].encode())
            i += 1
        elif not r and p.poll() is not None:
            break
    p.wait()
    os.close(m)
    return p.returncode, out.decode("utf-8", "replace")


def test_passwords(c):
    t = c.t
    files = {"secret/a.txt": blob(20000, 1, 9), "secret/b.bin": blob(5000, 0, 9)}
    zp = c.fresh("enc.zip")
    made = False
    try:
        import pyzipper
        with pyzipper.AESZipFile(zp, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
            z.setpassword(b"gogi1234")
            for k, v in files.items():
                z.writestr(k, v)
        made = True
    except ImportError:
        if shutil.which("7z"):
            src = t.write_tree(c.fresh("enc_src"), files)
            t.sh(["7z", "a", "-tzip", "-pgogi1234", "-mem=AES256", zp, "."], cwd=src)
            made = True
    if not made:
        c.check(True, "passwords skipped (no pyzipper/7z)")
        return
    exp = {"secret": ("d",)}
    exp.update({k: ("f", v) for k, v in files.items()})
    d = c.fresh("pw1")
    rc, so, se = c.run(["x", zp, "-o", d, "-p", "gogi1234"])
    c.check(rc == 0 and not same_tree(tree(d), exp), "password via -p", se[-200:])
    d = c.fresh("pw1b")
    rc, so, se = c.run(["x", zp, "-o" + d, "-pgogi1234"])
    c.check(rc == 0 and not same_tree(tree(d), exp), "password via -pPASS -oDIR", se[-200:])
    d = c.fresh("pw2")
    rc, so, se = c.run(["x", zp, "-o", d, "-p", "wrong"])
    c.check(rc == 2 and "Wrong password" in se and not any(v[0] == "f" for v in tree(d).values()),
            "wrong -p: exit 2, nothing written", "rc=%d %s" % (rc, se[-200:]))
    d = c.fresh("pw3")
    rc, so, se = c.run(["x", zp, "-o", d])
    c.check(rc == 2 and "Password required" in se, "no terminal, no -p: exit 2", "rc=%d %s" % (rc, se[-200:]))
    rc, so, se = c.run(["t", zp, "-p", "gogi1234"])
    c.check(rc == 0, "t with password", se[-200:])
    # terminal prompt, without echo; first answer wrong
    d = c.fresh("pw4")
    rc, out = pty_run(c, ["x", zp, "-o", d], [("Enter password", "nope\n"), ("Wrong password", "gogi1234\n")])
    c.check(rc == 0 and not same_tree(tree(d), exp) and "gogi1234" not in out and "nope" not in out,
            "password typed on a terminal (no echo, retry)", "rc=%d %r" % (rc, out[-400:]))
    # overwrite question on a terminal: rename
    rc, out = pty_run(c, ["x", zp, "-o", d, "-p", "gogi1234", "-t", "1"], [("(Q)uit?", "r\n"), ("(Q)uit?", "n\n")])
    c.check(rc == 0 and os.path.exists(os.path.join(d, "secret/a (2).txt")) and not os.path.exists(
        os.path.join(d, "secret/b (2).bin")), "overwrite question on a terminal", "rc=%d %r" % (rc, out[-300:]))
    rc, out = pty_run(c, ["x", zp, "-o", d, "-p", "gogi1234"], [("(Q)uit?", "q\n")])
    c.check(rc == 255, "quit at the overwrite question: exit 255", "rc=%d" % rc)
    # Korean prompt
    d = c.fresh("pw5")
    rc, out = pty_run(c, ["x", zp, "-o", d], [("암호를 입력하세요", "gogi1234\n")], env=c.env("ko_KR.UTF-8"))
    c.check(rc == 0 and "모두 정상입니다" in out, "Korean password prompt", "rc=%d %r" % (rc, out[-300:]))


def test_test_cmd(c, arcs):
    rc, so, se = c.run(["t", arcs["tgz"]])
    c.check(rc == 0 and "Everything is Ok" in so and "Files: 7" in so, "t ok", "rc=%d %s" % (rc, so[-300:]))
    bad = c.fresh("bad.zip")
    data = bytearray(open(arcs["zip"], "rb").read())
    off = data.find(b"top/big.bin") + 200
    for i in range(64):
        data[off + i] ^= 0x55
    open(bad, "wb").write(data)
    rc, so, se = c.run(["t", bad])
    c.check(rc == 2 and "ERROR" in se and "Everything is Ok" not in so, "t damaged: exit 2", "rc=%d %s" % (rc, se[-200:]))
    d = c.fresh("bad_out")
    rc, so, se = c.run(["x", bad, "-o", d])
    c.check(rc == 2 and not os.path.exists(os.path.join(d, "top/big.bin")), "damaged file removed", "rc=%d" % rc)
    d = c.fresh("bad_keep")
    rc, so, se = c.run(["x", bad, "-o", d, "--keep-broken"])
    c.check(rc == 2 and os.path.exists(os.path.join(d, "top/big.bin")), "--keep-broken keeps it", "rc=%d" % rc)


def test_list(c, arcs):
    rc, so, se = c.run(["l", arcs["tar"]])
    c.check(rc == 0 and "top/문서/사진/고기.jpg" in so and "Type = TAR" in so and "7 files, 9 folders" in so,
            "l", so[-300:])
    rc, so, se = c.run(["l", "-slt", c.t.path("links.tar")])
    c.check(rc == 0 and "Symbolic Link = file.txt" in so and "Path = d/inner" in so and "Hard Link = d/file.txt" in so,
            "l -slt", so[-500:])


def test_create(c):
    t = c.t
    src = c.fresh("csrc")
    long_dir = "깊은폴더" * 10                           # 120 bytes
    long_name = "아주긴파일이름" * 11 + ".txt"           # 235 bytes
    files = {
        "proj/readme.md": b"# hello\n",
        "proj/문서/보고서.txt": blob(50000, 1, 5),
        "proj/%s/%s" % (long_dir, long_name): blob(3000, 1, 6),
        "proj/bin/run.sh": b"#!/bin/sh\necho run\n",
        "proj/big.dat": blob(2 << 20, 1, 7),
        "proj/empty.txt": b"",
        "proj/ascii/" + "d" * 90 + "/" + "f" * 95 + ".txt": b"ustar prefix split",   # 197 bytes, no pax
        "proj/" + "x" * 150 + ".txt": b"no slash to split at",                     # pax path
        "proj/" + "e" * 120 + "/inner.txt": b"long folder",
    }
    t.write_tree(src, files)
    os.makedirs(os.path.join(src, "proj/빈폴더/안쪽"))
    os.chmod(os.path.join(src, "proj/bin/run.sh"), 0o755)
    os.symlink("readme.md", os.path.join(src, "proj/link.md"))
    long_target = "../" + long_dir + "/" + long_name
    os.symlink(long_target, os.path.join(src, "proj/bin/longlink"))
    os.symlink("/does/not/exist", os.path.join(src, "proj/dangling"))
    extra = os.path.join(src, "extra.txt")
    open(extra, "wb").write(b"extra file")
    for k in files:
        os.utime(os.path.join(src, k), (MT + 77, MT + 77))
    os.utime(os.path.join(src, "proj/빈폴더/안쪽"), (MT + 99, MT + 99))
    out = c.fresh("created.tar")
    rc, so, se = c.run(["a", out, os.path.join(src, "proj"), extra])
    c.check(rc == 0 and os.path.exists(out), "a: create tar", "rc=%d %s %s" % (rc, so[-200:], se[-300:]))
    if rc:
        return
    # GNU tar
    if shutil.which("tar"):
        r = subprocess.run(["tar", "-tvf", out], capture_output=True)
        lst = r.stdout.decode("utf-8", "replace")
        c.check(r.returncode == 0 and long_name in lst and "proj/link.md -> readme.md" in lst and "proj/빈폴더/안쪽/" in lst,
                "tar -tvf reads it", lst[-500:] + r.stderr.decode(errors="replace")[-200:])
    # Python tarfile: names, types, targets, modes, times, data
    probs = []
    with tarfile.open(out) as tf:
        mem = {m.name.rstrip("/"): m for m in tf.getmembers()}
        for k, v in files.items():
            m = mem.get(k)
            if not m or not m.isfile() or tf.extractfile(m).read() != v:
                probs.append("file " + k)
            elif m.mtime != MT + 77:
                probs.append("mtime %s %s" % (k, m.mtime))
        if "extra.txt" not in mem:
            probs.append("extra.txt (second input, common parent)")
        lk = mem.get("proj/link.md")
        if not lk or not lk.issym() or lk.linkname != "readme.md":
            probs.append("symlink")
        ll = mem.get("proj/bin/longlink")
        if not ll or not ll.issym() or ll.linkname != long_target:
            probs.append("long link target")
        if not mem.get("proj/dangling") or not mem["proj/dangling"].issym():
            probs.append("dangling link stored")
        dd = mem.get("proj/빈폴더/안쪽")
        if not dd or not dd.isdir() or dd.mtime != MT + 99:
            probs.append("empty folder")
        rs = mem.get("proj/bin/run.sh")
        if not rs or rs.mode & 0o777 != 0o755:
            probs.append("exec mode")
        names = list(mem)
        if any(n.startswith("proj/") is False and n not in ("proj", "extra.txt") for n in names):
            probs.append("unexpected names " + str(names[:5]))
    c.check(not probs, "python tarfile agrees", "; ".join(probs[:6]))
    if shutil.which("7z"):
        r = subprocess.run(["7z", "t", out], capture_output=True)
        c.check(r.returncode == 0, "7z t accepts it", r.stdout.decode(errors="replace")[-300:])
    # our own extraction gives the tree back (links, empty folders, modes)
    d = c.fresh("created_x")
    rc, so, se = c.run(["x", out, "-o", d])
    exp = tree(src)
    got = tree(d)
    probs = same_tree(got, exp, {"proj/bin/run.sh": 0o755 & ~current_umask()})
    probs = [p for p in probs if "dangling" not in p]
    c.check(rc in (0, 1) and not probs, "own extraction of the created tar", "rc=%d %s" % (rc, probs[:5]))
    # existing archive: refused without -y, replaced with -y
    rc, so, se = c.run(["a", out, extra])
    c.check(rc == 2 and "already exists" in se, "a on existing archive without -y: exit 2", "rc=%d %s" % (rc, se[-200:]))
    rc, so, se = c.run(["a", out, extra, "-y"])
    with tarfile.open(out) as tf:
        names = tf.getnames()
    c.check(rc == 0 and names == ["extra.txt"], "a -y replaces the archive", str(names))
    # the archive being written is never part of itself
    inside = os.path.join(src, "proj", "self.tar")
    rc, so, se = c.run(["a", inside, os.path.join(src, "proj")])
    with tarfile.open(inside) as tf:
        names = tf.getnames()
    c.check(rc == 0 and not any("self.tar" in n for n in names) and not any(
        f.startswith("self.tar.tmp") for f in os.listdir(os.path.join(src, "proj"))),
        "archive not included in itself, no temp files left", str([n for n in names if "self" in n]))
    os.remove(inside)
    # relative inputs, format from -f
    out2 = c.fresh("rel.bin")
    rc, so, se = c.run(["a", out2, "-f", "tar", "proj/readme.md"], cwd=src)
    with tarfile.open(out2) as tf:
        names = tf.getnames()
    c.check(rc == 0 and names == ["readme.md"], "relative input, -f tar", "rc=%d %s" % (rc, names))
    # follow links
    out3 = c.fresh("follow.tar")
    rc, so, se = c.run(["a", out3, os.path.join(src, "proj/link.md"), "--follow-links"])
    with tarfile.open(out3) as tf:
        m = tf.getmember("link.md")
        data = tf.extractfile(m).read() if m.isfile() else None
    c.check(rc == 0 and data == b"# hello\n", "--follow-links stores the target's data", str(data))
    # errors: unknown format, encryption on tar, missing input
    rc, so, se = c.run(["a", c.fresh("x.unknownext"), extra])
    c.check(rc == 7, "a: unknown format -> 7", "rc=%d" % rc)
    rc, so, se = c.run(["a", c.fresh("enc.tar"), extra, "-p", "pw"])
    c.check(rc == 7 and "encryption" in se, "a: tar with password -> 7", "rc=%d %s" % (rc, se[-200:]))
    out4 = c.fresh("missing.tar")
    rc, so, se = c.run(["a", out4, extra, os.path.join(src, "no_such_file")])
    with tarfile.open(out4) as tf:
        names = tf.getnames()
    c.check(rc == 1 and names == ["extra.txt"] and "not found" in se, "a: missing input -> warning, exit 1",
            "rc=%d %s" % (rc, se[-200:]))
    rc, so, se = c.run(["a", c.fresh("nothing.tar"), os.path.join(src, "no_such_file")])
    c.check(rc == 2 and not os.path.exists(c.t.path("nothing.tar")), "a: nothing to compress -> exit 2", "rc=%d" % rc)


def test_messages_exit(c, arcs):
    rc, so, se = c.run(["t", arcs["tar"]], env=c.env("ko_KR.UTF-8"))
    c.check(rc == 0 and "모두 정상입니다" in so and "파일: 7" in so, "Korean messages (LANG=ko_KR.UTF-8)", so[-200:])
    rc, so, se = c.run(["t", arcs["tar"]], env=c.env("ko_KR.UTF-8", LC_ALL="en_US.UTF-8"))
    c.check(rc == 0 and "Everything is Ok" in so, "LC_ALL overrides LANG", so[-200:])
    rc, so, se = c.run(["t", arcs["tar"]], env=c.env("en_US.UTF-8", LC_MESSAGES="ko_KR.UTF-8"))
    c.check("모두 정상입니다" in so, "LC_MESSAGES=ko", so[-200:])
    rc, so, se = c.run(["x", c.t.path("no_such.zip")], env=c.env("ko_KR.UTF-8"))
    c.check(rc == 2 and "파일을 찾을 수 없습니다" in se, "missing archive: exit 2 (Korean)", "rc=%d %s" % (rc, se))
    rc, so, se = c.run(["q"])
    c.check(rc == 7, "unknown command -> 7", "rc=%d" % rc)
    rc, so, se = c.run(["x", arcs["tar"], "--bogus"])
    c.check(rc == 7 and "Unknown option" in se, "unknown option -> 7", "rc=%d" % rc)
    rc, so, se = c.run([])
    c.check(rc == 7 and "Usage" in se, "no arguments -> 7 + usage", "rc=%d" % rc)
    rc, so, se = c.run(["x"])
    c.check(rc == 7, "x without archive -> 7", "rc=%d" % rc)
    rc, so, se = c.run(["x", arcs["tar"], "-o"])
    c.check(rc == 7, "missing option value -> 7", "rc=%d" % rc)
    rc, so, se = c.run(["--help"])
    c.check(rc == 0 and "Usage" in so, "--help", "")
    rc, so, se = c.run(["--help"], env=c.env("ko_KR.UTF-8"))
    c.check(rc == 0 and "사용법" in so, "--help (Korean)", "")
    notarc = c.fresh("plain.txt")
    open(notarc, "wb").write(b"just text, not an archive\n" * 10)
    rc, so, se = c.run(["l", notarc])
    c.check(rc == 2 and "Cannot open archive" in se, "not an archive -> 2", "rc=%d %s" % (rc, se))
    rc, so, se = c.run(["i"])
    c.check(rc == 0 and "TAR" in so and "Formats (create)" in so and "CRC-32" in so, "i", so[-300:])


def test_names(c):
    """shortening of names longer than the file system allows; zip slip"""
    t = c.t
    arc = c.fresh("longname.tar")
    comp = "아" * 100 + ".txt"                  # 304 bytes in UTF-8 > 255
    with tarfile.open(arc, "w", format=tarfile.PAX_FORMAT) as tf:
        tar_member(tf, "d/" + comp, b"long one")
        tar_member(tf, "d/" + "아" * 99 + "b.txt", b"long two")
    d = c.fresh("longname")
    rc, so, se = c.run(["x", arc, "-o", d])
    names = os.listdir(os.path.join(d, "d")) if os.path.isdir(os.path.join(d, "d")) else []
    ok = len(names) == 2 and all(len(n.encode()) <= 255 and "~" in n and n.endswith(".txt") for n in names)
    data = sorted(open(os.path.join(d, "d", n), "rb").read() for n in names)
    c.check(rc == 1 and ok and data == [b"long one", b"long two"] and "shortened" in se,
            "over-long names shortened with a hash (warning)", "rc=%d %s %s" % (rc, names, se[-200:]))
    slip = c.fresh("slip.zip")
    with zipfile.ZipFile(slip, "w") as z:
        for k in ["../../evil1.txt", "/abs/evil2.txt", "a/../../evil3.txt", "ok/../fine.txt"]:
            z.writestr(zipfile.ZipInfo(k), k.encode())
    box = c.fresh("slip_box")
    os.makedirs(box)
    d = os.path.join(box, "a", "b")
    rc, so, se = c.run(["x", slip, "-o", d])
    outside = [f for f in os.listdir(box) if f != "a"] + [f for f in os.listdir(os.path.join(box, "a")) if f != "b"]
    c.check(rc == 0 and not outside and os.path.exists(os.path.join(d, "evil1.txt")), "zip slip stays inside",
            "rc=%d outside=%s" % (rc, outside))


def test_hostile(c, arcs):
    rnd = random.Random(1234)
    srcs = [open(arcs["zip"], "rb").read()[:400000], open(arcs["tgz"], "rb").read()[:200000],
            open(c.t.path("links.tar"), "rb").read()]
    n = 0
    bad = []
    for si, data in enumerate(srcs):
        for k in range(10):
            b = bytearray(data)
            if k < 3:
                b = b[:rnd.randrange(1, len(b))]
            else:
                for _ in range(rnd.randrange(1, 20)):
                    p = rnd.randrange(len(b))
                    b[p] ^= 1 << rnd.randrange(8)
            p = c.fresh("fuzz_%d_%d.bin" % (si, k))
            open(p, "wb").write(b)
            d = c.fresh("fuzz_out")
            rc, so, se = c.run(["x", p, "-o", d, "-y"], timeout=60)
            n += 1
            if rc not in (0, 1, 2):
                bad.append("%d/%d rc=%d %s" % (si, k, rc, se[-200:]))
            rc, so, se = c.run(["l", "-slt", p], timeout=60)
            if rc not in (0, 1, 2):
                bad.append("l %d/%d rc=%d" % (si, k, rc))
    c.check(not bad, "hostile archives: %d damaged inputs, no crash or hang" % n, "; ".join(bad[:4]))


def test_tar_big(c):
    """pax headers for 8 GiB+ sizes, times before 1970 / after 2242, long link targets (C driver)"""
    t = c.t
    try:
        drv = t.build_driver("tests/drivers/app_tar_big.c")
    except Exception as e:
        return c.check(False, "build app_tar_big driver", str(e)[-500:])
    out = c.fresh("big.tar")
    r = subprocess.run(EXEC + [drv, out], capture_output=True, timeout=1200)
    err = r.stderr.decode(errors="replace")
    if r.returncode or "Sanitizer" in err:
        os.path.exists(out) and os.remove(out)
        return c.check(False, "tar writer: huge member", err[-500:] + r.stdout.decode(errors="replace")[-300:])
    probs = []
    with tarfile.open(out) as tf:
        m = {x.name: x for x in tf.getmembers()}
        if m.get("huge.bin") is None or m["huge.bin"].size != (8 << 30) + 513:
            probs.append("size %s" % (m.get("huge.bin") and m["huge.bin"].size))
        if m.get("old.txt") is None or m["old.txt"].mtime != -31536000:
            probs.append("negative mtime %s" % (m.get("old.txt") and m["old.txt"].mtime))
        if m.get("future.txt") is None or m["future.txt"].mtime != 1 << 34:
            probs.append("future mtime")
        if m.get("tail.txt") is None or tf.extractfile(m["tail.txt"]).read() != b"after the big one":
            probs.append("member after the huge one")
        lk = m.get("link")
        if lk is None or lk.linkname != "t" * 300:
            probs.append("long link")
    rr = t.run_gzt(["l", out])
    if b"huge.bin" not in rr.stdout or str((8 << 30) + 513).encode() not in rr.stdout:
        probs.append("own listing")
    os.remove(out)
    c.check(not probs, "tar writer: pax size/mtime/linkpath (8 GiB+ member)", "; ".join(probs))


def test_engine_api(c):
    t = c.t
    try:
        drv = t.build_driver("tests/drivers/app_engine.c")
    except Exception as e:
        return c.check(False, "build app_engine driver", str(e)[-500:])
    for n in ("nest_view", "nest_tmp", "ans", "paused", "cin", "made.tar", "cancelled.tar"):
        c.fresh(n)
    # nested archives: zip stored inside tar (view), zip inside tar.gz (temporary copy)
    inner = c.fresh("inner.zip")
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("in/a.txt", b"nested A")
        z.writestr("in/b.txt", blob(10000, 1, 4))
    for mode, name in (("w", "outer.tar"), ("w:gz", "outer.tar.gz")):
        p = c.fresh(name)
        with tarfile.open(p, mode) as tf:
            tf.add(inner, "pack/inner.zip")
            tar_member(tf, "pack/other.txt", b"other")
    r = subprocess.run(EXEC + [drv, t.work], capture_output=True, timeout=600)
    out = r.stdout.decode("utf-8", "replace")
    err = r.stderr.decode("utf-8", "replace")
    lines = [l for l in out.splitlines() if l.startswith(("ok ", "FAIL "))]
    for l in lines:
        c.check(l.startswith("ok "), "engine: " + l.split(" ", 1)[1][:70], l)
    c.check(r.returncode == 0 and lines and "Sanitizer" not in err, "engine driver finished",
            "rc=%d %s %s" % (r.returncode, out[-300:], err[-800:]))
    for n in ("cin", "made.tar", "paused", "cancelled.tar"):      # large intermediates
        c.fresh(n)


def run(t):
    c = Ctx(t)
    if not os.path.exists(c.cli):
        t.skip("%s missing: run make build/gogitzip (make test builds it)" % c.cli)
    arcs = {"zip": c.fresh("fx.zip"), "tar": c.fresh("fx.tar"), "tgz": c.fresh("fx.tgz")}
    make_zip(arcs["zip"])
    make_tar(arcs["tar"])
    make_tar(arcs["tgz"], "w:gz")
    test_extract_basic(c, arcs)
    test_overwrite(c, arcs)
    test_smart_strip(c, arcs)
    test_links(c)
    test_modes(c)
    test_passwords(c)
    test_test_cmd(c, arcs)
    test_list(c, arcs)
    test_create(c)
    test_messages_exit(c, arcs)
    test_names(c)
    test_hostile(c, arcs)
    test_tar_big(c)
    test_engine_api(c)
