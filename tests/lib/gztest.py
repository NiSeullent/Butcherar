"""
고깃ZIP test helpers used by tests/cases/*.py.

Every case module defines   def run(t): ...   and uses the T object below to
create fixtures in its own work directory and check the native driver (gzt):

    t.check_extract(archive, {"dir/a.txt": b"...", "dir": None}, pw="x")
    t.check_vs_7z(archive)                 # 7-Zip's extraction is the reference
    t.check_hostile(path)                  # must not crash / hang
    t.check_roundtrip("zip", files)        # gzt c, then 7z t + our own extraction
    t.skip("reason")                       # nothing to test (tool missing)
"""
import os, sys, shutil, subprocess, unicodedata, hashlib

if sys.platform == 'darwin':
    # CI runners use the C locale: 7-Zip and friends would mangle non-ASCII arguments
    os.environ.setdefault('LC_ALL', 'en_US.UTF-8')
    os.environ.setdefault('LANG', 'en_US.UTF-8')

def nfc(s):
    """macOS file systems hand back decomposed (NFD) Hangul: compare names composed."""
    return unicodedata.normalize('NFC', s)

def normalize(name):
    """What 고깃ZIP shows for a raw entry name."""
    name = name.replace("\\", "/")
    parts = [p for p in name.split("/") if p not in ("", ".", "..")]
    if parts and len(parts[0]) == 2 and parts[0][1] == ":":
        parts = parts[1:]
    s = "/".join("".join("_" if ord(ch) < 0x20 else ch for ch in p) for p in parts)
    return unicodedata.normalize("NFC", s) if any(0x1100 <= ord(c) <= 0x11FF for c in s) else s

class SkipModule(Exception):
    pass

class T:
    def __init__(self, gzt, work, module, verbose=False):
        self.gzt, self.work, self.module, self.verbose = gzt, work, module, verbose
        self.results = []          # (ok, label, detail)
        os.makedirs(work, exist_ok=True)

    # ---------- utilities ----------
    def path(self, *names):
        p = os.path.join(self.work, *names)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def tool(self, name):
        return shutil.which(name)

    def need(self, *tools):
        miss = [x for x in tools if not shutil.which(x)]
        if miss:
            raise SkipModule("missing tools: " + " ".join(miss))

    def skip(self, why):
        raise SkipModule(why)

    def sh(self, args, cwd=None, check=True, env=None, input=None, timeout=600):
        r = subprocess.run(args, cwd=cwd, capture_output=True, env=env, input=input, timeout=timeout)
        if check and r.returncode:
            raise RuntimeError("command failed (%d): %s\n%s%s" % (r.returncode, " ".join(map(str, args)),
                               r.stdout.decode(errors="replace")[-2000:], r.stderr.decode(errors="replace")[-2000:]))
        return r

    def write_tree(self, root, files):
        """files: {relpath: bytes or None (directory)}"""
        shutil.rmtree(root, ignore_errors=True)
        os.makedirs(root, exist_ok=True)
        for k, v in files.items():
            fp = os.path.join(root, k)
            if v is None:
                os.makedirs(fp, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(fp), exist_ok=True)
                with open(fp, "wb") as f:
                    f.write(v)
        return root

    def read_tree(self, root):
        out = {}
        for dp, dns, fns in os.walk(root):
            for fn in fns:
                fp = os.path.join(dp, fn)
                if os.path.islink(fp):
                    continue
                rel = nfc(os.path.relpath(fp, root).replace(os.sep, "/"))
                try:
                    out[rel] = open(fp, "rb").read()
                except PermissionError:          # reference tools may restore mode 000
                    os.chmod(fp, 0o600)
                    out[rel] = open(fp, "rb").read()
        return out

    def record(self, ok, label, detail=""):
        self.results.append((bool(ok), label, detail))
        return ok

    # ---------- driver ----------
    def run_gzt(self, args, env_extra=None, timeout=300):
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        return subprocess.run([self.gzt] + args, capture_output=True, env=env, timeout=timeout)

    def extract(self, arc, pw=None, cp=None, acp=None, tier=None, outdir=None, env=None, timeout=300):
        out = outdir or os.path.join(self.work, "out_" + os.path.basename(arc))
        shutil.rmtree(out, ignore_errors=True)
        args = ["x", arc, out, pw or "", str(cp or 0)]
        if tier is not None:
            args.append(str(tier))
        e = dict(env or {})
        if acp:
            e["GZ_TEST_ACP"] = str(acp)
        r = self.run_gzt(args, e, timeout)
        rows = {}
        for line in r.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split("\t")
            if len(parts) == 5 and parts[0].isdigit():
                rows[int(parts[0])] = (int(parts[1]), int(parts[2]), int(parts[3]), parts[4])
        return r, rows, out

    def listing(self, arc, cp=None, env=None):
        r = self.run_gzt(["l", arc, str(cp or 0)], env)
        rows = []
        typ = None
        for line in r.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split("\t")
            if parts[0] == "TYPE":
                typ = parts[1]
            elif len(parts) >= 7 and parts[0].isdigit():
                rows.append(dict(idx=int(parts[0]), is_dir=int(parts[1]), usize=int(parts[2]),
                                 csize=int(parts[3]), method=parts[4], mode=int(parts[5], 8),
                                 name=parts[6]))
        return r, typ, rows

    def build_driver(self, src, name=None, extra=()):
        """Compile a C test driver (e.g. tests/drivers/foo.c) against the host core objects
        (build/host/**/*.o, built by `make build/gzt` with the same HOST_CFLAGS). Returns its path."""
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        bdir = os.path.dirname(self.gzt)
        objs = []
        for dp, dns, fns in os.walk(os.path.join(bdir, "host")):
            objs += [os.path.join(dp, f) for f in fns if f.endswith(".o")]
        out = os.path.join(self.work, name or os.path.splitext(os.path.basename(src))[0])
        flags = os.environ.get("HOST_CFLAGS", "-O2 -g").split()
        inc = ["-I" + os.path.join(root, d) for d in ("src/core", "src/codec", "src/fmt", "src/posix", "src/app")]
        cmd = [os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-pthread"] + flags + inc + \
              ["-o", out, os.path.join(root, src)] + sorted(objs) + list(extra) + ["-pthread"]
        if sys.platform == "darwin":
            cmd.append("-liconv")
        self.sh(cmd)
        return out

    # ---------- checks ----------
    def check_extract(self, arc, expected, pw=None, cp=None, acp=None, label=None, tier=None,
                      allow_extra=False, ordered=False, env=None, expect_type=None):
        """expected: {name: bytes | None (directory)} or list of (name, bytes|None) by index."""
        label = label or os.path.basename(arc)
        try:
            r, rows, out = self.extract(arc, pw, cp, acp, tier, env=env)
        except subprocess.TimeoutExpired:
            return self.record(False, label, "timeout")
        info = r.stderr.decode("utf-8", "replace").strip().splitlines()
        info = info[0] if info else ""
        if r.returncode:
            return self.record(False, label, "driver failed: %s %s" % (r.stdout.decode(errors="replace")[:300], info))
        if expect_type and ("type=%s " % expect_type) not in info:
            return self.record(False, label, "type mismatch: %s (want %s)" % (info, expect_type))
        problems = []
        if ordered or isinstance(expected, list):
            items = expected if isinstance(expected, list) else list(expected.items())
            for i, (name, data) in enumerate(items):
                if i not in rows:
                    problems.append("missing #%d %s" % (i, name)); continue
                st, isdir, size, gname = rows[i]
                if gname != normalize(name):
                    problems.append("name #%d: got %r want %r" % (i, gname, normalize(name)))
                if data is None:
                    continue
                if st != 0:
                    problems.append("error #%d %s: %d" % (i, name, st)); continue
                fp = os.path.join(out, "%d.bin" % i)
                if not os.path.exists(fp) or open(fp, "rb").read() != data:
                    problems.append("data #%d %s" % (i, name))
        else:
            by_name = {}
            for i, (st, isdir, size, gname) in rows.items():
                by_name.setdefault(gname, []).append((i, st, isdir))
            for name, data in expected.items():
                n = normalize(name)
                cands = by_name.get(n)
                if not cands:
                    if data is not None:
                        problems.append("missing %s" % n)
                    continue
                if data is None:
                    continue
                okk = False
                errs = []
                for i, st, isdir in cands:
                    if isdir:
                        continue
                    fp = os.path.join(out, "%d.bin" % i)
                    if st != 0:
                        errs.append("error %d" % st); continue
                    if os.path.exists(fp) and open(fp, "rb").read() == data:
                        okk = True; break
                    errs.append("data mismatch")
                if not okk:
                    problems.append("%s: %s" % (n, ",".join(errs) or "no file"))
            if not allow_extra:
                want = {normalize(k) for k, v in expected.items() if v is not None}
                for i, (st, isdir, size, gname) in rows.items():
                    if not isdir and gname not in want and gname:
                        problems.append("unexpected %s" % gname)
        detail = "; ".join(problems[:8]) + (" ..." if len(problems) > 8 else "")
        return self.record(not problems, label, detail or ("%d entries  %s" % (len(rows), info)))

    def sevenzip_extract(self, arc, pw=None, extra=()):
        out = os.path.join(self.work, "ref7z_" + os.path.basename(arc))
        shutil.rmtree(out, ignore_errors=True)
        args = ["7z", "x", "-y", "-o" + out, arc] + (["-p" + pw] if pw is not None else ["-p-"]) + list(extra)
        r = subprocess.run(args, capture_output=True, timeout=600)
        return r, out

    def check_vs_7z(self, arc, pw=None, label=None, allow_extra=False, **kw):
        """Compare our extraction with 7-Zip's (files only)."""
        r, out = self.sevenzip_extract(arc, pw)
        if r.returncode:
            return self.record(False, label or os.path.basename(arc),
                               "7z reference failed: " + r.stdout.decode(errors="replace")[-300:])
        exp = self.read_tree(out)
        return self.check_extract(arc, exp, pw=pw, label=label, allow_extra=allow_extra, **kw)

    def check_hostile(self, path, label=None, timeout=30, pw=None):
        label = label or "hostile " + os.path.basename(path)
        try:
            r, rows, out = self.extract(path, pw=pw, timeout=timeout)
        except subprocess.TimeoutExpired:
            return self.record(False, label, "timeout")
        err = r.stderr.decode(errors="replace")
        bad = r.returncode not in (0, 1) or "Sanitizer" in err or "runtime error" in err
        return self.record(not bad, label, "rc=%d %s" % (r.returncode, err[-300:] if bad else ""))

    def check_roundtrip(self, fmt, files, level=5, pw=None, label=None, env=None, verify_7z=True,
                        sevenzip_args=()):
        """Create an archive with gzt c from files {rel: bytes|None}; verify with 7z and gzt x."""
        label = label or "create %s L%d%s" % (fmt, level, " pw" if pw else "")
        src = self.write_tree(os.path.join(self.work, "rt_src_" + fmt), files)
        ext = {"tgz": "tar.gz", "tbz2": "tar.bz2", "txz": "tar.xz", "tzst": "tar.zst"}.get(fmt, fmt)
        arc = os.path.join(self.work, "rt_%s_L%d%s.%s" % (fmt, level, "_pw" if pw else "", ext))
        if os.path.exists(arc):
            os.remove(arc)
        rels = sorted(files.keys())
        r = self.run_gzt(["c", fmt, arc, str(level), pw or "-", src] + rels, env)
        if r.returncode:
            return self.record(False, label, "create failed: %s %s" % (r.stdout.decode(errors="replace")[-300:],
                                                                       r.stderr.decode(errors="replace")[-300:]))
        exp = {k: v for k, v in files.items() if v is not None}
        ok = True
        if verify_7z and shutil.which("7z") and fmt not in ("zst", "tzst"):
            rr, out = self.sevenzip_extract(arc, pw, sevenzip_args)
            got = self.read_tree(out)
            if fmt in ("gz", "bz2", "xz", "zst"):
                ok = rr.returncode == 0 and list(got.values()) == list(exp.values())
            else:
                ok = rr.returncode == 0 and got == exp
            if not ok:
                return self.record(False, label, "7z disagrees: rc=%d %s" % (rr.returncode, rr.stdout.decode(errors="replace")[-300:]))
        if fmt in ("gz", "bz2", "xz", "zst"):
            r2, rows, out = self.extract(arc, pw)
            data = open(os.path.join(out, "0.bin"), "rb").read() if os.path.exists(os.path.join(out, "0.bin")) else None
            ok = r2.returncode == 0 and data == list(exp.values())[0]
            return self.record(ok, label, "" if ok else "own extraction mismatch")
        return self.check_extract(arc, exp, pw=pw, label=label, allow_extra=True)
