"""Release metadata (static checks, no build needed):

* one version: src/core/version.h -> engine.h, Windows resources, macOS Info.plist template,
  Makefile, Linux metainfo (newest <release>), README / web site / release notes
  (tools/gen_docs.py keeps them in step), the CLI's --version and `i` when it is built
* the format tables of README.md, web/index.html and the release notes match the format /
  writer registry (GZ_FORMAT / GZ_WRITER lines), and the parser of tools/gen_docs.py agrees
  with the program's own list (`gogitzip i`)
* .github/workflows/*.yml parse (PyYAML when installed), call only make targets that
  exist, build every release asset, check out the tag on manual runs and attach the assets
* the web site: well-formed HTML, unique ids, local assets exist, download links and
  their data-asset patterns name the published files; the README's local links exist
* Linux packaging scripts: POSIX sh syntax, asset names as the workflow expects
"""
import os, re, sys, json, subprocess
from html.parser import HTMLParser

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import gen_docs                                   # noqa: E402


def read(*rel):
    return open(os.path.join(ROOT, *rel), encoding="utf-8").read()


def assets(ver):
    """every file a release carries (besides SHA256SUMS.txt)"""
    return ["GogitZip.exe", "GogitZip64.exe", "GogitZIP-mac.dmg",
            "GogitZIP-%s-linux-x86_64.tar.gz" % ver, "GogitZIP-%s-linux-aarch64.tar.gz" % ver,
            "gogitzip_%s_amd64.deb" % ver, "gogitzip_%s_arm64.deb" % ver]


# ---------------------------------------------------------------- version

def check_version(t, ver):
    vh = read("src", "core", "version.h")
    parts = [re.search(r"#define GZ_VER_%s (\d+)" % k, vh) for k in ("MAJOR", "MINOR", "PATCH")]
    t.record(all(parts) and ".".join(p.group(1) for p in parts) == ver and re.fullmatch(r"\d+\.\d+\.\d+", ver),
             "version.h: GZ_APP_VERSION %s = GZ_VER_MAJOR.MINOR.PATCH" % ver)
    t.record(not re.search(r"#\s*include\s*<", vh), "version.h: preprocessor only (read by windres)")
    eng = read("src", "app", "engine.h")
    t.record('#include "version.h"' in eng and "#define GZ_APP_VERSION" not in eng,
             "engine.h takes the version from version.h")
    wapp = read("src", "win", "app.h")
    t.record(re.search(r"#define GZ_VERSION_W\s+GZ_WIDEN\(GZ_APP_VERSION\)", wapp) is not None
             and not re.search(r'GZ_VERSION_[AW]\s+L?"\d', wapp), "Windows app.h: version from version.h")
    rc = read("res", "app.rc")
    t.record('#include "../src/core/version.h"' in rc and "FILEVERSION     GZ_VER_MAJOR,GZ_VER_MINOR,GZ_VER_PATCH,0" in rc
             and "PRODUCTVERSION  GZ_VER_MAJOR,GZ_VER_MINOR,GZ_VER_PATCH,0" in rc
             and re.search(r'"FileVersion",\s+GZ_APP_VERSION', rc) and re.search(r'"ProductVersion",\s+GZ_APP_VERSION', rc)
             and not re.search(r'VERSION\s+\d+,\d+', rc), "res/app.rc: VERSIONINFO from version.h")
    mk = read("Makefile")
    t.record(re.search(r"^VERSION\s*:=.*src/core/version\.h", mk, re.M) is not None and "MACVER    = $(VERSION)" in mk,
             "Makefile: VERSION (macOS bundle, packages) from version.h")
    plist = read("data", "mac", "Info.plist")
    t.record(re.search(r"<key>CFBundleShortVersionString</key>\s*<string>@VERSION@</string>", plist) is not None and
             re.search(r"<key>CFBundleVersion</key>\s*<string>@VERSION@</string>", plist) is not None,
             "Info.plist template: CFBundleShortVersionString / CFBundleVersion = @VERSION@")
    meta = read("data", "linux", "gogitzip.metainfo.xml")
    rels = re.findall(r'<release version="([^"]+)" date="(\d{4}-\d\d-\d\d)"', meta)
    key = lambda v: tuple(int(x) for x in v.split("."))
    t.record(bool(rels) and rels[0][0] == ver and [r[0] for r in rels] == sorted((r[0] for r in rels), key=key, reverse=True),
             "metainfo: newest <release> is %s" % ver, str(rels))
    readme_txt = read("tools", "linux", "README.txt")
    t.record("@VERSION@" in readme_txt and not re.search(r"\b\d+\.\d+\.\d+\b", readme_txt.split("\n")[0]),
             "package README.txt: version filled in by pkg.sh")
    site = read("web", "index.html")
    m = re.search(r'<html[^>]*\bdata-version="([^"]+)"', site)
    t.record(m is not None and m.group(1) == ver, "web: <html data-version> = %s" % ver)
    for rel, need in ((("README.md",), "GogitZIP-%s-linux-x86_64.tar.gz" % ver),
                      (("web", "index.html"), "고깃ZIP %s" % ver),
                      ((".github", "release-notes.md"), "## 고깃ZIP %s" % ver)):
        t.record(need in read(*rel), "%s names %s" % ("/".join(rel), need))
    # stale release numbers next to the product name anywhere in the documents
    for rel in gen_docs.DOCS:
        txt = read(rel)
        bad = sorted({m.group(2) for rx in gen_docs.VERSION_RES for m in re.finditer(rx, txt) if m.group(2) != ver})
        t.record(not bad, "%s: no other release number" % rel, " ".join(bad))


def check_built(t, ver):
    """the programs print the version (when make test built them)"""
    cli = os.path.join(os.path.dirname(t.gzt), "gogitzip")
    if not os.path.exists(cli):
        return
    env = dict(os.environ, LANG="C.UTF-8")
    for k in ("LC_ALL", "LC_MESSAGES", "LANGUAGE"):
        env.pop(k, None)
    r = subprocess.run([cli, "--version"], capture_output=True, timeout=60, env=env)
    t.record(r.returncode == 0 and r.stdout.decode().strip() == "GogitZIP " + ver, "gogitzip --version",
             r.stdout.decode(errors="replace")[:200])
    r = subprocess.run([cli, "i"], capture_output=True, timeout=60, env=env)
    out = r.stdout.decode("utf-8", "replace")
    t.record(r.returncode == 0 and out.startswith("고깃ZIP %s\n" % ver), "gogitzip i: version line", out[:80])
    # the registry as the program has it vs. the source parser of tools/gen_docs.py
    readers, writers = gen_docs.registry(ROOT)
    head, _, tail = out.partition("Formats (create):")
    prog_r = [(l[2:14].rstrip(), l[15:].split()) for l in head.splitlines() if l.startswith("  ")]
    prog_w = []
    for l in tail.split("\n\n")[0].splitlines():
        if l.startswith("  "):
            rest = l[15:].split()
            prog_w.append((l[2:14].rstrip(), rest[0].lstrip("."), [x for x in rest[1:] if not x.startswith("+")],
                           [x[1:] for x in rest[1:] if x.startswith("+")]))
    src_r = [(x["name"], x["exts"]) for x in readers]
    src_w = [(x["name"], x["ext"], x["methods"], [gen_docs.ENC_NAME[e] for e in x["enc"]]) for x in writers]
    t.record(prog_r == src_r, "gen_docs.registry() readers = gogitzip i (%d)" % len(prog_r),
             "only in program: %s / only in parser: %s" % ([x for x in prog_r if x not in src_r][:5],
                                                           [x for x in src_r if x not in prog_r][:5]))
    t.record(prog_w == src_w, "gen_docs.registry() writers = gogitzip i (%d)" % len(prog_w),
             "%s / %s" % (prog_w[:3], src_w[:3]))


# ---------------------------------------------------------------- format tables

def check_tables(t, ver):
    readers, writers = gen_docs.registry(ROOT)
    gen, unplaced, undescribed = gen_docs.blocks(ROOT)
    # registry sanity: what gen_registry.sh would collect
    syms = set()
    for d in ("core", "codec", "fmt"):
        for fn in os.listdir(os.path.join(ROOT, "src", d)):
            if fn.endswith(".c"):
                syms |= set(re.findall(r"^GZ_FORMAT\((\w+)\)", read("src", d, fn), re.M))
    t.record(len(syms) == len(readers) and len(readers) >= 40, "registry: %d readers parsed, %d writers" %
             (len(readers), len(writers)))
    t.record(not unplaced, "every writer has a reader row", ", ".join(unplaced))
    t.record(True, "META describes every reader", ("undescribed: " + ", ".join(undescribed)) if undescribed else "")
    stale = gen_docs.stale(ROOT)
    t.record(not stale, "README / web / release notes match the registry and version",
             "stale: %s - run: python3 tools/gen_docs.py" % ", ".join(s[0] for s in stale))
    # every marker block present where the documents promise it
    want = {"README.md": ["formats-md", "formats-list-en", "nread", "nwrite"],
            "web/index.html": ["formats-html", "formats-filters", "nread", "nwrite"],
            ".github/release-notes.md": ["formats-list-ko", "writers-ko", "nread"]}
    for rel, keys in want.items():
        txt = read(*rel.split("/"))
        miss = [k for k in keys if "<!-- gen:%s -->" % k not in txt]
        t.record(not miss, "%s has generated blocks" % rel, "missing: %s" % miss)
    # the tables themselves: one row per reader, writers marked
    site = read("web", "index.html")
    rows = re.findall(r'<tr data-cat="(\w+)" data-w="([01])"', site)
    t.record(len(rows) == len(readers) and sum(int(w) for _, w in rows) == int(gen["nwritefmt"]),
             "site table: %d rows, %s writable" % (len(rows), gen["nwritefmt"]))
    md = read("README.md")
    block = md.split("<!-- gen:formats-md -->", 1)[-1].split("<!-- /gen:formats-md -->", 1)[0]
    mdrows = re.findall(r"^\| \*\*(.+?)\*\* \|", block, re.M)
    t.record(len(mdrows) == len(readers), "README tables: %d rows" % len(mdrows))
    for x in readers:
        if not any(e in site for e in ("<code>.%s</code>" % s for s in x["exts"][:1])):
            t.record(False, "site lists %s" % x["name"])


# ---------------------------------------------------------------- workflows

def make_targets():
    """rule names of the Makefile, $(B) and $(DIST) expanded"""
    mk = read("Makefile")
    out = set()
    for m in re.finditer(r"^([^\s#=:][^=:\n]*?)\s*::?(?!=)", mk, re.M):
        for tok in m.group(1).split():
            out.add(tok.replace("$(B)", "build").replace("$(DIST)", "build/dist"))
    ph = re.search(r"^\.PHONY:(.*)$", mk, re.M)
    if ph:
        out |= set(ph.group(1).split())
    return out


def make_calls(script):
    """targets named on `make ...` command lines of a shell script"""
    import shlex
    out = []
    for line in script.splitlines():
        if line.lstrip().startswith("#"):
            continue
        for m in re.finditer(r'(?:^|[;&|(]|\s)make\s+(.*)', line):
            rest = m.group(1)
            try:
                toks = shlex.split(rest, comments=True)
            except ValueError:
                toks = rest.split()
            i = 0
            while i < len(toks):
                tok = toks[i]
                if tok in (";", "&&", "||", "|") or tok.endswith((";", "|", "&")):
                    break
                if tok in ("-C", "-f", "-o", "-W", "-I"):
                    i += 2
                    continue
                if not tok.startswith("-") and not re.search(r"[=$<>]", tok):    # not options, variables, redirections
                    out.append(tok)
                i += 1
    return out


def run_scripts(text, yaml):
    """the run: scripts of a workflow (every non-comment line without PyYAML)"""
    if yaml is None:
        return [text]
    out = []
    try:
        doc = yaml.safe_load(text)
    except Exception:
        return [text]
    for job in (doc or {}).get("jobs", {}).values():
        for st in job.get("steps", []):
            if "run" in st:
                out.append(str(st["run"]))
    return out


def check_workflows(t, ver):
    wdir = os.path.join(ROOT, ".github", "workflows")
    files = sorted(f for f in os.listdir(wdir) if f.endswith((".yml", ".yaml")))
    t.record("build.yml" in files and "pages.yml" in files, "workflows: build.yml, pages.yml")
    targets = make_targets()
    try:
        import yaml
    except ImportError:
        yaml = None
    for fn in files:
        text = open(os.path.join(wdir, fn), encoding="utf-8").read()
        t.record("\t" not in text, "%s: no tabs" % fn)
        called = [c for sc in run_scripts(text, yaml) for c in make_calls(sc)]
        miss = sorted({c for c in called if c not in targets})
        t.record(not miss, "%s: make targets exist (%s)" % (fn, " ".join(sorted(set(called))) or "none"), str(miss))
        if yaml is None:
            continue
        try:
            doc = yaml.safe_load(text)
        except Exception as e:
            t.record(False, "%s: YAML parses" % fn, str(e)[:300])
            continue
        t.record(isinstance(doc, dict) and "jobs" in doc, "%s: YAML parses" % fn)
        if fn != "build.yml" or not isinstance(doc, dict):
            continue
        on = doc.get("on", doc.get(True, {}))          # YAML 1.1 reads the key "on" as True
        jobs = doc.get("jobs", {})
        t.record(isinstance(on, dict) and "v*" in (on.get("push") or {}).get("tags", []) and
                 "published" in (on.get("release") or {}).get("types", []) and
                 "tag" in ((on.get("workflow_dispatch") or {}).get("inputs") or {}),
                 "build.yml triggers: v* tags, published releases, manual run with a tag")
        want = {"windows", "linux-test", "linux-package", "macos", "release"}
        t.record(want <= set(jobs), "build.yml jobs: %s" % ", ".join(sorted(jobs)))
        # every job checking out code takes the tag on a manual run
        for name, job in jobs.items():
            for st in job.get("steps", []):
                if str(st.get("uses", "")).startswith("actions/checkout"):
                    ref = str((st.get("with") or {}).get("ref", ""))
                    t.record("inputs.tag" in ref and "workflow_dispatch" in ref, "build.yml %s: checks out the tag" % name, ref)
        rel = jobs.get("release", {})
        needs = rel.get("needs", [])
        t.record(set(needs) >= {"windows", "linux-test", "linux-package", "macos"}, "release job needs every build", str(needs))
        steps = rel.get("steps", [])
        pub = [s for s in steps if str(s.get("uses", "")).startswith("softprops/action-gh-release")]
        files_ = str((pub[0].get("with") or {}).get("files", "")) if pub else ""
        pats = [l.strip() for l in files_.splitlines() if l.strip()]
        import fnmatch
        names = assets(ver) + ["SHA256SUMS.txt"]
        unmatched = [n for n in names if not any(fnmatch.fnmatch("dist/" + n, p) for p in pats)]
        t.record(pub and not unmatched and (pub[0].get("with") or {}).get("body_path"),
                 "release attaches every asset + SHA256SUMS.txt with the notes", "unmatched: %s" % unmatched)
        body = json.dumps(steps, ensure_ascii=False)
        t.record("release-notes.md" in body and "sha256sum" in body, "release body = notes + checksums")
        pk = jobs.get("linux-package", {})
        mat = ((pk.get("strategy") or {}).get("matrix") or {}).get("include", [])
        t.record({m.get("arch") for m in mat} == {"x86_64", "aarch64"} and
                 all(str(m.get("os", "")).startswith("ubuntu-22.04") for m in mat),
                 "Linux packages: x86_64 + aarch64 on Ubuntu 22.04 (glibc 2.35)", str(mat))
        pjs = json.dumps(pk, ensure_ascii=False)
        t.record("make dist-linux deb" in pjs or ("make dist-linux" in pjs and "make deb" in pjs),
                 "linux-package job runs make dist-linux and make deb")
        tj = json.dumps(jobs.get("linux-test", {}), ensure_ascii=False)
        tools = ["xorriso", "genisoimage", "libarchive-tools", "squashfs-tools", "cabextract", "gcab", "mtools",
                 "dosfstools", "cpio", "rpm", "nsis", "lhasa", "arj", "unar", "wimtools", "lzip", "lzop", "zstd", "lz4",
                 "brotli", "ncompress", "qemu-utils", "fdisk", "gdisk", "ntfs-3g", "udftools", "msitools", "hfsprogs",
                 "innoextract", "7zip", "xvfb", "xdotool", "imagemagick", "libgtk-3-dev", "pyzipper", "pyppmd",
                 "pyliblzfse"]
        miss = [x for x in tools if not re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(x), tj)]
        t.record(not miss and "make test" in tj, "linux-test installs the test tools and runs make test", str(miss))


# ---------------------------------------------------------------- web site, README, notes

class _Html(HTMLParser):
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr",
            "path", "circle"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.errors, self.ids, self.refs, self.links = [], [], [], [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.append(a["id"])
        for k in ("src", "href"):
            if a.get(k):
                self.refs.append(a[k])
        if tag == "a":
            self.links.append(a)
        if tag not in self.VOID:
            self.stack.append((tag, self.getpos()))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in self.VOID and self.stack and self.stack[-1][0] == tag:
            self.stack.pop()

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if not self.stack or self.stack[-1][0] != tag:
            # optional end tags (p, li, tr, td ...) are not used on this page: everything is closed
            self.errors.append("unexpected </%s> at %s (open: %s)" % (tag, self.getpos(), self.stack[-1:]))
            for i in range(len(self.stack) - 1, -1, -1):
                if self.stack[i][0] == tag:
                    del self.stack[i:]
                    break
            return
        self.stack.pop()


def check_site(t, ver):
    html = read("web", "index.html")
    p = _Html()
    p.feed(html)
    p.close()
    t.record(not p.errors and [s[0] for s in p.stack] == [], "web/index.html: tags balanced",
             "; ".join(p.errors[:5]) + (" unclosed: %s" % p.stack[:5] if p.stack else ""))
    try:
        import html5lib
        parser = html5lib.HTMLParser(strict=False)
        parser.parse(html)
        errs = [e for e in parser.errors]
        t.record(not errs, "web/index.html: html5lib finds no parse errors", str(errs[:5]))
    except ImportError:
        pass
    dup = sorted({i for i in p.ids if p.ids.count(i) > 1})
    t.record(not dup, "web/index.html: unique ids", str(dup))
    missing = []
    for r in p.refs:
        if r.startswith(("http:", "https:", "#", "mailto:")):
            if r.startswith("#") and len(r) > 1 and r[1:] not in p.ids:
                missing.append(r)
            continue
        if not os.path.exists(os.path.join(ROOT, "web", r.split("#")[0])):
            missing.append(r)
    for r in re.findall(r'"(assets/[^"]+)"', html):          # screenshots named in the script
        if not os.path.exists(os.path.join(ROOT, "web", r)):
            missing.append(r)
    t.record(not missing, "web/index.html: local files and anchors exist", str(missing))
    dl = "https://github.com/NiSeullent/Butcherar/releases/latest/download/"
    hrefs = {a.get("href", "") for a in p.links}
    miss = [n for n in assets(ver) if dl + n not in hrefs]
    t.record(not miss, "web: download links for every release file", str(miss))
    bad = []
    for a in p.links:
        pat = a.get("data-asset")
        if pat is None:
            continue
        name = a.get("href", "").rsplit("/", 1)[-1]
        if not re.search(pat, name) or sum(1 for n in assets(ver) if re.search(pat, n)) != 1:
            bad.append((pat, name))
    t.record(not bad and sum(1 for a in p.links if "data-asset" in a) == len(assets(ver)),
             "web: data-asset patterns match exactly their file", str(bad))
    t.record(re.search(r'<meta name="viewport" content="width=device-width', html) is not None and
             "@media (max-width" in html, "web: phone layout (viewport, media queries)")
    t.record(not re.search(r"<script[^>]+src=", html), "web: no external scripts")
    for word in ("SmartScreen", "Gatekeeper", "xattr -dr com.apple.quarantine", "Windows 2000", "ALZ", "EGG", "AES-256"):
        t.record(word in html, "web mentions %s" % word)

    md = read("README.md")
    bad = []
    for m in re.finditer(r"\]\(([^)\s]+)\)|<img src=\"([^\"]+)\"", md):
        r = m.group(1) or m.group(2)
        if r.startswith(("http:", "https:", "#")):
            continue
        if not os.path.exists(os.path.join(ROOT, r.split("#")[0])):
            bad.append(r)
    t.record(not bad, "README: local links and images exist", str(bad))
    for word in ("## English", "Windows 2000", "10.13", "glibc 2.35", "make dist-linux", "make deb", "make mac",
                 "MinGW", "## 라이선스"):
        t.record(word in md, "README mentions %s" % word)

    notes = read(".github", "release-notes.md")
    miss = [n for n in assets(ver) if n not in notes]
    t.record(not miss, "release notes: download table names every file", str(miss))
    for word in ("압축 파일", "설치 파일·실행 파일", "디스크 이미지", "파일 시스템", "SmartScreen", "xattr -dr com.apple.quarantine",
                 "ALZ", "EGG", "SHA-256"):
        t.record(word in notes, "release notes mention %s" % word)


def check_packaging(t, ver):
    for fn in ("pkg.sh", "install.sh", "uninstall.sh"):
        path = os.path.join(ROOT, "tools", "linux", fn)
        r = subprocess.run(["sh", "-n", path], capture_output=True)
        t.record(r.returncode == 0 and os.access(path, os.X_OK), "tools/linux/%s: sh -n, executable" % fn,
                 r.stderr.decode(errors="replace")[:300])
    pkg = read("tools", "linux", "pkg.sh")
    t.record("name=GogitZIP-$ver-linux-$arch" in pkg and "name=gogitzip_${ver}_$arch" in pkg,
             "pkg.sh: file names GogitZIP-<ver>-linux-<arch>.tar.gz, gogitzip_<ver>_<arch>.deb")
    t.record("libgtk-3-0" in pkg and "--root-owner-group" in pkg, "pkg.sh: .deb depends on GTK 3, root-owned files")
    mk = read("Makefile")
    t.record(re.search(r"^dist-linux: linux$", mk, re.M) is not None and re.search(r"^deb: linux$", mk, re.M) is not None,
             "Makefile: dist-linux and deb targets")


def run(t):
    ver = gen_docs.version(ROOT)
    check_version(t, ver)
    check_tables(t, ver)
    check_workflows(t, ver)
    check_site(t, ver)
    check_packaging(t, ver)
    check_built(t, ver)
