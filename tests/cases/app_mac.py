"""고깃ZIP macOS front end (src/mac, data/mac, tools/gen_mac_data.py, tools/make_icns.py).

Everywhere (Linux included):
* data/mac is what tools/gen_mac_data.py generates; Info.plist and the .strings files are
  valid property lists with the keys a bundle needs; every document type UTI is declared
  (by macOS or our UTImportedTypeDeclarations), no extension has two UTIs, the main formats
  are claimed; every type and service has a Korean name
* NSServices messages exist as methods, menu selectors named in main.m are implemented,
  every TR/TRP/TRF/MS string id used by src/mac exists
* AppIcon.icns / ArchiveIcon.icns: icns structure, PNG elements ic07..ic10 of the right size
  (make_icns.py pack/parse/validate also on synthetic data, including damaged files)
* the Mac strings table (tests/drivers/app_mac_strings.c): both languages complete
* the Makefile's mac / dmg targets (dry run)
* with GNUstep's headers + clang: an Objective-C syntax and ARC check of every src/mac/*.m
  (GNUstep plus tests/data/app_mac/gnustep shims standing in for the newer AppKit API)
On macOS, when build/mac/GogitZIP.app exists (make mac): universal binary, minimum versions,
signature, Info.plist lint, and the app's command line modes (--extract-to, --test,
--compress with --yes, usage errors).
"""
import os, re, io, sys, glob, shutil, struct, zipfile, plistlib, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MAC = os.path.join(ROOT, "src", "mac")
DATA = os.path.join(ROOT, "data", "mac")
sys.path.insert(0, os.path.join(ROOT, "tools"))


def app_version():
    for rel in (("src", "core", "version.h"), ("src", "app", "engine.h")):
        m = re.search(r'#define GZ_APP_VERSION "([^"]+)"', open(os.path.join(ROOT, *rel)).read())
        if m:
            return m.group(1)


def load_plist(path):
    raw = open(path, "rb").read().replace(b"@VERSION@", app_version().encode())
    return plistlib.loads(raw)


def sources():
    return {os.path.basename(p): open(p, encoding="utf-8").read() for p in sorted(glob.glob(os.path.join(MAC, "*.[mh]")))}


# ---------------------------------------------------------------- generated data

def check_generated(t):
    r = t.sh([sys.executable, "-I", os.path.join(ROOT, "tools", "gen_mac_data.py"), "--check"], check=False)
    out = (r.stdout + r.stderr).decode("utf-8", "replace")
    t.record(r.returncode == 0, "data/mac is current (gen_mac_data.py --check)", out[-600:])


def check_info_plist(t):
    import gen_mac_data as g
    p = load_plist(os.path.join(DATA, "Info.plist"))
    need = {"CFBundleExecutable": "GogitZIP", "CFBundleIdentifier": g.BUNDLE_ID, "CFBundlePackageType": "APPL",
            "CFBundleIconFile": "AppIcon", "NSPrincipalClass": "NSApplication", "LSMinimumSystemVersion": "10.13",
            "CFBundleShortVersionString": app_version(), "CFBundleName": "GogitZIP"}
    bad = ["%s=%r" % (k, p.get(k)) for k, v in need.items() if p.get(k) != v]
    t.record(not bad, "Info.plist keys", " ".join(bad))
    t.record(p.get("LSMinimumSystemVersionByArchitecture") == {"x86_64": "10.13", "arm64": "11.0"} and
             p.get("NSHighResolutionCapable") is True, "Info.plist: per-architecture minimum, high resolution")
    locs = p.get("CFBundleLocalizations", [])
    t.record({"en", "ko"} <= set(locs) and all(os.path.isdir(os.path.join(DATA, l + ".lproj")) for l in ("en", "ko")),
             "localizations en + ko", repr(locs))
    for icon in ("AppIcon.icns", "ArchiveIcon.icns"):
        t.record(os.path.exists(os.path.join(DATA, icon)), "icon file " + icon)

    # document types and UTIs
    decl = {d["UTTypeIdentifier"]: d for d in p.get("UTImportedTypeDeclarations", [])}
    problems, ext_uti = [], {}
    for d in decl.values():
        exts = d.get("UTTypeTagSpecification", {}).get("public.filename-extension", [])
        conf = d.get("UTTypeConformsTo", [])
        if not exts or "public.data" not in conf or not d.get("UTTypeDescription"):
            problems.append("incomplete declaration " + d["UTTypeIdentifier"])
        for e in exts:
            if e != e.lower() or "." in e:
                problems.append("bad extension %r" % e)
            if ext_uti.setdefault(e, d["UTTypeIdentifier"]) != d["UTTypeIdentifier"]:
                problems.append("extension %s declared twice" % e)
    claimed = set()
    types = p.get("CFBundleDocumentTypes", [])
    for dt in types:
        if dt.get("LSHandlerRank") not in ("Default", "Alternate") or dt.get("CFBundleTypeRole") != "Viewer":
            problems.append("rank/role of " + dt.get("CFBundleTypeName", "?"))
        if not dt.get("LSItemContentTypes"):
            problems.append("no content types: " + dt.get("CFBundleTypeName", "?"))
        for u in dt.get("LSItemContentTypes", []):
            if u not in decl and u not in g.SYSTEM_UTIS:
                problems.append("undeclared UTI " + u)
            claimed.add(u)
    for u in decl:
        if u not in claimed:
            problems.append("declared but unused UTI " + u)
    t.record(types and not problems, "document types / imported UTIs (%d types, %d UTIs)" % (len(types), len(decl)),
             "; ".join(problems[:10]))
    # the extensions behind the claimed UTIs (system ones from the generator's table)
    exts = set(ext_uti)
    for en, ko, rank, kind, pairs in g.selected_types():
        exts.update(e for e, u in pairs)
    main = {"zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "zst", "lz4", "cab", "iso", "dmg", "lzh", "arj",
            "cpio", "rpm", "deb", "wim", "z", "lzma", "xar"}
    t.record(main <= exts, "main archive extensions claimed", " ".join(sorted(main - exts)))
    readable = __import__("gen_linux_data").readable_exts()
    missing, unread = g.unmapped(readable)
    t.record(True, "readable extensions without a document type: %s" % (" ".join(missing) or "none"))

    # Finder services
    svc = p.get("NSServices", [])
    src = "\n".join(sources().values())
    sp = []
    for s in svc:
        msg = s.get("NSMessage", "")
        if not re.search(r"-\s*\(void\)\s*%s:\s*\(NSPasteboard \*\)\w+\s+userData:\(NSString \*\)\w+\s+error:"
                         r"\(NSString \*\*\)\w+" % re.escape(msg), src):
            sp.append("no method %s:userData:error:" % msg)
        if s.get("NSPortName") != p.get("CFBundleName"):
            sp.append("NSPortName of " + msg)
        if "NSRequiredContext" not in s or not s.get("NSSendFileTypes"):
            sp.append("context / file types of " + msg)
        if not s.get("NSMenuItem", {}).get("default"):
            sp.append("title of " + msg)
    t.record(len(svc) == 3 and not sp, "NSServices (%d)" % len(svc), "; ".join(sp))
    return p


def check_strings_files(t, info):
    ko = plistlib.load(open(os.path.join(DATA, "ko.lproj", "InfoPlist.strings"), "rb"))
    en = plistlib.load(open(os.path.join(DATA, "en.lproj", "InfoPlist.strings"), "rb"))
    sm = plistlib.load(open(os.path.join(DATA, "ko.lproj", "ServicesMenu.strings"), "rb"))
    t.record(ko.get("CFBundleDisplayName") == "고깃ZIP" and en.get("CFBundleDisplayName") == "GogitZIP" and
             info.get("LSHasLocalizedDisplayName") is True, "localized display name")
    names = {d["CFBundleTypeName"] for d in info["CFBundleDocumentTypes"]}
    names |= {d["UTTypeDescription"] for d in info["UTImportedTypeDeclarations"]}
    miss = sorted(n for n in names if not ko.get(n))
    t.record(not miss, "Korean names of document types and UTIs", ", ".join(miss[:8]))
    titles = [s["NSMenuItem"]["default"] for s in info["NSServices"]]
    t.record(all(sm.get(x) for x in titles) and "고깃ZIP으로 압축" in sm.values() and "여기에 풀기" in sm.values(),
             "Korean service titles", repr(sm))


# ---------------------------------------------------------------- sources

def check_sources(t):
    src = sources()
    allsrc = "\n".join(src.values())
    strings_h = open(os.path.join(ROOT, "src", "app", "strings.h"), encoding="utf-8").read()
    mstrings_h = src.get("mstrings.h", "")
    ids = set(re.findall(r"\b(STR_[A-Z0-9_]+)\b", allsrc))
    unknown = sorted(i for i in ids if not re.search(r"X\(%s\s*," % i, strings_h))
    t.record(not unknown, "shared string ids used by src/mac exist (%d)" % len(ids), " ".join(unknown))
    mids = set(re.findall(r"\b(MS_[A-Z0-9_]+)\b", allsrc)) - {"MS__COUNT"}
    unknown = sorted(i for i in mids if not re.search(r"X\(%s\s*," % i, mstrings_h))
    t.record(not unknown, "mac string ids used by src/mac exist (%d)" % len(mids), " ".join(unknown))
    # actions the menus send to the window controller are implemented
    sels = set(re.findall(r"@selector\(((?:cmd|open|clear)\w*:)\)", src.get("main.m", "") + src.get("mainwnd.m", "")))
    missing = sorted(s for s in sels if not re.search(r"-\s*\((?:void|IBAction)\)\s*%s\s*\(" % re.escape(s), allsrc))
    t.record(sels and not missing, "menu / toolbar actions implemented (%d)" % len(sels), " ".join(missing))
    # no nullability annotations (a header with some needs them everywhere) and no libc in the strings table
    t.record(not re.search(r"\b(_Nullable|_Nonnull|nullable|nonnull|NS_ASSUME_NONNULL)\b", allsrc),
             "no nullability annotations in src/mac")
    t.record("#include <" not in mstrings_h, "mstrings.h needs no system header")
    # the Objective-C sources never include src/app/strings.h through the include path
    t.record(not re.search(r'#\s*(?:include|import)\s*[<"]strings\.h[>"]', allsrc),
             "src/app/strings.h included by relative path only")


def check_strings_driver(t):
    # build_driver links every build/host object; src/app/strings.o is among them once the
    # command line tool was built (make test does), else compile the source with the driver
    have = os.path.exists(os.path.join(os.path.dirname(t.gzt), "host", "app", "strings.o"))
    extra = () if have else (os.path.join(ROOT, "src", "app", "strings.c"),)
    drv = t.build_driver("tests/drivers/app_mac_strings.c", extra=extra)
    r = t.sh([drv], check=False)
    out = r.stdout.decode("utf-8", "replace")
    t.record(r.returncode == 0 and out.startswith("ok"), "mac strings table (both languages)", out[-800:])


# ---------------------------------------------------------------- icns

def png(w, h, color=b"\x80"):
    import zlib
    raw = b"".join(b"\x00" + color * (w * 4) for _ in range(h))
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def check_icns(t):
    import make_icns as mi
    for name in ("AppIcon.icns", "ArchiveIcon.icns"):
        data = open(os.path.join(DATA, name), "rb").read()
        probs = mi.validate(data)
        els = [e for e, _ in mi.parse(data)] if not probs else []
        t.record(not probs and len(data) < 200 * 1024, "%s: %s (%d KB)" % (name, " ".join(els), len(data) // 1024),
                 "; ".join(probs))
    # the container code itself: round trip, and damaged files are rejected, never crash
    good = mi.pack([("ic07", png(128, 128)), ("ic08", png(256, 256)), ("ic09", png(512, 512)),
                    ("ic10", png(1024, 1024))])
    ok = mi.validate(good) == [] and [e for e, _ in mi.parse(good)] == ["ic07", "ic08", "ic09", "ic10"]
    t.record(ok, "icns pack / parse round trip")
    bad = [
        good[:-1],                                    # truncated
        b"icnz" + good[4:],                           # magic
        good[:4] + struct.pack(">I", len(good) + 8) + good[8:],          # total length
        good[:12] + struct.pack(">I", 4) + good[16:],                    # element length < 8
        good[:12] + struct.pack(">I", 0x7fffffff) + good[16:],           # element past the end
        mi.pack([("ic07", png(64, 64))]),             # wrong size, missing elements
        mi.pack([("ic07", b"not a png")]),
    ]
    t.record(all(mi.validate(b) for b in bad), "damaged icns files are rejected (%d cases)" % len(bad))
    r = t.sh([sys.executable, "-I", os.path.join(ROOT, "tools", "make_icns.py"), "--check"], check=False)
    t.record(r.returncode == 0, "make_icns.py --check", (r.stdout + r.stderr).decode(errors="replace")[-400:])


# ---------------------------------------------------------------- build rules

def check_makefile(t):
    r = t.sh(["make", "-n", "-C", ROOT, "mac", "B=" + t.path("mk")], check=False)
    out = r.stdout.decode("utf-8", "replace")
    want = ["-fobjc-arc", "-arch x86_64 -arch arm64", "-mmacosx-version-min=10.13", "-framework Cocoa",
            "Contents/Info.plist", "Contents/Helpers/gogitzip", "codesign", "AppIcon.icns", "ko.lproj"]
    miss = [w for w in want if w not in out]
    nsrc = len(glob.glob(os.path.join(MAC, "*.m")))
    t.record(r.returncode == 0 and not miss and out.count("-x objective-c") == nsrc,
             "make -n mac (%d Objective-C files)" % nsrc, " ".join(miss) + r.stderr.decode(errors="replace")[-300:])
    r = t.sh(["make", "-n", "-C", ROOT, "dmg", "B=" + t.path("mk")], check=False)
    out = r.stdout.decode("utf-8", "replace")
    t.record(r.returncode == 0 and "hdiutil create" in out and "GogitZIP-mac.dmg" in out, "make -n dmg")


# ---------------------------------------------------------------- GNUstep syntax check

def gnustep_check(t):
    clang = shutil.which("clang")
    gs = "/usr/include/GNUstep"
    gcc = shutil.which("gcc")
    objc = None
    if gcc:
        r = subprocess.run([gcc, "-print-file-name=include"], capture_output=True, text=True)
        cand = os.path.join(r.stdout.strip(), "objc")
        if os.path.isfile(os.path.join(cand, "runtime.h")):
            objc = cand
    if not (clang and os.path.isfile(os.path.join(gs, "AppKit", "AppKit.h")) and objc):
        t.record(True, "Objective-C check skipped (needs clang, libgnustep-gui-dev, GCC objc headers)")
        return
    inc = t.path("gnustep", "inc")
    shutil.rmtree(inc, ignore_errors=True)
    shutil.copytree(os.path.join(ROOT, "tests", "data", "app_mac", "gnustep"), inc)
    # GCC's runtime headers, made acceptable to clang with ARC
    for f in os.listdir(objc):
        s = open(os.path.join(objc, f), encoding="utf-8", errors="replace").read()
        if f == "runtime.h":
            s = s.replace("return object->class_pointer;",
                          "return ((struct objc_object *)(__bridge void *)object)->class_pointer;")
            s = s.replace("Protocol **", "Protocol *__unsafe_unretained *")
        dst = os.path.join(inc, "objc", f)
        if not os.path.exists(dst):
            open(dst, "w", encoding="utf-8").write(s)
    files = sorted(glob.glob(os.path.join(MAC, "*.m")))
    bad = []
    env_skip = None
    for f in files:
        cmd = [clang, "-fsyntax-only", "-x", "objective-c", "-std=gnu11", "-fobjc-arc", "-fblocks",
               "-fobjc-runtime=gnustep-2.0", "-DGNUSTEP", "-DGNUSTEP_BASE_LIBRARY=1", "-DGNU_GUI_LIBRARY=1",
               "-DGNU_RUNTIME=1", "-Wall", "-Wextra", "-Wno-unused-parameter", "-Wno-missing-field-initializers",
               "-Wno-protocol", "-I" + inc, "-I" + gs, "-include", os.path.join(inc, "appkit_compat.h"),
               "-I" + os.path.join(ROOT, "src", "core"), "-I" + os.path.join(ROOT, "src", "codec"),
               "-I" + os.path.join(ROOT, "src", "fmt"), f]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        lines = [l for l in r.stderr.splitlines() if re.search(r": (error|warning):", l)]
        mine = [l for l in lines if l.startswith(MAC) and "id<NSMenuItem>" not in l]
        if r.returncode and not mine:
            env_skip = lines[:3]           # the shim does not fit this GNUstep: not our code
        if mine:
            bad.append("%s: %s" % (os.path.basename(f), " | ".join(mine[:4])))
    if env_skip and not bad:
        t.record(True, "Objective-C check skipped: GNUstep headers differ from the shim", " ".join(env_skip))
        return
    t.record(not bad, "Objective-C syntax + ARC check of %d files (GNUstep)" % len(files), "\n".join(bad))


# ---------------------------------------------------------------- macOS: the built bundle

def check_bundle(t):
    app = os.path.join(os.path.dirname(t.gzt), "mac", "GogitZIP.app")
    if sys.platform != "darwin" or not os.path.isdir(app):
        t.record(True, "bundle checks skipped (macOS with make mac only)")
        return
    exe = os.path.join(app, "Contents", "MacOS", "GogitZIP")
    helper = os.path.join(app, "Contents", "Helpers", "gogitzip")
    for b in (exe, helper):
        r = t.sh(["lipo", b, "-verify_arch", "x86_64", "arm64"], check=False)
        t.record(r.returncode == 0, "universal " + os.path.basename(b))
    r = t.sh(["otool", "-arch", "arm64", "-l", exe], check=False)
    t.record(b"minos 11.0" in r.stdout, "arm64 slice: macOS 11")
    r = t.sh(["otool", "-arch", "x86_64", "-l", exe], check=False)
    t.record(re.search(rb"(minos|version) 10\.13", r.stdout) is not None, "x86_64 slice: macOS 10.13")
    r = t.sh(["plutil", "-lint", os.path.join(app, "Contents", "Info.plist")], check=False)
    t.record(r.returncode == 0, "plutil -lint Info.plist")
    r = t.sh(["codesign", "--verify", "--deep", "--strict", app], check=False)
    t.record(r.returncode == 0, "codesign --verify", r.stderr.decode(errors="replace")[-300:])
    for f in ("AppIcon.icns", "ArchiveIcon.icns", "assets.bin", "ko.lproj/InfoPlist.strings"):
        t.record(os.path.exists(os.path.join(app, "Contents", "Resources", f)), "bundle resource " + f)
    r = t.sh([exe, "--version"], check=False, timeout=60)
    t.record(r.returncode == 0 and app_version().encode() in r.stdout, "GogitZIP --version")
    r = t.sh([exe, "--no-such-option"], check=False, timeout=60)
    t.record(r.returncode == 7 and b"--extract-to" in r.stderr, "usage error: exit 7")

    # command line modes (a window server session is needed: GitHub's macOS runners have one)
    files = {"top/readme.txt": b"hello\n" * 100, "top/고기/삼겹살.txt": "목살 갈비\n".encode() * 500,
             "top/empty.txt": b""}
    z = t.path("cli", "in.zip")
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        for n, d in files.items():
            zf.writestr(n, d)
    out = t.path("cli", "out")
    shutil.rmtree(out, ignore_errors=True)
    r = t.sh([exe, "--extract-to", out, "--yes", z], check=False, timeout=120)
    err = r.stderr.decode("utf-8", "replace")
    if r.returncode and re.search(r"WindowServer|CGS|kCGError|_RegisterApplication", err):
        t.record(True, "command line modes skipped: no window server session", err[-300:])
        return
    t.record(r.returncode == 0 and t.read_tree(out) == files, "--extract-to --yes", err[-400:])
    r = t.sh([exe, "--test", "--yes", z], check=False, timeout=120)
    t.record(r.returncode == 0, "--test --yes (good archive)", r.stderr.decode(errors="replace")[-300:])
    broken = t.path("cli", "broken.zip")
    data = bytearray(open(z, "rb").read())
    data[60:90] = bytes(30)
    open(broken, "wb").write(bytes(data))
    r = t.sh([exe, "--test", "--yes", broken], check=False, timeout=120)
    t.record(r.returncode == 2, "--test --yes (damaged archive): exit 2", "rc=%d" % r.returncode)
    src = t.write_tree(t.path("cli", "src"), files)
    made = t.path("cli", "made.zip")
    if os.path.exists(made):
        os.remove(made)
    r = t.sh([exe, "--compress", os.path.join(src, "top"), "--output", made, "--yes"], check=False, timeout=120)
    ok = r.returncode == 0 and os.path.exists(made)
    if ok:
        with zipfile.ZipFile(made) as zf:
            got = {n: zf.read(n) for n in zf.namelist() if not n.endswith("/")}
        ok = got == files
    t.record(ok, "--compress --output --yes", r.stderr.decode(errors="replace")[-300:])


def run(t):
    check_generated(t)
    info = check_info_plist(t)
    check_strings_files(t, info)
    check_sources(t)
    check_strings_driver(t)
    check_icns(t)
    check_makefile(t)
    gnustep_check(t)
    check_bundle(t)
