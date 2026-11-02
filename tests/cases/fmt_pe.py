"""Executable readers: PE/COFF (PE32, PE32+) and TE, ELF, Mach-O and universal binaries.

PE: sections, the resource tree with conversions (ICON/GROUP_ICON -> .ico, GROUP_CURSOR -> .cur,
BITMAP -> .bmp, VERSION and STRING tables -> .txt, MANIFEST), COFF symbols, Authenticode
certificates, overlays and nested archives opened in place (view()).
References: 7-Zip (sections, raw resources, single-icon .ico, .bmp, string/version texts),
icoutils' wrestool (whole .ico/.cur rebuilt from groups), the original files fed to windres,
osslsigncode (signature). Also: SFX regressions (a PE/ELF stub with an appended archive opens
as the archive), Wine's DLLs, hostile and fuzzed inputs."""
import os, re, io, struct, zlib, shutil, subprocess, random, zipfile, tarfile, gzip

BOM = b"\xef\xbb\xbf"
WINE = ["/usr/lib/x86_64-linux-gnu/wine/x86_64-windows", "/usr/lib/i386-linux-gnu/wine/i386-windows",
        "/usr/lib/wine/x86_64-windows", "/usr/lib/wine/i386-windows"]

# ---------------------------------------------------------------- helpers

def write(p, data):
    with open(p, "wb") as f:
        f.write(data)
    return p

def gzt_rows(t, path, env=None):
    """{name: (status, data)} of gzt x, plus the type string."""
    r, rows, out = t.extract(path, env=env)
    info = r.stderr.decode("utf-8", "replace")
    m = re.search(r"type=(.*?) entries=", info)
    res = {}
    for i, (st, isdir, size, name) in rows.items():
        fp = os.path.join(out, "%d.bin" % i)
        res[name] = (st, open(fp, "rb").read() if os.path.exists(fp) else None)
    return (m.group(1) if m else None), res

def seven_tree(t, path, typ=None):
    out = os.path.join(t.work, "ref7z")
    shutil.rmtree(out, ignore_errors=True)
    args = ["7z", "x", "-y", "-o" + out, path] + (["-t" + typ] if typ else [])
    r = subprocess.run(args, capture_output=True, timeout=600)
    return r.returncode, t.read_tree(out)

def split7(k):
    """7-Zip resource path -> (lang|None, TYPE, name) or (lang|None, 'string'|'version', None).
    7-Zip names resources ".rsrc/<lang>/<TYPE>/<name>" and drops <lang> when the file uses one."""
    parts = k.split("/")
    if parts[0] != ".rsrc" or len(parts) < 2:
        return None
    rest = parts[1:]
    if len(rest) == 1 and rest[0] in ("string.txt", "version.txt"):
        return (None, rest[0][:-4], None)
    if len(rest) == 2 and rest[0].isdigit() and rest[1] in ("string.txt", "version.txt"):
        return (rest[0], rest[1][:-4], None)
    if len(rest) == 3:
        return tuple(rest)
    if len(rest) == 2:
        return (None, rest[0], rest[1])
    return None

def u16_to_txt(v):
    return BOM + v.decode("utf-16-le", "surrogatepass").encode("utf-8", "replace")

def compare_pe_7z(ref, mine):
    """Problems between 7-Zip's extraction of a PE and ours (names mapped to our layout)."""
    multi, slangs, probs = {}, 0, []
    for k in ref:
        m = split7(k)
        if m and m[2] is not None:
            multi.setdefault((m[1], re.sub(r"\.(ico|bmp)$", "", m[2])), set()).add(m[0])
        elif m:
            slangs += m[1] == "string"
    for k, v in ref.items():
        m = split7(k)
        if m and m[2] is not None:
            lang, typ, nm = m
            if typ in ("GROUP_ICON", "GROUP_CURSOR"):
                continue                      # whole .ico/.cur: checked against wrestool
            base = re.sub(r"\.(ico|bmp)$", "", nm)
            ext = nm[len(base):]
            if typ == "ICON" and not ext and v[:8] == b"\x89PNG\r\n\x1a\n":
                ext = ".png"
            name = ".rsrc/%s/%s" % (typ, base)
            if len(multi[(typ, base)]) > 1:
                name += "/" + lang
            cands = [x for x in mine if x == name or x == name + ext or x.startswith(name + ".")]
            if not cands:
                probs.append("missing " + name + ext)
            elif typ == "BITMAP" and not ext and any(c.endswith(".bmp") and (mine[c][1] or b"")[14:] == v
                                                     and mine[c][1][:2] == b"BM" for c in cands):
                pass                          # header 7-Zip does not build (V4/V5 headers)
            elif not any(mine[c][1] == v for c in cands):
                probs.append("data %s (%s)" % (name + ext, ",".join(cands)))
        elif m:
            lang, kind, _ = m
            want = u16_to_txt(v)
            if kind == "string":
                cands = [".rsrc/STRING.txt" if slangs == 1 else ".rsrc/STRING/%s.txt" % lang]
            else:
                cands = [x for x in mine if re.match(r"^\.rsrc/VERSION/[^/]+(/%s)?\.txt$" % (lang or r"\d+"), x)]
            if not any(c in mine and mine[c][1] == want for c in cands):
                probs.append("text %s -> %s" % (k, cands))
        elif k in mine:
            if mine[k][1] != v:
                probs.append("data " + k)
        elif not any(x[1] == v for x in mine.values()):
            probs.append("missing " + k)       # sections with resolved long names ("_4")
    return probs

def wrestool_groups(t, path, mine):
    """Compare our GROUP_ICON/GROUP_CURSOR files with wrestool -x. Returns (count, problems)."""
    wd = os.path.join(t.work, "wrestool")
    shutil.rmtree(wd, ignore_errors=True)
    os.makedirs(wd)
    for ty in ("14", "12"):
        subprocess.run(["wrestool", "-x", "-t" + ty, "-o", wd, path], capture_output=True, timeout=120)
    n, probs = 0, []
    for fn in sorted(os.listdir(wd)):
        m = re.match(r"^.*?_(12|14)_(.+?)(?:_(\d+))?\.(ico|cur)$", fn)   # wrestool may omit the language
        if not m:
            continue
        typ = "GROUP_ICON" if m.group(1) == "14" else "GROUP_CURSOR"
        name, lang, ext = m.group(2), m.group(3), m.group(4)
        d = bytearray(open(os.path.join(wd, fn), "rb").read())
        cnt = struct.unpack_from("<H", d, 4)[0]
        if ext == "cur":                      # wrestool keeps the hot spot WORDs in dwBytesInRes
            for i in range(cnt):
                o = 6 + 16 * i + 8
                struct.pack_into("<I", d, o, struct.unpack_from("<I", d, o)[0] - 4)
        cands = [".rsrc/%s/%s.%s" % (typ, name, ext)] + ([".rsrc/%s/%s/%s.%s" % (typ, name, lang, ext)] if lang else [])
        cands = [c for c in cands if c in mine]
        n += 1
        if not cands:
            probs.append("missing %s %s" % (typ, name)); continue
        got = mine[cands[0]][1] or b""
        # wrestool also appends as many junk bytes as the group directory has
        if bytes(d) != got and not (bytes(d[:len(got)]) == got and len(d) - len(got) == 6 + 14 * cnt):
            probs.append("data %s" % cands[0])
    return n, probs

# ---------------------------------------------------------------- image file generators

def png(w, h, seed=0):
    raw = b"".join(b"\0" + bytes((x * 7 + y * 3 + seed) & 255 for x in range(w * 4)) for y in range(h))
    def ch(tag, d):
        return struct.pack(">I", len(d)) + tag + d + struct.pack(">I", zlib.crc32(tag + d) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)) +
            ch(b"IDAT", zlib.compress(raw)) + ch(b"IEND", b""))

def dib(w, h, bpp, icon=True, seed=0):
    ncol = 1 << bpp if bpp <= 8 else 0
    row, mrow = ((w * bpp + 31) // 32) * 4, ((w + 31) // 32) * 4
    pix = bytes((i * 13 + bpp + seed) & 255 for i in range(row * h))
    mask = bytes((i * 5 + seed) & 255 for i in range(mrow * h)) if icon else b""
    hdr = struct.pack("<IiiHHIIiiII", 40, w, h * 2 if icon else h, 1, bpp, 0, len(pix) + len(mask), 0, 0, 0, 0)
    pal = bytes((i * 3 + seed) & 255 for i in range(ncol * 4))
    return hdr + pal + pix + mask

def icondir(imgs, typ=1):
    """imgs: (w, h, colors, planes|hotx, bitcount|hoty, data) -> .ico / .cur file"""
    out = struct.pack("<HHH", 0, typ, len(imgs))
    off, data = 6 + 16 * len(imgs), b""
    for (w, h, cc, a, b, d) in imgs:
        out += struct.pack("<BBBBHHII", w & 255, h & 255, cc, 0, a, b, len(d), off)
        off += len(d)
        data += d
    return out + data

def bmp_file(w, h, bpp, seed=0):
    d = dib(w, h, bpp, False, seed)
    pal = (1 << bpp) * 4 if bpp <= 8 else 0
    return b"BM" + struct.pack("<IHHI", 14 + len(d), 0, 0, 14 + 40 + pal) + d

# ---------------------------------------------------------------- a small PE writer (hostile cases)

def rsrc_section(leaves, va):
    """leaves: [(type, name, lang, data)] with int ids or str names -> .rsrc bytes at RVA va.
    Layout as linkers write it: directories (preorder), data entries, name strings, data."""
    tree = {}
    for ty, nm, lg, d in leaves:
        tree.setdefault(ty, {}).setdefault(nm, {})[lg] = d
    key = lambda k: (0, k) if isinstance(k, str) else (1, k)
    dirs = []                                # [level, keys, node, child dir indices]

    def walk(level, node):
        i = len(dirs)
        ents = sorted(node, key=key)
        dirs.append([level, ents, node, []])
        if level < 2:
            for k in ents:
                dirs[i][3].append(walk(level + 1, node[k]))
        return i
    walk(0, tree)
    off, dir_off = 0, []
    for d in dirs:
        dir_off.append(off)
        off += 16 + 8 * len(d[1])
    data = [d[2][k] for d in dirs if d[0] == 2 for k in d[1]]
    de_off = off
    off += 16 * len(data)
    name_off = {}
    for n in sorted({k for d in dirs for k in d[1] if isinstance(k, str)}):
        name_off[n] = off
        off += 2 + 2 * len(n)
    off = (off + 15) & ~15
    data_off = []
    for x in data:
        data_off.append(off)
        off = (off + len(x) + 7) & ~7
    buf = bytearray(off)
    li = 0
    for i, (level, ents, node, kids) in enumerate(dirs):
        o = dir_off[i]
        nn = sum(isinstance(k, str) for k in ents)
        struct.pack_into("<IIHHHH", buf, o, 0, 0, 0, 0, nn, len(ents) - nn)
        for j, k in enumerate(ents):
            nf = (0x80000000 | name_off[k]) if isinstance(k, str) else k
            if level < 2:
                of = 0x80000000 | dir_off[kids[j]]
            else:
                of = de_off + 16 * li
                struct.pack_into("<IIII", buf, of, va + data_off[li], len(data[li]), 0, 0)
                buf[data_off[li]:data_off[li] + len(data[li])] = data[li]
                li += 1
            struct.pack_into("<II", buf, o + 16 + 8 * j, nf, of)
    for n, o in name_off.items():
        struct.pack_into("<H", buf, o, len(n))
        enc = n.encode("utf-16-le")
        buf[o + 2:o + 2 + len(enc)] = enc
    return bytes(buf)

def sect_off(img, name):
    """file offset of a section's raw data in a PE image"""
    lf = struct.unpack_from("<I", img, 0x3C)[0]
    ns, optsz = struct.unpack_from("<H", img, lf + 6)[0], struct.unpack_from("<H", img, lf + 20)[0]
    for i in range(ns):
        o = lf + 24 + optsz + 40 * i
        if img[o:o + 8].rstrip(b"\0") == name.encode():
            return struct.unpack_from("<I", img, o + 20)[0]
    return None

def pe_image(sections, rsrc=None, pe64=False, ts=0x5F5E1000, cert=None, overlay=b"", nsec_override=None,
             lfanew=0x80):
    """sections: [(name, data, chars)]; rsrc: leaves for a .rsrc section (appended last)."""
    fa, sa = 0x200, 0x1000
    secs = list(sections)
    hdr_end = lfanew + 24 + (240 if pe64 else 224) + 40 * (len(secs) + (1 if rsrc is not None else 0))
    first = (hdr_end + fa - 1) & ~(fa - 1)
    va, off, table, body = sa, first, [], b""
    rs_dir = (0, 0)
    allsec = secs + ([(".rsrc", None, 0x40000040)] if rsrc is not None else [])
    for name, data, chars in allsec:
        if data is None:
            data = rsrc_section(rsrc, va)
            rs_dir = (va, len(data))
        raw = (len(data) + fa - 1) & ~(fa - 1)
        table.append(struct.pack("<8sIIIIIIHHI", name.encode()[:8], len(data), va, raw, off if raw else 0, 0, 0, 0, 0, chars))
        body += data + bytes(raw - len(data))
        off += raw
        va += (max(len(data), 1) + sa - 1) & ~(sa - 1)
    dirs = [(0, 0)] * 16
    dirs[2] = rs_dir
    end = first + len(body)
    tail = b""
    if overlay:
        tail += overlay
    if cert is not None:
        pad = (-(end + len(tail))) % 8
        tail += bytes(pad)
        wc = struct.pack("<IHH", 8 + len(cert), 0x200, 2) + cert
        wc += bytes((-len(wc)) % 8)
        dirs[4] = (end + len(tail), len(wc))
        tail += wc
    if pe64:
        opt = struct.pack("<HBBIIIII", 0x20B, 2, 30, len(body), 0, 0, 0x1000, 0x1000) + struct.pack(
            "<QIIHHHHHHIIIIHHQQQQII", 0x140000000, sa, fa, 6, 0, 0, 0, 5, 2, 0, va, first, 0, 2, 0x160,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    else:
        opt = struct.pack("<HBBIIIIII", 0x10B, 2, 30, len(body), 0, 0, 0x1000, 0x1000, 0) + struct.pack(
            "<IIIHHHHHHIIIIHHIIIIII", 0x400000, sa, fa, 4, 0, 0, 0, 4, 0, 0, va, first, 0, 2, 0x8140,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"".join(struct.pack("<II", *d) for d in dirs)
    coff = struct.pack("<4sHHIIIHH", b"PE\0\0", 0x8664 if pe64 else 0x14C,
                       nsec_override if nsec_override is not None else len(table), ts, 0, 0, len(opt), 0x102)
    dos = bytearray(lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, lfanew)
    head = bytes(dos) + coff + opt + b"".join(table)
    return head + bytes(first - len(head)) + body + tail

def string_block(strings):
    """16 counted UTF-16 strings (index -> text)"""
    out = b""
    for i in range(16):
        s = strings.get(i, "").encode("utf-16-le")
        out += struct.pack("<H", len(s) // 2) + s
    return out

# ---------------------------------------------------------------- test sections

def check_views(t, drv, path, label):
    r = t.sh([drv, "view", path], check=False, timeout=600)
    out = r.stdout.decode(errors="replace")
    t.record(r.returncode == 0 and "VIEW OK" in out, "views " + label, out.strip().splitlines()[-1] if out else "")

def child(t, drv, path, entry, label, expect_type, expect):
    out = t.path("child_" + re.sub(r"\W", "_", label))
    shutil.rmtree(out, ignore_errors=True)
    r = t.sh([drv, "child", path, entry, out], check=False)
    lines = r.stdout.decode("utf-8", "replace").splitlines()
    got = {}
    typ = None
    for ln in lines:
        p = ln.split("\t")
        if p[0] == "TYPE":
            typ = p[1]
        elif len(p) == 5 and p[0].isdigit() and p[2] == "0":
            fp = os.path.join(out, p[0] + ".bin")
            got[p[4]] = open(fp, "rb").read() if os.path.exists(fp) and p[1] == "0" else None
    ok = typ == expect_type and all((v in got.values()) if k is None else got.get(k) == v for k, v in expect.items())
    t.record(ok, "nested %s" % label, "type=%s entries=%d %s" % (typ, len(got), "" if ok else lines[:3]))

def wine_files():
    out = []
    for d in WINE:
        if os.path.isdir(d):
            out += [os.path.join(d, f) for f in sorted(os.listdir(d)) if re.search(r"\.(exe|dll|drv|cpl|ocx|sys|acm|tlb)$", f)]
    return out

def test_wine(t, drv):
    files = wine_files()
    if not files:
        t.record(True, "wine DLLs", "skipped: Wine not installed")
        return
    keep = ("notepad.exe", "comctl32.dll", "shell32.dll", "user32.dll", "ole32.dll", "riched20.dll",
            "winecfg.exe", "regedit.exe", "comdlg32.dll", "msi.dll", "shdocvw.dll", "oleaut32.dll")
    pick = [f for i, f in enumerate(files) if i % 40 == 0 or os.path.basename(f) in keep]
    bad, groups, gbad = [], 0, []
    wres = t.tool("wrestool")
    for f in pick:
        rc, ref = seven_tree(t, f, "PE")
        typ, mine = gzt_rows(t, f)
        probs = compare_pe_7z(ref, mine) if typ == "PE" else ["type %s" % typ]
        if probs:
            bad.append("%s: %s" % (os.path.basename(f), probs[:3]))
        if wres:
            n, p = wrestool_groups(t, f, mine)
            groups += n
            gbad += p
    t.record(not bad, "Wine PE vs 7-Zip (%d files)" % len(pick), "; ".join(bad[:4]))
    if wres:
        t.record(not gbad and groups > 20, "Wine icon/cursor groups vs wrestool (%d)" % groups, "; ".join(gbad[:4]))
    for nm in ("notepad.exe", "comctl32.dll"):
        for f in files:
            if os.path.basename(f) == nm:
                check_views(t, drv, f, os.path.basename(os.path.dirname(f)) + "/" + nm)

RC = r'''#include <windows.h>
LANGUAGE LANG_ENGLISH, SUBLANG_ENGLISH_US
1 ICON "app.ico"
MainIcon ICON "app.ico"
2 CURSOR "arrow.cur"
10 BITMAP "pic.bmp"
11 BITMAP "pal.bmp"
1 24 "app.manifest"
100 RCDATA "payload.zip"
About HTML "about.htm"
300 MyType { "named type data" }
200 RCDATA { "english" }
STRINGTABLE { 1 "Hello" 2 "Line\nTwo" 17 "Seventeen" }
VS_VERSION_INFO VERSIONINFO
 FILEVERSION 1,2,3,4
 PRODUCTVERSION 5,6,7,8
 FILEFLAGSMASK 0x3f
 FILEFLAGS 0x41
 FILEOS VOS_NT_WINDOWS32
 FILETYPE VFT_APP
 FILESUBTYPE 0
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "041204B0"
    BEGIN
      VALUE "CompanyName", "고깃집 테스트"
      VALUE "FileDescription", "GogitZIP PE test"
      VALUE "FileVersion", "1.2.3.4"
      VALUE "AVeryLongKeyNameForPadding", "x"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x412, 1200
  END
END
LANGUAGE LANG_KOREAN, SUBLANG_KOREAN
STRINGTABLE { 1 "안녕하세요" 33 "둘째 블록" }
200 RCDATA { "korean" }
'''

def build_windres(t):
    """Fixture executables (i686 and x86-64) from RC with the input files. None without MinGW."""
    tools = [("i686-w64-mingw32-gcc", "i686-w64-mingw32-windres", "app32.exe"),
             ("x86_64-w64-mingw32-gcc", "x86_64-w64-mingw32-windres", "app64.exe")]
    d = t.path("rc", "x")[:-2]
    os.makedirs(d, exist_ok=True)
    ico = icondir([(16, 16, 16, 1, 4, dib(16, 16, 4)), (32, 32, 0, 1, 8, dib(32, 32, 8, seed=1)),
                   (48, 48, 0, 1, 32, dib(48, 48, 32, seed=2)), (256, 256, 0, 1, 32, png(256, 256))])
    cur = icondir([(32, 32, 0, 5, 7, dib(32, 32, 1, seed=3)), (16, 16, 0, 1, 2, dib(16, 16, 1, seed=4))], 2)
    files = {"app.ico": ico, "arrow.cur": cur, "pic.bmp": bmp_file(40, 30, 24), "pal.bmp": bmp_file(20, 10, 8, 5),
             "app.manifest": b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                             b'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"/>\n',
             "about.htm": b"<html><body>about</body></html>", "main.c": b"int main(void){return 0;}\n",
             "app.rc": RC.encode("utf-8")}
    zb = io.BytesIO()
    with zipfile.ZipFile(zb, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("inner/a.txt", b"inner file " * 50)
        z.writestr("b.bin", bytes(range(256)))
    files["payload.zip"] = zb.getvalue()
    for k, v in files.items():
        write(os.path.join(d, k), v)
    out = {}
    for cc, wr, exe in tools:
        if not (t.tool(cc) and t.tool(wr)):
            continue
        o = os.path.join(d, exe[:-4] + ".o")
        t.sh([wr, "-c", "65001", "app.rc", "-O", "coff", "-o", o], cwd=d)
        t.sh([cc, "-o", os.path.join(d, exe), "main.c", o], cwd=d)
        out[exe] = os.path.join(d, exe)
    return out, files

def test_windres(t, drv):
    exes, files = build_windres(t)
    if not exes:
        t.record(True, "windres fixtures", "skipped: MinGW not installed")
        return None
    s1033 = BOM + b"1\tHello\r\n2\tLine\\nTwo\r\n17\tSeventeen\r\n"
    s1042 = BOM + "1\t안녕하세요\r\n33\t둘째 블록\r\n".encode("utf-8")
    exp = {
        ".rsrc/GROUP_ICON/1.ico": files["app.ico"],
        ".rsrc/GROUP_ICON/MAINICON.ico": files["app.ico"],
        ".rsrc/GROUP_CURSOR/2.cur": files["arrow.cur"],
        ".rsrc/BITMAP/10.bmp": files["pic.bmp"],
        ".rsrc/BITMAP/11.bmp": files["pal.bmp"],
        ".rsrc/MANIFEST/1.manifest": files["app.manifest"],
        ".rsrc/RCDATA/100.zip": files["payload.zip"],
        ".rsrc/HTML/ABOUT.html": files["about.htm"],
        ".rsrc/MYTYPE/300": b"named type data",
        ".rsrc/RCDATA/200/1033": b"english",
        ".rsrc/RCDATA/200/1042": b"korean",
        ".rsrc/STRING/1033.txt": s1033,
        ".rsrc/STRING/1042.txt": s1042,
        ".rsrc/ICON/4.png": png(256, 256),
    }
    for exe, path in sorted(exes.items()):
        typ, mine = gzt_rows(t, path)
        probs = [k for k, v in exp.items() if k not in mine or mine[k][1] != v]
        t.record(typ == "PE" and not probs, "windres %s resources" % exe,
                 "type=%s bad=%s have=%s" % (typ, probs[:4], sorted(k for k in mine if k.startswith(".rsrc"))[:40] if probs else ""))
        # the version text: 7-Zip's layout (also a key longer than the alignment column)
        ver = mine.get(".rsrc/VERSION/1.txt", (0, b""))[1] or b""
        t.record(ver.startswith(BOM + b"FILEVERSION    1,2,3,4\r\nPRODUCTVERSION 5,6,7,8\r\n") and
                 "고깃집 테스트".encode() in ver and b"FILEFLAGS      VS_FF_DEBUG | 0x40\r\n" in ver and
                 b'VALUE "AVeryLongKeyNameForPadding", "x"' in ver and
                 b"FILEOS         VOS_NT_WINDOWS32\r\n" in ver, "windres %s version text" % exe, ver[:60])
        rc, ref = seven_tree(t, path, "PE")
        probs = compare_pe_7z(ref, mine)
        t.record(rc == 0 and not probs, "windres %s vs 7-Zip" % exe, "; ".join(probs[:4]))
        if t.tool("wrestool"):
            n, p = wrestool_groups(t, path, mine)
            t.record(n == 3 and not p, "windres %s groups vs wrestool" % exe, "%d %s" % (n, p[:3]))
        check_views(t, drv, path, exe)
        child(t, drv, path, ".rsrc/RCDATA/100.zip", "zip in RCDATA of " + exe, "ZIP",
              {"inner/a.txt": b"inner file " * 50, "b.bin": bytes(range(256))})
    return exes

def has_format(t, data, name, typ):
    """Does this build open a plain archive of this kind (formats merged from other components)?"""
    p = write(t.path("probe_" + name), data)
    r, rows, out = t.extract(p)
    return ("type=%s " % typ) in r.stderr.decode(errors="replace")

def make_7z(t, files, name):
    src = t.write_tree(t.path("src7_" + name), files)
    arc = t.path(name + ".7z")
    if os.path.exists(arc):
        os.remove(arc)
    t.sh(["7z", "a", "-mx=5", arc, "."], cwd=src)
    return open(arc, "rb").read()

def make_zip(files):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in files.items():
            z.writestr(k, v)
    return b.getvalue()

def make_tar(files):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for k, v in files.items():
            ti = tarfile.TarInfo(k)
            ti.size = len(v)
            tf.addfile(ti, io.BytesIO(v))
    return b.getvalue()

def check_sfx(t, drv, stub, label, payload, kind, files, have):
    """stub + archive: opens as the archive when this build has the format, else the stub's
    reader shows the payload as [overlay]<ext> (exact bytes) that opens in place."""
    p = write(t.path("sfx_%s_%s" % (label, kind)), stub + payload)
    typ, mine = gzt_rows(t, p)
    want = {"7z": "7z", "zip": "ZIP", "rar": "RAR", "cab": "CAB"}.get(kind)
    if have:
        # a current RAR makes RAR5 archives; the legacy reader names itself "RAR"
        ok = (typ == want or (kind == "rar" and typ in ("RAR", "RAR5"))) and \
            all(mine.get(k, (0, None))[1] == v for k, v in files.items())
        t.record(ok, "SFX %s + %s opens as %s" % (label, kind, want), "type=%s %d entries" % (typ, len(mine)))
    else:
        ov = [k for k in mine if k.startswith("[overlay]")]
        ok = typ in ("PE", "ELF") and len(ov) == 1 and mine[ov[0]][1] == payload
        t.record(ok, "SFX %s + %s: %s not built, payload as overlay" % (label, kind, want),
                 "type=%s overlay=%s" % (typ, ov))

def test_sfx(t, drv, exes):
    files = {"readme.txt": b"SFX payload\n" * 30, "dir/data.bin": bytes(random.Random(5).getrandbits(8) for _ in range(5000))}
    have7 = has_format(t, make_7z(t, files, "plain"), "plain.7z", "7z")
    stubs = []
    if exes:
        stubs.append(("mingw", open(exes[sorted(exes)[0]], "rb").read()))
    stubs.append(("pywriter", pe_image([(".text", b"\xc3" * 100, 0x60000020)],
                                       rsrc=[(3, 1, 1033, dib(16, 16, 4)), (16, 1, 1033, b"\0" * 8)])))
    for label, stub in stubs:
        z = make_zip(files)
        check_sfx(t, drv, stub, label, z, "zip", files, True)
        check_sfx(t, drv, stub, label, make_7z(t, files, "sfx_" + label), "7z", files, have7)
        # payloads no archive probe claims at the top: shown as overlay, opened in place
        p = write(t.path("sfx_%s_tar" % label), stub + make_tar(files))
        typ, mine = gzt_rows(t, p)
        t.record(typ == "PE" and "[overlay]" in mine, "PE + tar lists [overlay]", "type=%s" % typ)
        child(t, drv, p, "[overlay]", "tar overlay of " + label, "TAR", files)
        p = write(t.path("sfx_%s_gz" % label), stub + gzip.compress(b"gzip payload " * 100, mtime=0))
        child(t, drv, p, "[overlay].gz", "gz overlay of " + label, "GZIP", {None: b"gzip payload " * 100})
        if t.tool("gcab"):
            src = t.write_tree(t.path("cabsrc"), {"a.txt": b"cab file a\n" * 40, "b.txt": b"bbb"})
            cab = t.path("pay.cab")
            if os.path.exists(cab):
                os.remove(cab)
            t.sh(["gcab", "-c", "-z", cab, "a.txt", "b.txt"], cwd=src)
            check_sfx(t, drv, stub, label, open(cab, "rb").read(), "cab", {"a.txt": b"cab file a\n" * 40}, True)
    if t.tool("rar"):
        src = t.write_tree(t.path("rarsrc"), files)
        rp = t.path("pay.rar")
        if os.path.exists(rp):
            os.remove(rp)
        t.sh(["rar", "a", "-r", rp, "."], cwd=src)
        rdata = open(rp, "rb").read()
        haver = has_format(t, rdata, "plain.rar", "RAR") or has_format(t, rdata, "plain5.rar", "RAR5")
        check_sfx(t, drv, stubs[0][1], stubs[0][0], rdata, "rar", files, haver)
    # 7-Zip's console SFX for Linux (an ELF stub) built by 7z itself
    for mod in ("/usr/lib/7zip/7zCon.sfx", "/usr/lib/p7zip/7zCon.sfx"):
        if not os.path.exists(mod):
            continue
        src = t.write_tree(t.path("src_elfsfx"), files)
        out = t.path("elfsfx.bin")
        if os.path.exists(out):
            os.remove(out)
        t.sh(["7z", "a", "-sfx" + mod, out, "."], cwd=src)
        data = open(out, "rb").read()
        stub_len = os.path.getsize(mod)
        check_sfx(t, drv, data[:stub_len], "7zCon.sfx", data[stub_len:], "7z", files, have7)
        p = write(t.path("elf_tar"), data[:stub_len] + make_tar(files))
        child(t, drv, p, "[overlay]", "tar overlay of an ELF stub", "TAR", files)
        break
    # a real Windows SFX stub: 7zS2con.sfx from the LZMA SDK (download, skipped offline)
    sdk = t.path("dl", "lzma2301.7z")
    if not os.path.exists(sdk):
        subprocess.run(["curl", "-sSfL", "-m", "60", "-o", sdk + ".part", "https://www.7-zip.org/a/lzma2301.7z"],
                       capture_output=True, timeout=90)
        if os.path.exists(sdk + ".part") and os.path.getsize(sdk + ".part") > 100000:
            os.rename(sdk + ".part", sdk)
    if os.path.exists(sdk):
        bd = t.path("sdk")
        shutil.rmtree(bd, ignore_errors=True)
        t.sh(["7z", "e", "-y", "-o" + bd, sdk, "bin/7zS2con.sfx", "bin/7zSD.sfx"])
        for m in ("7zS2con.sfx", "7zSD.sfx"):
            stub = open(os.path.join(bd, m), "rb").read()
            typ, mine = gzt_rows(t, os.path.join(bd, m))
            rc, ref = seven_tree(t, os.path.join(bd, m), "PE")
            probs = compare_pe_7z(ref, mine)
            t.record(typ == "PE" and not probs and any(k.endswith(".ico") for k in mine),
                     "LZMA SDK %s vs 7-Zip" % m, "; ".join(probs[:3]))
            check_sfx(t, drv, stub, m, make_7z(t, files, "sdk"), "7z", files, have7)
    else:
        t.record(True, "LZMA SDK SFX stubs", "skipped: offline")

def test_signature(t, exes):
    if not (exes and t.tool("osslsigncode") and t.tool("openssl")):
        t.record(True, "Authenticode", "skipped: osslsigncode/openssl/MinGW missing")
        return
    d = t.path("sign", "x")[:-2]
    key, crt = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
    if not os.path.exists(crt):
        t.sh(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "3650",
              "-subj", "/CN=GogitZIP test"])
    exe = exes[sorted(exes)[0]]
    payload = b"INSTALLER-PAYLOAD" * 200
    for label, src in (("plain", open(exe, "rb").read()), ("payload", open(exe, "rb").read() + payload)):
        unsigned = write(os.path.join(d, "u_%s.exe" % label), src)
        signed = os.path.join(d, "s_%s.exe" % label)
        sig = os.path.join(d, "sig_%s.der" % label)
        for p in (signed, sig):
            if os.path.exists(p):
                os.remove(p)
        t.sh(["osslsigncode", "sign", "-certs", crt, "-key", key, "-in", unsigned, "-out", signed])
        t.sh(["osslsigncode", "extract-signature", "-in", signed, "-out", sig])
        typ, mine = gzt_rows(t, signed)
        want = open(sig, "rb").read()
        ok = mine.get("[certificate].p7b", (0, None))[1] == want
        if label == "payload":
            ok = ok and mine.get("[overlay]", (0, None))[1] == payload
        else:
            ok = ok and not any(k.startswith("[overlay") for k in mine)
        t.record(ok, "Authenticode %s" % label, "type=%s %s" % (typ, sorted(k for k in mine if k.startswith("["))))
    # a signed ZIP SFX: the signature follows the archive and the file still opens as ZIP
    files = {"signed/a.txt": b"signed sfx " * 100, "b.txt": b"b"}
    unsigned = write(os.path.join(d, "u_sfx.exe"), open(exe, "rb").read() + make_zip(files))
    signed = os.path.join(d, "s_sfx.exe")
    if os.path.exists(signed):
        os.remove(signed)
    t.sh(["osslsigncode", "sign", "-certs", crt, "-key", key, "-in", unsigned, "-out", signed])
    t.check_extract(signed, files, label="signed ZIP SFX opens as ZIP", expect_type="ZIP")

def test_upx(t, exes):
    """UPX keeps the main icon group, the version and the manifest uncompressed; the rest of the
    resource directory points into the packed (virtual) section and is left out."""
    if not (exes and t.tool("upx")):
        t.record(True, "UPX", "skipped: upx or MinGW missing")
        return
    src = open(exes["app32.exe"], "rb").read() if "app32.exe" in exes else None
    if src is None:
        return
    p = write(t.path("upx32.exe"), src)
    r = t.sh(["upx", "-q", "-f", p], check=False)
    if r.returncode:
        t.record(True, "UPX", "skipped: upx failed")
        return
    typ, mine = gzt_rows(t, p)
    ok = typ == "PE" and "UPX1" in mine and any(k.startswith(".rsrc/GROUP_ICON/") and k.endswith(".ico") for k in mine)
    ok = ok and all(st == 0 for st, data in mine.values())
    t.record(ok, "UPX-packed executable", str(sorted(mine)))

def te_from_pe(pe):
    lf = struct.unpack_from("<I", pe, 0x3C)[0]
    mach, ns = struct.unpack_from("<HH", pe, lf + 4)
    optsz = struct.unpack_from("<H", pe, lf + 20)[0]
    opt = lf + 24
    entry, boc = struct.unpack_from("<II", pe, opt + 16)
    base = struct.unpack_from("<I", pe, opt + 28)[0]
    stripped = lf + 24 + optsz
    hdr = struct.pack("<2sHBBHIIQIIII", b"VZ", mach, ns, 10, stripped, entry, boc, base, 0, 0, 0, 0)
    return hdr + pe[stripped:]

def test_te(t, drv, exes):
    srcs = [("pywriter", pe_image([(".text", b"\x90" * 3000, 0x60000020), (".data", b"D" * 700, 0xC0000040)]))]
    if exes:
        srcs.append(("mingw", open(exes[sorted(exes)[0]], "rb").read()))
    for label, pe in srcs:
        te = write(t.path("te_%s.efi" % label), te_from_pe(pe) + b"TE-OVERLAY" * 10)
        typ, mine = gzt_rows(t, te)
        # (the unstripped MinGW file keeps its COFF symbols, which TE cannot point at)
        ok = typ == "TE" and (mine.get("[overlay]", (0, None))[1] or b"").endswith(b"TE-OVERLAY" * 10)
        rc, ref = seven_tree(t, te, "TE")
        if label == "pywriter":
            ok = ok and rc == 0 and len(ref) == 2               # 7-Zip reads this one
        if rc == 0 and ref:
            secs = {k: v for k, v in ref.items()}
            bad = [k for k, v in secs.items() if not any(m[1] == v for m in mine.values())]
            ok = ok and not bad
        t.record(ok, "TE image from %s" % label, "type=%s %s" % (typ, sorted(mine)[:8]))
        check_views(t, drv, te, "TE " + label)

def elf32_be():
    """A tiny big-endian 32-bit ELF (PowerPC) with two sections and an overlay."""
    text, data = b"\x4e\x80\x00\x20" * 8, b"big-endian data"
    shstr = b"\0.text\0.data\0.shstrtab\0.bss\0"
    off_text, off_data = 52, 52 + len(text)
    off_str = off_data + len(data)
    shoff = (off_str + len(shstr) + 3) & ~3
    def sh(name, typ, flags, off, size):
        return struct.pack(">IIIIIIIIII", name, typ, flags, 0, off, size, 0, 0, 1, 0)
    secs = (sh(0, 0, 0, 0, 0) + sh(1, 1, 6, off_text, len(text)) + sh(7, 1, 3, off_data, len(data)) +
            sh(13, 3, 0, off_str, len(shstr)) + sh(23, 8, 3, off_str, 4096))
    hdr = b"\x7fELF\x01\x02\x01" + bytes(9) + struct.pack(">HHIIIIIHHHHHH", 1, 20, 1, 0, 0, shoff, 0, 52, 0, 0, 40, 5, 3)
    body = hdr + text + data + shstr
    body += bytes(shoff - len(body)) + secs
    return body, {".text": text, ".data": data, ".shstrtab": shstr, ".bss": b""}

def test_elf(t, drv):
    cands = []
    for p in ("/usr/bin/ls", "/bin/ls", "/usr/lib/x86_64-linux-gnu/libz.so.1", "/usr/lib/7zip/7z.so"):
        if os.path.exists(p) and os.path.realpath(p) not in map(os.path.realpath, cands):
            cands.append(p)
    for p in cands[:3]:
        typ, mine = gzt_rows(t, p)
        rc, ref = seven_tree(t, p, "ELF")
        ref.pop("NULL", None)
        bad = [k for k, v in ref.items() if mine.get(k, (0, None))[1] != v]
        t.record(typ == "ELF" and rc == 0 and not bad, "ELF %s vs 7-Zip" % os.path.basename(p),
                 "%d sections, bad %s" % (len(ref), bad[:4]))
    if cands:
        check_views(t, drv, cands[0], "ELF " + os.path.basename(cands[0]))
    be, exp = elf32_be()
    p = write(t.path("be32.elf"), be + b"OVERLAY!" * 4)
    exp["[overlay]"] = b"OVERLAY!" * 4
    t.check_extract(p, exp, label="ELF 32-bit big-endian + overlay", expect_type="ELF")
    # program headers only (section header table removed): segments are listed
    if cands:
        d = bytearray(open(cands[0], "rb").read())
        if d[4] == 2:
            d[40:48] = bytes(8)                                  # e_shoff
            d[58:64] = bytes(6)                                  # e_shentsize, e_shnum, e_shstrndx
            p = write(t.path("noshdr.elf"), bytes(d))
            typ, mine = gzt_rows(t, p)
            t.record(typ == "ELF" and any(k.startswith("segment") and k.endswith("_LOAD") for k in mine),
                     "ELF without section headers lists segments", str(sorted(mine)[:5]))
    for cc, label in (("aarch64-linux-gnu-gcc", "aarch64"),):
        if t.tool(cc):
            src = write(t.path("a64.c"), b"int g = 7; const char s[] = \"elf string\"; int f(int x) { return x * g; }\n")
            o = t.path("a64.o")
            t.sh([cc, "-O2", "-c", src, "-o", o])
            typ, mine = gzt_rows(t, o)
            rc, ref = seven_tree(t, o, "ELF")
            ref.pop("NULL", None)
            bad = [k for k, v in ref.items() if mine.get(k, (0, None))[1] != v]
            t.record(typ == "ELF" and not bad and ".rodata" in "".join(mine), "ELF %s object vs 7-Zip" % label, str(bad[:4]))

def macho_be32():
    """A 32-bit big-endian (PowerPC) Mach-O with one segment, two sections and a zero-fill one."""
    text, cstr = b"\x60\x00\x00\x00" * 6, b"hello ppc\0"
    ncmds, segsz = 1, 56 + 68 * 3
    off_text = 28 + segsz
    off_cstr = off_text + len(text)
    def sect(name, seg, size, off, flags):
        return struct.pack(">16s16sIIIIIIIII", name, seg, 0, size, off, 2, 0, 0, flags, 0, 0)
    seg = struct.pack(">II16sIIIIIIII", 1, segsz, b"__TEXT", 0, 0x2000, 0, off_cstr + len(cstr), 7, 5, 3, 0)
    seg += sect(b"__text", b"__TEXT", len(text), off_text, 0x80000400)
    seg += sect(b"__cstring", b"__TEXT", len(cstr), off_cstr, 2)
    seg += sect(b"__bss", b"__DATA", 4096, 0, 1)
    hdr = struct.pack(">IIIIIII", 0xFEEDFACE, 18, 0, 2, ncmds, segsz, 0)
    return hdr + seg + text + cstr, {"__TEXT/__text": text, "__TEXT/__cstring": cstr, "__DATA/__bss": b""}

def test_macho(t, drv):
    be, exp = macho_be32()
    p = write(t.path("ppc.macho"), be + b"tail" * 5)
    exp["[overlay]"] = b"tail" * 5
    t.check_extract(p, exp, label="Mach-O 32-bit big-endian + overlay", expect_type="Mach-O")
    # Java class files share 0xCAFEBABE
    cls = write(t.path("Hello.class"), b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + bytes(300))
    r, rows, out = t.extract(cls)
    t.record("type=Mach-O" not in r.stderr.decode(errors="replace"), "Java class is not a universal binary")
    thin = {}
    if t.tool("clang") and (t.tool("ld64.lld") or t.tool("ld64.lld-18")):
        src = write(t.path("m.c"), b"int g = 5; const char *s = \"hello\"; int f(int x) { return x * g; }\n")
        for arch, tgt in (("arm64", "arm64-apple-macos11"), ("x86_64", "x86_64-apple-macos10.13")):
            out = t.path("m_%s.dylib" % arch)
            r = t.sh(["clang", "--target=" + tgt, "-fuse-ld=lld", "-shared", "-nostdlib", "-o", out, src,
                      "-Wl,-undefined,dynamic_lookup"], check=False)
            if r.returncode == 0:
                thin[arch] = open(out, "rb").read()
    if not thin:
        # hand-made thin files so the universal reader is still covered
        thin = {"ppc": be}
    for arch, data in sorted(thin.items()):
        if arch == "ppc":
            continue
        pth = t.path("m_%s.dylib" % arch)
        typ, mine = gzt_rows(t, pth)
        rc, ref = seven_tree(t, pth, "MachO")
        names = {k.replace("/", ""): v for k, v in mine.items()}
        bad = [k for k, v in ref.items() if names.get(k, (0, None))[1] != v]
        t.record(typ == "Mach-O" and rc == 0 and not bad and ref, "Mach-O %s dylib vs 7-Zip" % arch, str(bad[:4]))
    # universal: 32-bit fat header, 4 KiB aligned slices (as lipo writes)
    cpus = {"arm64": (0x0100000C, 0), "x86_64": (0x01000007, 3), "ppc": (18, 0)}
    archs = sorted(thin)
    hdr = struct.pack(">II", 0xCAFEBABE, len(archs))
    off, body, ents = 4096, b"", b""
    for a in archs:
        ents += struct.pack(">IIIII", cpus[a][0], cpus[a][1], off + len(body), len(thin[a]), 12)
        body += thin[a] + bytes((-len(thin[a])) % 4096)
    fat = hdr + ents
    fat += bytes(4096 - len(fat)) + body
    p = write(t.path("fat.bin"), fat)
    t.check_extract(p, {a: thin[a] for a in archs}, label="universal binary (%s)" % ",".join(archs),
                    expect_type="Mach-O Universal")
    check_views(t, drv, p, "universal")
    child(t, drv, p, archs[0], "thin slice of a universal binary", "Mach-O", {})
    # FAT_MAGIC_64
    hdr = struct.pack(">II", 0xCAFEBABF, len(archs))
    ents = b""
    pos = 4096
    for a in archs:
        ents += struct.pack(">IIQQII", cpus[a][0], cpus[a][1], pos, len(thin[a]), 12, 0)
        pos += len(thin[a]) + (-len(thin[a])) % 4096
    fat64 = hdr + ents
    fat64 += bytes(4096 - len(fat64)) + body
    p = write(t.path("fat64.bin"), fat64)
    t.check_extract(p, {a: thin[a] for a in archs}, label="universal binary, 64-bit header", expect_type="Mach-O Universal")
    if t.tool("llvm-lipo") or t.tool("llvm-lipo-18"):
        lipo = t.tool("llvm-lipo") or t.tool("llvm-lipo-18")
        ins = [t.path("m_%s.dylib" % a) for a in archs if a != "ppc"]
        if len(ins) >= 2:
            out = t.path("lipo.dylib")
            if os.path.exists(out):
                os.remove(out)
            t.sh([lipo, "-create"] + ins + ["-output", out])
            t.check_extract(out, {a: thin[a] for a in archs if a != "ppc"}, label="llvm-lipo universal dylib",
                            expect_type="Mach-O Universal")

# ---------------------------------------------------------------- hostile

def test_hostile(t, drv, exes):
    ico = dib(16, 16, 4)
    good = pe_image([(".text", b"\xc3" * 64, 0x60000020)],
                    rsrc=[(3, 1, 1033, ico), (14, 1, 1033, struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHIH", 16, 16, 16, 0, 1, 4, len(ico), 1)),
                          (6, 1, 1033, string_block({0: "zero", 5: "five"})), (10, "DATA", 0, b"rcdata"),
                          (2, 7, 1033, dib(8, 8, 24, False))])
    p = write(t.path("py.exe"), good)
    t.check_extract(p, {".rsrc/ICON/1.ico": struct.pack("<HHHBBBBHHII", 0, 1, 1, 16, 16, 16, 0, 0, 0, 40 + 64 + 128 + 64, 22) + ico,
                        ".rsrc/GROUP_ICON/1.ico": struct.pack("<HHHBBBBHHII", 0, 1, 1, 16, 16, 16, 0, 1, 4, len(ico), 22) + ico,
                        ".rsrc/STRING.txt": BOM + b"0\tzero\r\n5\tfive\r\n", ".rsrc/RCDATA/DATA": b"rcdata",
                        ".rsrc/BITMAP/7.bmp": b"BM" + struct.pack("<IHHI", 14 + 40 + 8 * 24 // 8 * 8, 0, 0, 54) + dib(8, 8, 24, False),
                        ".text": b"\xc3" * 64 + bytes(512 - 64)},
                    label="Python-built PE", expect_type="PE")
    rs_off = sect_off(good, ".rsrc")
    cases = {}
    d = bytearray(good)
    struct.pack_into("<I", d, rs_off + 16 + 4, 0x80000000)             # type -> root (cycle)
    cases["rsrc cycle"] = bytes(d)
    d = bytearray(good)
    struct.pack_into("<HH", d, rs_off + 12, 0xFFFF, 0xFFFF)            # 131070 root entries
    cases["rsrc huge count"] = bytes(d)
    d = bytearray(good)
    for i in range(5):                                                  # all types share one subtree
        struct.pack_into("<I", d, rs_off + 16 + 8 * i + 4, struct.unpack_from("<I", d, rs_off + 16 + 4)[0])
    cases["rsrc shared subtree"] = bytes(d)
    d = bytearray(good)
    struct.pack_into("<I", d, 0x3C, 0xFFFFFFF0)
    cases["e_lfanew"] = bytes(d)
    cases["65535 sections"] = pe_image([(".text", b"x" * 10, 0x60000020)], nsec_override=0xFFFF)
    # 2000 sections that all map the whole file: without the byte budget ~2 GB would be listed
    over = bytearray(pe_image([(".s%d" % i, b"O" * 16, 0x40000040) for i in range(2000)]))
    for i in range(2000):
        struct.pack_into("<II", over, 0x80 + 24 + 224 + 40 * i + 16, len(over), 0)
    cases["overlapping sections"] = bytes(over)
    # three languages whose entries all point at the first one's data entry: listed once
    sh = bytearray(pe_image([(".text", b"x", 0x60000020)], rsrc=[(10, 1, lg, b"shared %d" % lg) for lg in (1, 2, 3)]))
    ro = sect_off(sh, ".rsrc")
    lang_dir = ro + 2 * (16 + 8)                                        # root, type dir, then the name dir
    first = struct.unpack_from("<I", sh, lang_dir + 16 + 4)[0]
    for j in (1, 2):
        struct.pack_into("<I", sh, lang_dir + 16 + 8 * j + 4, first)
    cases["shared data entry"] = bytes(sh)
    # group icon pointing at missing / huge images, string block with bad lengths, version garbage
    cases["bad group"] = pe_image([(".text", b"x", 0x60000020)], rsrc=[
        (14, 1, 0, struct.pack("<HHH", 0, 1, 3) + struct.pack("<BBBBHHIH", 1, 1, 0, 0, 1, 1, 0xFFFFFFFF, 9) * 3),
        (12, 2, 0, struct.pack("<HHH", 0, 2, 0xFFFF)), (1, 3, 0, b"\1\0"),
        (6, 1, 0, b"\xff\xff" + b"A" * 30), (16, 1, 0, struct.pack("<HHH", 0xFFFF, 52, 0) + b"V\0S\0" * 40),
        (2, 1, 0, struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 8, 0, 0, 0, 0, 0xFFFFFFFF, 0))])
    for name, data in cases.items():
        p = write(t.path("hostile_%s.exe" % name.replace(" ", "_")), data)
        t.check_hostile(p, label="hostile PE: " + name)
    typ, mine = gzt_rows(t, t.path("hostile_shared_data_entry.exe"))
    t.record(typ == "PE" and mine.get(".rsrc/RCDATA/1", (0, None))[1] == b"shared 1" and
             not any("RCDATA/1/" in k for k in mine), "data entry shared by three languages listed once", str(sorted(mine)))
    typ, mine = gzt_rows(t, t.path("hostile_bad_group.exe"))
    t.record(typ == "PE" and ".rsrc/GROUP_ICON/1" in mine and ".rsrc/STRING/1" in mine and ".rsrc/VERSION/1" in mine
             and ".rsrc/VERSION/1.txt" not in mine and ".rsrc/BITMAP/1" in mine,
             "broken group/string/version/bitmap fall back to raw", str(sorted(mine)))
    r, rows, out = t.extract(t.path("hostile_overlapping_sections.exe"))
    total = sum(v[2] for v in rows.values())
    t.record(r.returncode in (0, 1) and 60 <= len(rows) < 2000 and total <= 4 * len(over) + (64 << 20),
             "overlapping sections stay within the byte budget", "%d bytes in %d entries" % (total, len(rows)))
    # truncations of a real executable
    srcs = [p] + ([exes[k] for k in sorted(exes)] if exes else [])
    base = open(srcs[-1], "rb").read()
    for n in (64, 200, 0x200, 0x400, len(base) // 3, len(base) // 2, len(base) - 1):
        p = write(t.path("trunc_%d.exe" % n), base[:n])
        t.check_hostile(p, label="truncated PE at %d" % n)
    # in-process fuzzing: bit flips, special values, truncation (heavier under sanitizers)
    asan = "sanitize" in os.environ.get("HOST_CFLAGS", "")
    targets = [("python PE", t.path("py.exe"))] + [("windres " + k, v) for k, v in sorted((exes or {}).items())]
    for nm in ("be32.elf", "ppc.macho", "fat.bin", "te_pywriter.efi"):
        if os.path.exists(t.path(nm)):
            targets.append((nm, t.path(nm)))
    for f in wine_files():
        if os.path.basename(f) in ("notepad.exe",):
            targets.append(("wine " + os.path.basename(os.path.dirname(f)), f))
    for i, (label, path) in enumerate(targets):
        iters = 400 if asan and os.path.getsize(path) > 200000 else 1500 if asan else 3000
        r = t.sh([drv, "fuzz", path, str(iters), str(17 + i)], check=False, timeout=1200)
        out = r.stdout.decode(errors="replace").strip()
        err = r.stderr.decode(errors="replace")
        t.record(r.returncode == 0 and "FUZZ" in out and "Sanitizer" not in err and "runtime error" not in err,
                 "fuzz %s" % label, out[-200:] + err[-300:])

def test_gogitzip(t, drv):
    exe = os.path.join(os.path.dirname(t.gzt), "GogitZip.exe")
    if not os.path.exists(exe):
        t.record(True, "GogitZip.exe", "skipped: run make win first")
        return
    typ, mine = gzt_rows(t, exe)
    rc, ref = seven_tree(t, exe, "PE")
    probs = compare_pe_7z(ref, mine)
    t.record(typ == "PE" and not probs and any(k.endswith(".manifest") for k in mine) and
             any(k.startswith(".rsrc/GROUP_ICON/") for k in mine), "GogitZip.exe resources vs 7-Zip", "; ".join(probs[:3]))
    check_views(t, drv, exe, "GogitZip.exe")

def run(t):
    t.need("7z")
    drv = t.build_driver("tests/drivers/exe_check.c")
    exes = test_windres(t, drv)
    test_wine(t, drv)
    test_sfx(t, drv, exes)
    test_signature(t, exes)
    test_upx(t, exes)
    test_te(t, drv, exes)
    test_elf(t, drv)
    test_macho(t, drv)
    test_gogitzip(t, drv)
    test_hostile(t, drv, exes)
