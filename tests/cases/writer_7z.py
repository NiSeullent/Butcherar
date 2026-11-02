"""
7z writer (src/fmt/sevenz_write.c).

Archives are made with `gzt c 7z` (files on disk) and with tests/drivers/writer_7z.c
(symbolic links, 100 ns times, CTime/ATime, attributes, generated multi-GB inputs,
failing / shrinking / growing inputs, cancellation, sinks without write_at). Each one
is checked with 7-Zip (`7z t`, `7z x` + tree comparison), its header is decoded by an
independent parser below (structure, coders, filters, attributes, times; the AES
layer is decrypted with pycryptodome when present), and a subset goes through other
readers (libarchive's bsdtar, py7zr, unar) and through our own reader once a 7z
reader is registered. A table compares the sizes with `7z a` at the same settings.
"""
import os, struct, zlib, lzma, shutil, subprocess, random, hashlib, time
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
WINE64 = "/usr/lib/x86_64-linux-gnu/wine/x86_64-windows"
WINE32 = "/usr/lib/i386-linux-gnu/wine/i386-windows"
ARM64LIB = "/usr/aarch64-linux-gnu/lib"

M_DEFAULT, M_STORE, M_DEFLATE, M_DEFLATE64, M_BZIP2, M_LZMA, M_LZMA2, M_PPMD = range(8)
MNAME = {M_DEFAULT: "LZMA2", M_STORE: "Copy", M_DEFLATE: "Deflate", M_BZIP2: "BZip2",
         M_LZMA: "LZMA", M_LZMA2: "LZMA2", M_PPMD: "PPMd"}
CODER = {"00": "Copy", "21": "LZMA2", "030101": "LZMA", "030401": "PPMd", "040202": "BZip2",
         "040108": "Deflate", "03030103": "BCJ", "0a": "ARM64", "06f10701": "7zAES"}

# ---------------------------------------------------------------- 7z header parser

class Bad(Exception):
    pass

def kdf_7z(pw, power):
    data = pw.encode("utf-16-le")
    h = hashlib.sha256()
    chunk = []
    for i in range(1 << power):
        chunk.append(data + struct.pack("<Q", i))
        if len(chunk) == 4096:
            h.update(b"".join(chunk)); chunk = []
    h.update(b"".join(chunk))
    return h.digest()

class R:
    def __init__(s, b, p=0):
        s.b, s.p = b, p
    def byte(s):
        if s.p >= len(s.b): raise Bad("short header")
        v = s.b[s.p]; s.p += 1; return v
    def take(s, n):
        if s.p + n > len(s.b): raise Bad("short header")
        v = s.b[s.p:s.p + n]; s.p += n; return v
    def num(s):
        first = s.byte(); mask = 0x80; v = 0
        for i in range(8):
            if not first & mask:
                return v | ((first & (mask - 1)) << (8 * i))
            v |= s.byte() << (8 * i); mask >>= 1
        return v
    def u32(s): return struct.unpack("<I", s.take(4))[0]
    def u64(s): return struct.unpack("<Q", s.take(8))[0]
    def bits(s, n):
        out, m, v = [], 0, 0
        for _ in range(n):
            if not m: v, m = s.byte(), 0x80
            out.append(bool(v & m)); m >>= 1
        return out
    def defbits(s, n):
        return [True] * n if s.byte() else s.bits(n)

def read_streams(r):
    si = {"folders": [], "packsizes": [], "packpos": 0}
    while True:
        t = r.byte()
        if t == 0:
            return si
        if t == 6:
            si["packpos"] = r.num(); n = r.num()
            while True:
                t2 = r.byte()
                if t2 == 0: break
                if t2 == 9: si["packsizes"] = [r.num() for _ in range(n)]
                elif t2 == 10:
                    d = r.defbits(n); si["packcrc"] = [r.u32() if x else None for x in d]
                else: raise Bad("packinfo %d" % t2)
        elif t == 7:
            if r.byte() != 11: raise Bad("no kFolder")
            nf = r.num()
            if r.byte(): raise Bad("external")
            for _ in range(nf):
                coders, tin, tout = [], 0, 0
                for _ in range(r.num()):
                    f = r.byte()
                    cid = r.take(f & 15).hex()
                    ni = no = 1
                    if f & 0x10: ni, no = r.num(), r.num()
                    props = r.take(r.num()) if f & 0x20 else b""
                    coders.append((cid, ni, no, props)); tin += ni; tout += no
                bonds = [(r.num(), r.num()) for _ in range(tout - 1)]
                npk = tin - (tout - 1)
                pk = [r.num() for _ in range(npk)] if npk > 1 else None
                si["folders"].append(dict(coders=coders, bonds=bonds, packidx=pk, tout=tout))
            if r.byte() != 12: raise Bad("no unpack sizes")
            for f in si["folders"]:
                f["usizes"] = [r.num() for _ in range(f["tout"])]
                bound = {o for _, o in f["bonds"]}
                f["usize"] = [f["usizes"][i] for i in range(f["tout"]) if i not in bound][0]
                f["crc"] = None
            t2 = r.byte()
            if t2 == 10:
                d = r.defbits(nf)
                for f, x in zip(si["folders"], d):
                    f["crc"] = r.u32() if x else None
                t2 = r.byte()
            if t2: raise Bad("unpackinfo end")
        elif t == 8:
            fs = si["folders"]; nus = [1] * len(fs)
            t2 = r.byte()
            if t2 == 13:
                nus = [r.num() for _ in fs]; t2 = r.byte()
            sizes = []
            for f, k in zip(fs, nus):
                f["nsub"] = k
            if t2 == 9:
                for f, k in zip(fs, nus):
                    s = 0
                    for _ in range(k - 1):
                        v = r.num(); sizes.append(v); s += v
                    if k: sizes.append(f["usize"] - s)
                t2 = r.byte()
            else:
                sizes = [f["usize"] for f, k in zip(fs, nus) if k]
            crcs = []
            if t2 == 10:
                nd = sum(k for f, k in zip(fs, nus) if not (k == 1 and f["crc"] is not None))
                d = r.defbits(nd); vals = [r.u32() if x else None for x in d]; t2 = r.byte()
                it = iter(vals)
                for f, k in zip(fs, nus):
                    if k == 1 and f["crc"] is not None: crcs.append(f["crc"])
                    else: crcs += [next(it) for _ in range(k)]
            if t2: raise Bad("substreams end")
            si["subsizes"], si["subcrcs"] = sizes, crcs
        else:
            raise Bad("streams id %d" % t)

def decode_folder(data, base, si, k, password):
    """unpack folder k (coders: [7zAES] LZMA) - enough for the encoded header"""
    f = si["folders"][k]
    pos = base + 32 + si["packpos"] + sum(si["packsizes"][:k])
    buf = data[pos:pos + si["packsizes"][k]]
    for idx, (cid, ni, no, props) in enumerate(f["coders"]):
        if cid == "06f10701":
            if password is None: raise Bad("encrypted header")
            from Cryptodome.Cipher import AES
            b0 = props[0]; power = b0 & 0x3F
            b1 = props[1]; salt = ((b0 >> 7) & 1) + (b1 >> 4); ivn = ((b0 >> 6) & 1) + (b1 & 15)
            iv = props[2 + salt:2 + salt + ivn].ljust(16, b"\0")
            key = kdf_7z(password, power)
            buf = AES.new(key, AES.MODE_CBC, iv).decrypt(buf)[:f["usizes"][idx]]
        elif cid == "030101":
            d = props[0]; lc = d % 9; d //= 9; lp = d % 5; pb = d // 5
            dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1,
                  "dict_size": struct.unpack("<I", props[1:5])[0], "lc": lc, "lp": lp, "pb": pb}])
            buf = dec.decompress(buf, f["usizes"][idx])
        else:
            raise Bad("header coder %s" % cid)
    if f["crc"] is not None and zlib.crc32(buf) != f["crc"]:
        raise Bad("header CRC")
    return buf

def parse_7z(path, password=None):
    """Decode a 7z archive's directory. Returns dict(files=[...], folders=[...], encoded, hdr_coders)."""
    data = open(path, "rb").read()
    if data[:6] != b"7z\xbc\xaf\x27\x1c": raise Bad("signature")
    if zlib.crc32(data[12:32]) != struct.unpack_from("<I", data, 8)[0]: raise Bad("start header CRC")
    nho, nhs, nhcrc = struct.unpack_from("<QQI", data, 12)
    res = {"files": [], "folders": [], "encoded": False, "hdr_coders": [], "version": data[6:8],
           "size": len(data), "end": 32 + nho + nhs}
    if nhs == 0:
        return res
    h = data[32 + nho:32 + nho + nhs]
    if len(h) != nhs or zlib.crc32(h) != nhcrc: raise Bad("next header CRC")
    r = R(h); t = r.byte()
    if t == 23:
        si = read_streams(r)
        res["encoded"] = True
        res["hdr_coders"] = [CODER.get(c[0], c[0]) for c in si["folders"][0]["coders"]]
        h = decode_folder(data, 0, si, 0, password)
        r = R(h); t = r.byte()
    if t != 1: raise Bad("no header")
    si = {"folders": []}
    files = []
    while True:
        t = r.byte()
        if t == 0: break
        if t == 4:
            si = read_streams(r)
        elif t == 5:
            n = r.num()
            files = [dict(name=None, empty=False, isdir=False, attr=None, mtime=None, ctime=None,
                          atime=None) for _ in range(n)]
            empty = [False] * n; efile = []
            while True:
                pt = r.byte()
                if pt == 0: break
                size = r.num(); start = r.p; rr = R(r.take(size))
                if pt == 14:
                    empty = rr.bits(n)
                elif pt == 15:
                    efile = rr.bits(sum(empty))
                elif pt == 17:
                    if rr.byte(): raise Bad("external names")
                    names = rr.b[1:].decode("utf-16-le", "surrogatepass").split("\0")[:-1]
                    if len(names) != n: raise Bad("name count")
                    for f, nm in zip(files, names): f["name"] = nm
                elif pt in (18, 19, 20, 21):
                    d = rr.defbits(n)
                    if rr.byte(): raise Bad("external")
                    key = {18: "ctime", 19: "atime", 20: "mtime", 21: "attr"}[pt]
                    for f, x in zip(files, d):
                        if x: f[key] = rr.u32() if pt == 21 else rr.u64()
                r.p = start + size
            ei = 0
            for f, e in zip(files, empty):
                f["empty"] = e
                if e:
                    f["isdir"] = not (efile[ei] if ei < len(efile) else False); ei += 1
        else:
            raise Bad("header id %d" % t)
    # attach sizes / CRCs / folders
    sizes, crcs = si.get("subsizes", []), si.get("subcrcs", [])
    fmap = []
    for k, f in enumerate(si["folders"]):
        fmap += [k] * f.get("nsub", 1)
        f["names"] = [CODER.get(c[0], c[0]) for c in f["coders"]]
    j = 0
    for f in files:
        if f["empty"]:
            f["size"], f["crc"], f["folder"] = 0, None, None
        else:
            f["size"], f["crc"], f["folder"] = sizes[j], crcs[j] if j < len(crcs) else None, fmap[j]
            j += 1
    if j != len(sizes): raise Bad("stream count")
    for k, f in enumerate(si["folders"]):
        f["packed"] = si["packsizes"][k]
    res["files"], res["folders"] = files, si["folders"]
    res["packpos"] = si.get("packpos", 0)
    return res

# ---------------------------------------------------------------- data

def text_blob(n, seed):
    rnd = random.Random(seed)
    words = ["archive", "고깃집", "compression", "the", "of", "LZMA", "block", "파일", "이름", "solid",
             "header", "stream", "0x1F", "int", "return", "{", "}", ";", "\n", "    ", "7-Zip", "folder"]
    out = []
    size = 0
    while size < n:
        w = rnd.choice(words) + rnd.choice((" ", " ", "\n", ", "))
        out.append(w); size += len(w.encode())
    return "".join(out).encode()[:n]

def rand_blob(n, seed):
    return random.Random(seed).randbytes(n)

def copy_bin(src, dst, mode=0o644):
    if not os.path.exists(src):
        return False
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copyfile(src, dst)
    os.chmod(dst, mode)
    return True

def elf_filter(path):
    """Branch filter 7-Zip applies to an ELF file: BCJ (x86/x64), ARM64, or None."""
    try:
        with open(path, "rb") as f:
            h = f.read(20)
    except OSError:
        return None
    if h[:4] != b"\x7fELF" or len(h) < 20:
        return None
    machine = int.from_bytes(h[18:20], "little")
    return {3: "BCJ", 62: "BCJ", 183: "ARM64"}.get(machine)

def make_tree(t, name, big=False, arm=True):
    """A tree with text, binary, empty files and dirs, Korean names and executables."""
    root = t.path(name)
    shutil.rmtree(root, ignore_errors=True)
    files = {
        "readme.txt": text_blob(40000, 1),
        "docs/설명서.txt": ("한글 설명서 " * 3000).encode(),
        "docs/empty.txt": b"",
        "docs/notes.md": text_blob(5000, 2),
        "src/main.c": text_blob(30000, 3),
        "src/util.h": text_blob(3000, 4),
        "bin/random.bin": rand_blob(30000, 5),
        "bin/zeros.dat": bytes(100000),
        "nested/a/b/c.txt": b"deep file\n",
        "한글 폴더/파일 이름 (1).txt": ("가나다라마바사 " * 500).encode(),
        "bin/tiny.exe": b"MZ" + bytes(100),
        "bin/script": (b"#!/bin/sh\necho hello\n" * 200),
    }
    dirs = ["빈 폴더", "nested/a/b/empty"]
    t.write_tree(root, dict(files, **{d: None for d in dirs}))
    os.chmod(os.path.join(root, "bin/script"), 0o755)
    exe = {}
    if copy_bin(os.path.join(WINE64, "notepad.exe"), os.path.join(root, "bin/notepad64.exe")):
        exe["bin/notepad64.exe"] = "BCJ"
    if copy_bin(os.path.join(WINE64, "dplay.dll"), os.path.join(root, "bin/dplay.dll")):
        exe["bin/dplay.dll"] = "BCJ"
    if copy_bin(os.path.join(WINE64, "shfolder.dll"), os.path.join(root, "bin/pe_noext")):
        exe["bin/pe_noext"] = "BCJ"                       # PE found by its header
    # host ELF samples: x86 gets BCJ, AArch64 gets the ARM64 filter (new in 7-Zip 23; bsdtar, py7zr
    # and unar cannot read it, so the arm=False tree leaves such samples out)
    hostf = elf_filter("/bin/ls")
    if hostf and (arm or hostf == "BCJ"):
        if copy_bin("/bin/ls", os.path.join(root, "bin/ls"), 0o755):
            exe["bin/ls"] = hostf
        if copy_bin("/bin/ls", os.path.join(root, "bin/elf_noexec"), 0o644):
            exe["bin/elf_noexec"] = hostf                 # ELF without exec bit: found by header
    if arm and copy_bin(os.path.join(ARM64LIB, "libgcc_s.so.1"), os.path.join(root, "lib/libgcc_s.so.1")):
        exe["lib/libgcc_s.so.1"] = "ARM64"
    if big:
        if copy_bin(os.path.join(WINE32, "notepad.exe"), os.path.join(root, "bin/notepad32.exe")):
            exe["bin/notepad32.exe"] = "BCJ"
        if copy_bin(os.path.join(ARM64LIB, "ld-linux-aarch64.so.1"), os.path.join(root, "lib/ld-linux"), 0o755):
            exe["lib/ld-linux"] = "ARM64"
    for k in exe:
        files[k] = open(os.path.join(root, k), "rb").read()
    files["bin/script"] = open(os.path.join(root, "bin/script"), "rb").read()
    return root, files, dirs, exe

def rels_of(files, dirs):
    out = set(files)
    for d in dirs:
        out.add(d)
    for k in list(out):           # parents, like an enumeration would add them
        p = os.path.dirname(k)
        while p:
            out.add(p); p = os.path.dirname(p)
    return sorted(out)

# ---------------------------------------------------------------- checks

def sevenzip(t, args, timeout=900):
    return subprocess.run(["7z"] + args, capture_output=True, timeout=timeout)

def tree_of(root):
    files, dirs = {}, set()
    for dp, dns, fns in os.walk(root):
        for d in dns:
            p = os.path.join(dp, d)
            if not os.path.islink(p):
                dirs.add(unicodedata.normalize("NFC", os.path.relpath(p, root)))
        for fn in fns:
            p = os.path.join(dp, fn)
            rel = unicodedata.normalize("NFC", os.path.relpath(p, root))
            files[rel] = ("LINK", os.readlink(p)) if os.path.islink(p) else open(p, "rb").read()
    return files, dirs

def check_7z(t, arc, files, dirs, pw=None, label="", modes=None):
    """7z t, then 7z x and compare with {rel: bytes}; empty dirs must exist. Returns ok."""
    pwa = ["-p" + pw] if pw is not None else ["-p-"]
    r = sevenzip(t, ["t", arc] + pwa)
    if r.returncode or b"Everything is Ok" not in r.stdout:
        return t.record(False, label + " 7z t", r.stdout.decode(errors="replace")[-400:])
    out = t.path("x7_" + os.path.basename(arc))
    shutil.rmtree(out, ignore_errors=True)
    r = sevenzip(t, ["x", "-y", "-o" + out, arc] + pwa)
    if r.returncode:
        return t.record(False, label + " 7z x", r.stdout.decode(errors="replace")[-400:])
    got, gdirs = tree_of(out)
    probs = []
    for k, v in files.items():
        if k not in got: probs.append("missing " + k)
        elif got[k] != v: probs.append("data " + k)
    for k in got:
        if k not in files: probs.append("extra " + k)
    for d in dirs:
        if d not in gdirs: probs.append("dir " + d)
    for k, m in (modes or {}).items():
        p = os.path.join(out, k)
        if os.path.exists(p) and (os.lstat(p).st_mode & 0o7777) != m:
            probs.append("mode %s %o" % (k, os.lstat(p).st_mode & 0o7777))
    shutil.rmtree(out, ignore_errors=True)
    return t.record(not probs, label + " 7z t+x", "; ".join(probs[:6]))

def gzt_c(t, arc, level, src, rels, pw=None, method=None, solid=None, encnames=False):
    if os.path.exists(arc):
        os.remove(arc)
    # gzt c itself does not free its item list: leak checks are done through the driver
    env = {"ASAN_OPTIONS": (os.environ.get("ASAN_OPTIONS", "") + ":detect_leaks=0").lstrip(":")}
    if method is not None: env["GZ_METHOD"] = str(method)
    if solid is not None: env["GZ_SOLID"] = str(solid)
    if encnames: env["GZ_ENC_NAMES"] = "1"
    r = t.run_gzt(["c", "7z", arc, str(level), pw or "-", src] + rels, env, timeout=1800)
    return r.returncode == 0 and b"CREATE 0" in r.stdout, r

def run_driver(t, drv, name, lines, timeout=1800):
    man = t.path(name + ".man")
    arc = t.path(name + ".7z")
    if os.path.exists(arc):
        os.remove(arc)
    with open(man, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write("\t".join(str(x) for x in ln) + "\n")
    r = subprocess.run([drv, man, arc], capture_output=True, timeout=timeout)
    out = r.stdout.decode("utf-8", "replace")
    err = r.stderr.decode("utf-8", "replace")
    if r.returncode or "Sanitizer" in err or "runtime error" in err:      # leaks, UB, crashes
        t.record(False, name + ": driver exit", "rc=%d %s" % (r.returncode, err[-1500:]))
    info = {"crc": {}, "err": [], "result": None, "progress": None, "raw": out + r.stderr.decode(errors="replace")}
    for line in out.splitlines():
        p = line.split(" ", 3)
        if p[0] == "CRC": info["crc"][p[3]] = (int(p[1], 16), int(p[2]))
        elif p[0] == "ERR": info["err"].append((int(p[1]), p[2] if len(p) > 2 else ""))
        elif p[0] == "RESULT": info["result"] = int(p[1])
    pr = [l for l in out.splitlines() if l.startswith("PROGRESS")]
    if pr:
        v = pr[0].split()
        info["progress"] = (int(v[1]), int(v[2]), int(v[3]), int(v[4]))
    return arc, info

def own_reader(t):
    """Is a 7z reader registered in this build? (then gzt x is checked too)"""
    probe = t.path("probe_reader.7z")
    if not os.path.exists(probe):
        src = t.write_tree(t.path("probe_src"), {"a.txt": b"probe"})
        gzt_c(t, probe, 5, src, ["a.txt"])
    r, typ, rows = t.listing(probe)
    return r.returncode == 0 and typ is not None and typ.lower().startswith("7z")

def unix_ft(sec, frac=0):
    return sec * 10000000 + 116444736000000000 + frac

# ---------------------------------------------------------------- the tests

def run(t):
    t.need("7z")
    have_own = own_reader(t)
    drv = t.build_driver("tests/drivers/writer_7z.c")

    root, files, dirs, exe = make_tree(t, "tree")
    rels = rels_of(files, dirs)

    # ---- methods x levels x solid: 7z t + x, header structure ----
    combos = [(M_DEFAULT, lv, s) for lv in range(10) for s in (1, 0)]
    combos += [(m, lv, s) for m in (M_LZMA, M_PPMD, M_BZIP2, M_DEFLATE) for lv in (1, 5, 9) for s in (1, 0)]
    combos += [(M_STORE, 5, 1), (M_LZMA2, 0, 1)]
    for m, lv, s in combos:
        label = "%s L%d %s" % (MNAME[m], lv, "solid" if s else "non-solid")
        arc = t.path("m%d_l%d_s%d.7z" % (m, lv, s))
        ok, r = gzt_c(t, arc, lv, root, rels, method=m or None, solid=s)
        if not t.record(ok, label + " create", r.stdout.decode(errors="replace")[-200:]):
            continue
        if not check_7z(t, arc, files, dirs, label=label,
                        modes=dict({"bin/script": 0o755, "bin/zeros.dat": 0o644}, **({"bin/ls": 0o755} if "bin/ls" in files else {}))):
            continue
        try:
            a = parse_7z(arc)
        except Exception as e:
            t.record(False, label + " header", repr(e)); continue
        probs = []
        copy = m == M_STORE or (m == M_DEFAULT and lv == 0)
        want = "Copy" if copy else MNAME[m if m else M_LZMA2]
        byname = {f["name"]: f for f in a["files"]}
        for f in a["folders"]:
            main = [c for c in f["names"] if c not in ("BCJ", "ARM64", "7zAES")]
            if main != [want]: probs.append("coders %s" % f["names"])
        if len(a["files"]) != len(rels): probs.append("%d files, want %d" % (len(a["files"]), len(rels)))
        for k, v in files.items():
            f = byname.get(k)
            if not f: probs.append("no " + k); continue
            if f["size"] != len(v) or (v and f["crc"] != zlib.crc32(v)): probs.append("size/crc " + k)
            if not v and not (f["empty"] and not f["isdir"]): probs.append("empty file " + k)
        for d in dirs:
            if not byname.get(d, {}).get("isdir"): probs.append("dir " + d)
        if copy:
            if len(a["folders"]) != len([v for v in files.values() if v]): probs.append("copy: folder per file")
        for k, flt in exe.items():                      # executables get their filter, others none
            f = byname.get(k)
            if f and not copy and flt not in a["folders"][f["folder"]]["names"]:
                probs.append("%s not %s: %s" % (k, flt, a["folders"][f["folder"]]["names"]))
        for k in ("readme.txt", "bin/script", "bin/random.bin", "bin/tiny.exe"):
            f = byname.get(k)
            filt = [c for c in a["folders"][f["folder"]]["names"] if c in ("BCJ", "ARM64")]
            if k == "bin/tiny.exe":
                if not copy and filt != ["BCJ"]: probs.append("tiny.exe by name: %s" % filt)
            elif filt:
                probs.append("%s filtered %s" % (k, filt))
        if not s and len(a["folders"]) != len([v for v in files.values() if v]):
            probs.append("non-solid: %d folders" % len(a["folders"]))
        if s and not copy:
            kinds = [("ARM64" if "ARM64" in f["names"] else "BCJ" if "BCJ" in f["names"] else "plain")
                     for f in a["folders"]]
            # pe_noext / elf_noexec look like data by name: found by their header after the
            # BCJ group was written, they get a second BCJ folder
            # ARM64 samples exist with cross libs or on an ARM64 host; like BCJ, an ELF found only
            # by its header after the group was written gets a second folder
            arm_ok = (1, 2) if "ARM64" in exe.values() else (0,)
            if kinds.count("plain") != 1 or kinds.count("ARM64") not in arm_ok or kinds.count("BCJ") not in (1, 2):
                probs.append("solid folders %s" % kinds)
        if not a["encoded"] or a["hdr_coders"] != ["LZMA"]:
            probs.append("header not LZMA-encoded: %r" % a["hdr_coders"])
        attrs = {f["name"]: f["attr"] for f in a["files"]}
        if "bin/ls" in files and attrs.get("bin/ls") != (0x8000 | 0x20 | (0o100755 << 16)): probs.append("attr ls %r" % attrs.get("bin/ls"))
        if attrs.get("빈 폴더") != (0x8000 | 0x10 | (0o40755 << 16)): probs.append("attr dir %r" % attrs.get("빈 폴더"))
        t.record(not probs, label + " header", "; ".join(probs[:6]) or "%d folders, %d bytes" % (len(a["folders"]), a["size"]))

    # ---- encryption: ASCII and Korean passwords, encrypted names ----
    for pw, encn in (("secret", False), ("비밀번호 한글!", False), ("secret", True), ("암호abc", True)):
        for lv in (0, 5):
            label = "AES pw=%r L%d%s" % (pw, lv, " +names" if encn else "")
            arc = t.path("enc_%d_%d_%d.7z" % (len(pw), lv, encn))
            ok, r = gzt_c(t, arc, lv, root, rels, pw=pw, encnames=encn)
            if not t.record(ok, label + " create", r.stdout.decode(errors="replace")[-200:]):
                continue
            check_7z(t, arc, files, dirs, pw=pw, label=label)
            r = sevenzip(t, ["t", "-pwrong", arc])
            t.record(r.returncode != 0, label + " wrong password fails", "rc=%d" % r.returncode)
            r = sevenzip(t, ["l", "-p-", arc])
            listed = "readme.txt" in r.stdout.decode(errors="replace")
            if encn:
                t.record(r.returncode != 0 and not listed, label + " 7z l without password fails",
                         "rc=%d" % r.returncode)
            else:
                t.record(r.returncode == 0 and listed, label + " names listed without password", "rc=%d" % r.returncode)
            try:
                __import__("Cryptodome")
                a = parse_7z(arc, pw)
                probs = []
                for f in a["folders"]:
                    if f["names"][0] != "7zAES": probs.append("folder %s" % f["names"])
                    ivs = f["coders"][0][3]
                    if ivs[:2] != b"\x53\x0f" or len(ivs) != 18: probs.append("aes props %s" % ivs.hex())
                if len({f["coders"][0][3] for f in a["folders"]}) != len(a["folders"]): probs.append("IV reused")
                if encn and a["hdr_coders"] != ["7zAES", "LZMA"]: probs.append("header coders %s" % a["hdr_coders"])
                if not encn and "7zAES" in a["hdr_coders"]: probs.append("header encrypted")
                byname = {f["name"]: f for f in a["files"]}
                if byname.get("readme.txt", {}).get("crc") != zlib.crc32(files["readme.txt"]): probs.append("crc")
                t.record(not probs, label + " header (decrypted in Python)", "; ".join(probs))
            except ImportError:
                pass

    # ---- independent readers ----
    nroot, nfiles, ndirs, nexe = make_tree(t, "tree_noarm", arm=False)     # py7zr has no ARM64 filter
    nrels = rels_of(nfiles, ndirs)
    xarcs = []
    for m, lv, s, pw, encn in ((M_DEFAULT, 5, 1, None, False), (M_LZMA, 5, 0, None, False),
                               (M_BZIP2, 5, 1, None, False), (M_DEFLATE, 5, 1, None, False),
                               (M_PPMD, 5, 1, None, False), (M_STORE, 0, 1, None, False),
                               (M_DEFAULT, 5, 1, "secret", False), (M_DEFAULT, 5, 0, "비밀", True),
                               (M_STORE, 0, 1, "pw", True)):
        arc = t.path("xr_m%d_l%d_s%d%s%s.7z" % (m, lv, s, "_pw" if pw else "", "_names" if encn else ""))
        ok, r = gzt_c(t, arc, lv, nroot, nrels, pw=pw, method=m or None, solid=s, encnames=encn)
        if t.record(ok, "create " + os.path.basename(arc)):
            xarcs.append((arc, pw, m))
    # libarchive 3.7 fails on some PPMd + BCJ folders (7-Zip's own ones too): PPMd without executables
    ptxt = t.path("xr_ppmd_text.7z")
    ok, r = gzt_c(t, ptxt, 5, nroot, [x for x in nrels if x not in nexe and x != "bin/tiny.exe"],
                  method=M_PPMD, solid=1)
    t.record(ok, "create xr_ppmd_text.7z")
    if shutil.which("bsdtar"):                  # libarchive: no 7zAES, no ARM64 (without liblzma)
        for arc, pw, m in xarcs + [(ptxt, None, -1)]:
            if pw or m == M_PPMD:
                continue
            out = t.path("bsd_" + os.path.basename(arc))
            shutil.rmtree(out, ignore_errors=True); os.makedirs(out)
            r = subprocess.run(["bsdtar", "-xf", arc, "-C", out], capture_output=True)
            got, gdirs = tree_of(out)
            bad = [k for k, v in nfiles.items() if got.get(k) != v and not (m == -1 and (k in nexe or k == "bin/tiny.exe"))]
            t.record(not bad and all(d in gdirs for d in ndirs), "bsdtar " + os.path.basename(arc),
                     "rc=%d %s %s" % (r.returncode, bad[:4], r.stderr.decode(errors="replace")[-200:]))
    try:
        import py7zr
        for arc, pw, m in xarcs:
            out = t.path("py7zr_" + os.path.basename(arc))
            shutil.rmtree(out, ignore_errors=True)
            try:
                with py7zr.SevenZipFile(arc, "r", password=pw) as z:
                    z.extractall(out)
                got, gdirs = tree_of(out)
                bad = [k for k, v in nfiles.items() if got.get(k) != v] + [d for d in ndirs if d not in gdirs]
                t.record(not bad, "py7zr " + os.path.basename(arc), str(bad[:4]))
            except Exception as e:
                t.record(False, "py7zr " + os.path.basename(arc), repr(e)[:200])
    except ImportError:
        pass
    if shutil.which("unar"):
        for arc, pw, m in xarcs:
            out = t.path("unar_" + os.path.basename(arc))
            shutil.rmtree(out, ignore_errors=True)
            r = subprocess.run(["unar", "-q", "-f", "-D", "-o", out] + (["-p", pw] if pw else []) + [arc],
                               capture_output=True, timeout=300)
            got, gdirs = tree_of(out)
            bad = [k for k, v in nfiles.items() if got.get(k) != v]
            t.record(not bad, "unar " + os.path.basename(arc), "rc=%d %s" % (r.returncode, bad[:4]))

    # ---- our own reader ----
    if have_own:
        for name, pw in (("m0_l5_s1.7z", None), ("m0_l0_s1.7z", None), ("m4_l5_s0.7z", None),
                         ("m7_l5_s1.7z", None), ("enc_6_5_1.7z", "secret")):
            arc = t.path(name)
            if os.path.exists(arc):
                t.check_extract(arc, files, pw=pw, label="gzt x " + name)

    # ---- driver: links, times, attributes, modes, Korean names ----
    lnk_src = t.write_tree(t.path("lnk_src"), {"data.txt": b"link target data\n", "run.sh": b"#!/bin/sh\n"})
    os.chmod(os.path.join(lnk_src, "run.sh"), 0o750)
    T1 = unix_ft(1700000000, 1234567)
    T2 = unix_ft(1600000000, 7654321)
    T3 = unix_ft(1500000000, 5)
    lines = [("opt", "level", 5),
             ("d", "dir", "40755", "10", T1),
             ("d", "dir/빈 폴더", "40700", "10", T2),
             ("f", "dir/data.txt", os.path.join(lnk_src, "data.txt"), "100640", "20", T1, T2, T3),
             ("f", "dir/run.sh", os.path.join(lnk_src, "run.sh"), "100750", "20", T2, 0, 0),
             ("f", "readonly.txt", os.path.join(lnk_src, "data.txt"), "100444", "21", T3, 0, 0),
             ("l", "dir/link", "data.txt", "120777", T1),
             ("l", "dir/한글링크", "../readonly.txt", "120777", T2),
             ("l", "dangling", "nowhere/at/all", "120777", T3),
             ("f", "nomode.txt", os.path.join(lnk_src, "data.txt"), "0", "1", 0, 0, 0)]
    for s in (1, 0):
        for pw in (None, "pw"):
            ll = lines + [("opt", "solid", s)] + ([("opt", "password", pw)] if pw else [])
            name = "links_s%d%s" % (s, "_pw" if pw else "")
            arc, info = run_driver(t, drv, name, ll)
            label = "links/times/attrs %s%s" % ("solid" if s else "non-solid", " pw" if pw else "")
            if not t.record(info["result"] == 0, label + " create", "" if info["result"] == 0 else info["raw"][-300:]):
                continue
            out = t.path("x_" + name)
            shutil.rmtree(out, ignore_errors=True)
            r = sevenzip(t, ["x", "-y", "-snld", "-o" + out, arc, "-p" + (pw or "")])
            probs = []
            if r.returncode: probs.append("7z x rc=%d %s" % (r.returncode, r.stdout.decode(errors="replace")[-200:]))
            def rl(p):
                p = os.path.join(out, p)
                return os.readlink(p) if os.path.islink(p) else None
            if rl("dir/link") != "data.txt": probs.append("link %r" % rl("dir/link"))
            if rl("dir/한글링크") != "../readonly.txt": probs.append("korean link %r" % rl("dir/한글링크"))
            if rl("dangling") != "nowhere/at/all": probs.append("dangling %r" % rl("dangling"))
            try:
                if open(os.path.join(out, "dir/data.txt"), "rb").read() != b"link target data\n": probs.append("data")
                st = os.stat(os.path.join(out, "dir/run.sh"))
                if st.st_mode & 0o777 != 0o750: probs.append("mode run.sh %o" % (st.st_mode & 0o777))
                st = os.stat(os.path.join(out, "dir/data.txt"))
                if st.st_mtime_ns != (1700000000 * 10**9 + 123456700): probs.append("mtime %d" % st.st_mtime_ns)
                if not os.path.isdir(os.path.join(out, "dir/빈 폴더")): probs.append("empty dir")
            except OSError as e:
                probs.append(repr(e))
            try:
                a = parse_7z(arc, pw)
                by = {f["name"]: f for f in a["files"]}
                exp_attr = {"dir": 0x8000 | 0x10 | (0o40755 << 16), "dir/빈 폴더": 0x8000 | 0x10 | (0o40700 << 16),
                            "dir/data.txt": 0x8000 | 0x20 | (0o100640 << 16),
                            "readonly.txt": 0x8000 | 0x21 | (0o100444 << 16),
                            "dir/link": 0x8000 | 0x20 | (0o120777 << 16), "nomode.txt": 0x01}
                for k, v in exp_attr.items():
                    if by.get(k, {}).get("attr") != v: probs.append("attr %s %r" % (k, by.get(k, {}).get("attr")))
                d = by.get("dir/data.txt", {})
                if (d.get("mtime"), d.get("ctime"), d.get("atime")) != (T1, T2, T3): probs.append("times %r" % d)
                if by.get("dir/run.sh", {}).get("ctime") is not None: probs.append("ctime not given -> undefined")
                if by.get("nomode.txt", {}).get("mtime") is not None: probs.append("mtime 0 -> undefined")
                lk = by.get("dir/한글링크", {})
                if lk.get("size") != len("../readonly.txt") or lk.get("crc") != zlib.crc32(b"../readonly.txt"):
                    probs.append("link data")
                if [f["name"] for f in a["files"] if f["empty"]] != ["dir", "dir/빈 폴더"]: probs.append("empty order")
            except ImportError:
                pass
            except Exception as e:
                probs.append(repr(e))
            t.record(not probs, label, "; ".join(probs[:6]))

    # ---- driver: errors, shrinking / growing input, cancel, no write_at ----
    base = [("opt", "level", 3), ("g", "a.txt", 50000, 1, "text", "100644"), ("g", "b.txt", 70000, 2, "text", "100644")]
    cases = [
        ("open fails, skipped", [("x", "bad_open.txt", 1000, 1000, "open", 3)], "skip", 0, ["bad_open.txt"]),
        ("read fails mid-file", [("x", "bad_read.txt", 90000, 40000, "read", 4)], "skip", 0, ["bad_read.txt"]),
        ("read fails in the first 4 KiB", [("x", "bad_peek", 90000, 1000, "read", 4)], "skip", 0, ["bad_peek"]),
        ("read fails at once", [("x", "bad_read0.txt", 90000, 0, "read", 4)], "skip", 0, ["bad_read0.txt"]),
        ("file shrinks", [("x", "shrink.txt", 90000, 1234, "none", 5)], "skip", 0, []),
        ("file shrinks to 0", [("x", "gone.txt", 90000, 0, "none", 5)], "skip", 0, []),
        ("file grows", [("x", "grow.txt", 1000, 300000, "none", 6)], "skip", 0, []),
        ("empty file grows", [("x", "was_empty.txt", 0, 5000, "none", 7)], "skip", 0, []),
        ("empty file cannot be opened", [("x", "empty_bad.txt", 0, 0, "open", 8)], "skip", 0, ["empty_bad.txt"]),
        ("on_error aborts", [("x", "bad_open.txt", 1000, 1000, "open", 3)], "abort", 1, ["bad_open.txt"]),
    ]
    for s in (1, 0):
        for label, extra, pol, want_rc, want_err in cases:
            ll = base + extra + [("opt", "onerror", pol), ("opt", "solid", s), ("g", "z.txt", 3000, 9, "text", "100644")]
            name = "err_%s_%d" % (label.replace(" ", "_"), s)
            arc, info = run_driver(t, drv, name, ll)
            lab = "%s (%s)" % (label, "solid" if s else "non-solid")
            errs = [e[1] for e in info["err"]]
            if want_rc:
                t.record(info["result"] == 1 and errs == want_err, lab, "result %r errs %r" % (info["result"], errs))
                continue
            if not t.record(info["result"] == 0 and errs == want_err, lab + " result",
                            "result %r errs %r %s" % (info["result"], errs,
                                                      "" if info["result"] == 0 else info["raw"][-200:])):
                continue
            r = sevenzip(t, ["t", arc])
            if not t.record(r.returncode == 0, lab + " 7z t", r.stdout.decode(errors="replace")[-300:]):
                continue
            a = parse_7z(arc)
            by = {f["name"]: f for f in a["files"]}
            probs = []
            for nm, (crc, made) in info["crc"].items():
                if nm in ("bad_open.txt", "bad_read0.txt", "empty_bad.txt"):
                    if nm in by: probs.append(nm + " should be skipped")
                    continue
                f = by.get(nm)
                if not f: probs.append("missing " + nm); continue
                if made == 0:
                    if not (f["empty"] and not f["isdir"]): probs.append(nm + " should be an empty file")
                elif f["size"] != made or f["crc"] != crc:
                    probs.append("%s size %d/%d crc %r/%r" % (nm, f["size"], made, f["crc"], crc))
            t.record(not probs, lab + " content", "; ".join(probs))

    arc, info = run_driver(t, drv, "nowa", base + [("opt", "nowriteat", 1)])
    t.record(info["result"] == 5 and os.path.getsize(arc) == 0, "sink without write_at: GZ_E_METHOD, nothing written",
             "result %r size %d" % (info["result"], os.path.getsize(arc)))
    arc, info = run_driver(t, drv, "cancel", base + [("g", "big.bin", 50 << 20, 7, "mix", "100644"),
                                                      ("opt", "cancel_at", 8 << 20), ("opt", "level", 1)])
    t.record(info["result"] == 8 and os.path.getsize(arc) < (30 << 20), "cancel: GZ_E_CANCEL",
             "result %r size %d" % (info["result"], os.path.getsize(arc)))
    arc, info = run_driver(t, drv, "progress", base + [("g", "c.bin", 3 << 20, 8, "mix", "100644")])
    pr = info["progress"] or (0, 0, 0, 0)
    t.record(info["result"] == 0 and pr[0] > 3 and pr[1] == 1 and pr[2] == pr[3] == 50000 + 70000 + (3 << 20),
             "progress monotonic, ends at total", "%r" % (pr,))
    arc, info = run_driver(t, drv, "zipcrypto", base + [("opt", "password", "x"), ("opt", "encryption", 1)])
    t.record(info["result"] == 5, "ZipCrypto refused (GZ_E_METHOD)", "result %r" % info["result"])
    arc, info = run_driver(t, drv, "nopw", base + [("opt", "encryption", 2)])
    t.record(info["result"] == 6, "AES without password: GZ_E_PASSWORD", "result %r" % info["result"])
    arc, info = run_driver(t, drv, "allbad", [("x", "bad.txt", 10, 10, "open", 1)])
    r = sevenzip(t, ["t", arc])
    t.record(info["result"] == 0 and r.returncode == 0 and parse_7z(arc)["files"] == [],
             "only failing files: empty archive", "result %r rc=%d" % (info["result"], r.returncode))
    arc, info = run_driver(t, drv, "onlydirs", [("d", "x", "40755", "10", T1), ("d", "x/y", "40755", "10", T1)])
    r = sevenzip(t, ["t", arc])
    t.record(info["result"] == 0 and r.returncode == 0 and [f["name"] for f in parse_7z(arc)["files"]] == ["x", "x/y"],
             "directories only (no streams)", "rc=%d" % r.returncode)

    # randomized item lists: kinds, sizes, faults and options; 7z must accept every result
    rnd = random.Random(1234)
    fails = []
    for k in range(24):
        ll = [("opt", "level", rnd.choice((0, 1, 3, 5, 9))), ("opt", "method", rnd.choice((0, 0, 1, 2, 4, 5, 6, 7))),
              ("opt", "solid", rnd.choice((0, 1)))]
        pw = rnd.choice((None, None, "pw%d" % k))
        if pw:
            ll += [("opt", "password", pw), ("opt", "encnames", rnd.choice((0, 1)))]
        names = set()
        for j in range(rnd.randint(1, 25)):
            nm = "/".join(rnd.choice(("a", "b", "한", "d.exe", "e.so.1", "f.txt", "g")) for _ in range(rnd.randint(1, 3)))
            if nm in names or any(nm.startswith(x + "/") or x.startswith(nm + "/") for x in names):
                continue
            names.add(nm)
            kind = rnd.random()
            if kind < 0.1:
                ll.append(("d", nm, "40755", "10", unix_ft(1600000000 + j)))
            elif kind < 0.2:
                ll.append(("l", nm, "../target%d" % j, "120777", 0))
            elif kind < 0.4:
                dec = rnd.choice((0, 10, 5000, 70000))
                act = rnd.choice((0, 10, 5000, 70000, 300000))
                ll.append(("x", nm, dec, act, rnd.choice(("none", "none", "open", "read")), j))
            else:
                ll.append(("g", nm, rnd.choice((1, 100, 4096, 70000, 1 << 20)), j, rnd.choice(("zero", "rand", "text", "mix")),
                           rnd.choice(("100644", "100755", "0"))))
        arc, info = run_driver(t, drv, "rand%02d" % k, ll)
        if info["result"] != 0:
            fails.append("%d: result %r" % (k, info["result"])); continue
        r = sevenzip(t, ["t", arc, "-p" + (pw or "")])
        if r.returncode:
            fails.append("%d: 7z t %s" % (k, r.stdout.decode(errors="replace")[-200:])); continue
        try:
            a = parse_7z(arc, pw)
        except ImportError:
            continue
        except Exception as e:
            fails.append("%d: parse %r" % (k, e)); continue
        by = {f["name"]: f for f in a["files"]}
        for nm, (crc, made) in info["crc"].items():
            f = by.get(nm)
            if made and (not f or f["size"] != made or f["crc"] != crc):
                fails.append("%d: %s" % (k, nm))
        os.remove(arc)
    t.record(not fails, "24 randomized item lists (faults, options) accepted by 7z t", "; ".join(fails[:5]))

    arc, info = run_driver(t, drv, "tiny", [("g", "a.txt", 10, 1, "text", "100644")])
    a = parse_7z(arc)
    r = sevenzip(t, ["t", arc])
    t.record(info["result"] == 0 and r.returncode == 0 and not a["encoded"] and len(a["files"]) == 1,
             "tiny archive: plain header (LZMA would not shrink it)", "%d bytes" % a["size"])

    # long and odd names
    long_name = "/".join(["깊은폴더%02d" % i for i in range(40)] + ["x" * 200 + ".txt"])
    odd = ["a b/c;d'e\"f.txt", "./lead/dot.txt", "/abs/olute.txt", "trail/", "%s/한글.dat" % ("가" * 120), long_name]
    ll = [("opt", "level", 1)] + [("g", nm, 100 + i, i, "text", "100644") for i, nm in enumerate(odd)]
    arc, info = run_driver(t, drv, "names", ll)
    try:
        names = [f["name"] for f in parse_7z(arc)["files"]]
    except Exception as e:
        names = [repr(e)]
    want = ["a b/c;d'e\"f.txt", "lead/dot.txt", "abs/olute.txt", "trail", "%s/한글.dat" % ("가" * 120), long_name]
    r = sevenzip(t, ["t", arc])
    t.record(info["result"] == 0 and r.returncode == 0 and sorted(names) == sorted(want), "odd and long names",
             "%r" % [n[:40] for n in names])

    # ---- 10k small files (gzt c) ----
    many = {"many/d%02d/f%05d.txt" % (i % 50, i): (("file %d " % i) * (1 + i % 7)).encode() for i in range(10000)}
    msrc = t.write_tree(t.path("many_src"), many)
    mrels = sorted(many)
    for s in (1, 0):
        arc = t.path("many_s%d.7z" % s)
        t0 = time.time()
        ok, r = gzt_c(t, arc, 5, msrc, mrels, solid=s)
        dt = time.time() - t0
        if t.record(ok, "10k files %s create" % ("solid" if s else "non-solid"), "%.1fs" % dt):
            check_7z(t, arc, many, [], label="10k files %s (%.1fs, %d bytes)" % ("solid" if s else "non-solid",
                                                                               dt, os.path.getsize(arc)))
    shutil.rmtree(msrc, ignore_errors=True)

    # ---- 300 MB file (driver, generated) ----
    for lv, kind in ((1, "text"),):
        arc, info = run_driver(t, drv, "big300", [("opt", "level", lv), ("g", "big.bin", 300 << 20, 11, kind, "100644"),
                                                  ("g", "small.txt", 1000, 12, "text", "100644")])
        ok = info["result"] == 0
        if t.record(ok, "300 MB file create", "" if ok else info["raw"][-200:]):
            p = subprocess.Popen(["7z", "x", "-so", arc, "big.bin"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            crc, n = 0, 0
            while True:
                b = p.stdout.read(1 << 20)
                if not b: break
                crc = zlib.crc32(b, crc); n += len(b)
            p.wait()
            want = info["crc"].get("big.bin")
            t.record(p.returncode == 0 and want == (crc, n), "300 MB file 7z x matches",
                     "got %08x/%d want %r, archive %d bytes" % (crc, n, want, os.path.getsize(arc)))
        if os.path.exists(arc):
            os.remove(arc)

    # ---- over 4 GiB (sizes and offsets past 32 bits): slow, GZ_SLOW_TESTS=1 ----
    if os.environ.get("GZ_SLOW_TESTS"):
        arc, info = run_driver(t, drv, "big5g", [("opt", "level", 1), ("g", "a.bin", 1000, 1, "text", "100644"),
                                                 ("g", "zero5g.bin", (4 << 30) + 12345, 2, "zero", "100644"),
                                                 ("g", "z.txt", 5000, 3, "text", "100644"), ("opt", "solid", 1)])
        r = sevenzip(t, ["t", arc])
        a = parse_7z(arc)
        by = {f["name"]: f for f in a["files"]}
        ok = info["result"] == 0 and r.returncode == 0 and by["zero5g.bin"]["size"] == (4 << 30) + 12345 and \
            by["z.txt"]["crc"] == info["crc"]["z.txt"][0]
        t.record(ok, "4 GiB + 12345 byte file in a solid block", "rc=%d %d bytes" % (r.returncode, os.path.getsize(arc)))
        os.remove(arc)

    # ---- sizes compared with 7z a at the same settings ----
    size_table(t, drv)

def size_table(t, drv):
    corpus = t.path("corpus")
    shutil.rmtree(corpus, ignore_errors=True)
    shutil.copytree(os.path.join(ROOT, "src"), os.path.join(corpus, "src"))
    for src, dst in ((os.path.join(WINE64, "notepad.exe"), "bin/notepad64.exe"),
                     (os.path.join(WINE32, "notepad.exe"), "bin/notepad32.exe"),
                     (os.path.join(WINE64, "dplay.dll"), "bin/dplay.dll")):
        if os.path.exists(src):
            os.makedirs(os.path.dirname(os.path.join(corpus, dst)), exist_ok=True)
            shutil.copyfile(src, os.path.join(corpus, dst))
    rels = []
    for dp, dns, fns in os.walk(corpus):
        for x in dns + fns:
            rels.append(os.path.relpath(os.path.join(dp, x), corpus))
    rels.sort()
    total = sum(os.path.getsize(os.path.join(corpus, r)) for r in rels if os.path.isfile(os.path.join(corpus, r)))
    rows = []
    worst = 0.0
    configs = [(M_DEFAULT, lv, 1) for lv in (1, 3, 5, 7, 9)] + [(M_DEFAULT, 5, 0)] + \
              [(m, 5, 1) for m in (M_LZMA, M_PPMD, M_BZIP2, M_DEFLATE)] + [(M_STORE, 0, 1)]
    for m, lv, s in configs:
        ours = t.path("size_ours.7z")
        ref = t.path("size_7z.7z")
        t0 = time.time()
        ok, r = gzt_c(t, ours, lv, corpus, rels, method=m or None, solid=s)
        t_ours = time.time() - t0
        if os.path.exists(ref):
            os.remove(ref)
        args = ["a", "-bd", "-mx%d" % lv, "-ms=%s" % ("on" if s else "off"), "-mmt=1", ref, "."]
        if m not in (M_DEFAULT, M_STORE):
            args.insert(2, "-m0=" + MNAME[m])
        t0 = time.time()
        rr = subprocess.run(["7z"] + args, cwd=corpus, capture_output=True)
        t_ref = time.time() - t0
        if not ok or rr.returncode:
            t.record(False, "size table %s L%d" % (MNAME[m], lv), "create failed"); continue
        a, b = os.path.getsize(ours), os.path.getsize(ref)
        ratio = a / b
        if m != M_STORE:
            worst = max(worst, ratio)
        rows.append("%-8s L%d %-9s ours %9d (%5.1fs)  7z %9d (%5.1fs)  %+.2f%%" % (
            MNAME[m], lv, "solid" if s else "non-solid", a, t_ours, b, t_ref, (ratio - 1) * 100))
        r = sevenzip(t, ["t", ours])
        t.record(r.returncode == 0 and ratio < 1.06, "size %s L%d %s vs 7z a" % (MNAME[m], lv, "solid" if s else "non-solid"),
                 rows[-1])
    table = "corpus %d bytes (src/ + PE files)\n" % total + "\n".join(rows)
    with open(t.path("size_table.txt"), "w") as f:
        f.write(table + "\n")
    if t.verbose:
        print(table)
    t.record(True, "size table written", t.path("size_table.txt"))
    shutil.rmtree(corpus, ignore_errors=True)
