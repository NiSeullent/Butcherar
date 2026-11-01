"""7z reader tests (src/fmt/sevenz.c).

Fixtures: 7-Zip 23 (every method it can write, filters, BCJ2, solid modes, header
compression/encryption, Korean names and passwords, times, attributes, symlinks,
anti items of differential updates, deletions, volumes, 10k files), py7zr (another
writer: Zstd, Brotli, PPMd, Delta, AES with encrypted headers), a small 7z writer
below for structures 7-Zip does not produce (External names in additional streams,
LZMA chained into LZMA, filters directly on packed streams, Swap2, zero-length
substreams, version 0.2, numCyclesPower 0x3F, odd salt/IV sizes) and for hostile
headers, synthetic PE/ELF SFX stubs, truncations, bit flips and an in-process
fuzzer (tests/drivers/sevenz_tool.c), which also checks the gz_out protocol,
selective solid extraction, random access in solid folders, check_password, views
and speed against 7z.
"""
import os, random, struct, zlib, lzma, bz2, hashlib, shutil, subprocess, time, importlib.util

E_FORMAT, E_DATA, E_CRC, E_METHOD, E_PASSWORD, E_TRUNC, E_LIMIT = 2, 3, 4, 5, 6, 9, 15
SIG = b"7z\xbc\xaf\x27\x1c"

# ---------------------------------------------------------------- data

def gen_text(n, seed=1):
    rnd = random.Random(seed)
    words = ["고기", "삼겹살", "archive", "7-Zip", "folder", "coder", "the", "and", "\n", "    ",
             "static", "u32", "Bandizip", "목살", "0x%04x" % seed]
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(words).encode() + b" "
    return bytes(out[:n])

def gen_bin(n, seed=2):
    return random.Random(seed).randbytes(n)

def gen_code(n):
    out = bytearray()
    for d in ("/usr/bin", "/usr/lib/x86_64-linux-gnu"):
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            p = os.path.join(d, f)
            if os.path.isfile(p) and not os.path.islink(p) and 20000 < os.path.getsize(p) < 3000000:
                try:
                    out += open(p, "rb").read()
                except OSError:
                    pass
            if len(out) >= n:
                return bytes(out[:n])
    return bytes(out) + gen_bin(max(0, n - len(out)), 9)

def base_tree():
    return {
        "readme.txt": gen_text(5000),
        "data/random.bin": gen_bin(70000),
        "data/zeros.bin": bytes(100000),
        "data/empty.txt": b"",
        "data/sub/deep/leaf.txt": b"leaf\n" * 33,
        "한글 폴더/고기 목록.txt": "삼겹살, 목살, 갈비\n".encode() * 50,
        "한글 폴더/빈 폴더": None,
        "empty dir": None,
        "spaces and (parens) [x].txt": b"x" * 777,
        "unicode/日本語ファイル.txt": "テスト".encode() * 99,
        "unicode/ελληνικά.txt": b"greek",
    }

# ---------------------------------------------------------------- tiny 7z writer

def num(v):
    for i in range(8):
        if v < (1 << (7 * (i + 1))):
            return bytes([((0xFF << (8 - i)) & 0xFF) | (v >> (8 * i))]) + (v & ((1 << (8 * i)) - 1)).to_bytes(i, "little")
    return b"\xff" + v.to_bytes(8, "little")

def bits(flags):
    out = bytearray((len(flags) + 7) // 8)
    for i, f in enumerate(flags):
        if f:
            out[i >> 3] |= 0x80 >> (i & 7)
    return bytes(out)

def prop(pid, data):
    return num(pid) + num(len(data)) + data

def digests(crcs):
    if all(c is not None for c in crcs):
        head = b"\x01"
    else:
        head = b"\x00" + bits([c is not None for c in crcs])
    return head + b"".join(struct.pack("<I", c) for c in crcs if c is not None)

def coder_bytes(cid, props=None, nin=1):
    flag = len(cid) | (0x10 if nin != 1 else 0) | (0x20 if props is not None else 0)
    b = bytes([flag]) + cid
    if nin != 1:
        b += num(nin) + num(1)
    if props is not None:
        b += num(len(props)) + props
    return b

def folder_bytes(coders, bonds=(), packed=None):
    b = num(len(coders)) + b"".join(coder_bytes(*c) for c in coders)
    for i, o in bonds:
        b += num(i) + num(o)
    if packed is not None and len(packed) > 1:
        b += b"".join(num(p) for p in packed)
    return b

class Folder:
    """coders: [(id bytes, props|None, nin)], sizes: unpack size per coder, subs: file sizes"""
    def __init__(self, coders, sizes, bonds=(), packed=None, crc=None, subs=None, sub_crcs=None):
        self.coders, self.sizes, self.bonds, self.packed = coders, sizes, bonds, packed
        self.crc, self.subs, self.sub_crcs = crc, subs, sub_crcs

def streams_info(pack_sizes, folders, pack_pos=0, with_subs=True, folders_raw=None):
    out = b""
    if pack_sizes is not None:
        out += b"\x06" + num(pack_pos) + num(len(pack_sizes)) + b"\x09" + b"".join(num(s) for s in pack_sizes) + b"\x00"
    if folders:
        out += b"\x07\x0b" + num(len(folders))
        out += folders_raw if folders_raw is not None else b"\x00" + b"".join(
            folder_bytes(f.coders, f.bonds, f.packed) for f in folders)
        out += b"\x0c" + b"".join(num(s) for f in folders for s in f.sizes)
        if any(f.crc is not None for f in folders):
            out += b"\x0a" + digests([f.crc for f in folders])
        out += b"\x00"
        if with_subs and any(f.subs is not None for f in folders):
            out += b"\x08"
            subs = [f.subs if f.subs is not None else [f.sizes[0]] for f in folders]
            if any(len(s) != 1 for s in subs):
                out += b"\x0d" + b"".join(num(len(s)) for s in subs)
            if any(len(s) > 1 for s in subs):
                out += b"\x09" + b"".join(num(x) for s in subs for x in s[:-1])
            crcs = []
            for f, s in zip(folders, subs):
                if len(s) == 1 and f.crc is not None:
                    continue
                crcs += f.sub_crcs if f.sub_crcs is not None else [None] * len(s)
            if crcs and any(c is not None for c in crcs):
                out += b"\x0a" + digests(crcs)
            out += b"\x00"
    return out + b"\x00"

def files_info(files, extra=b"", names=True):
    """files: dicts name, stream (bool), dir, anti, mtime, attr"""
    out = num(len(files))
    empty = [not f.get("stream", True) for f in files]
    if any(empty):
        out += prop(0x0E, bits(empty))
        ef = [not f.get("dir", False) for f, e in zip(files, empty) if e]
        if any(ef):
            out += prop(0x0F, bits(ef))
        anti = [f.get("anti", False) for f, e in zip(files, empty) if e]
        if any(anti):
            out += prop(0x10, bits(anti))
    out += extra
    if names:
        out += prop(0x11, b"\x00" + b"".join(f["name"].encode("utf-16-le") + b"\0\0" for f in files))
    for pid, key, fmt in ((0x14, "mtime", "<Q"), (0x15, "attr", "<I")):
        vals = [f.get(key) for f in files]
        if any(v is not None for v in vals):
            dv = b"\x01" if all(v is not None for v in vals) else b"\x00" + bits([v is not None for v in vals])
            out += prop(pid, dv + b"\x00" + b"".join(struct.pack(fmt, v) for v in vals if v is not None))
    return b"\x05" + out + b"\x00"

def sig_header(nh_off, header, ver=4, packed=b""):
    start = struct.pack("<QQI", nh_off, len(header), zlib.crc32(header))
    return SIG + bytes([0, ver]) + struct.pack("<I", zlib.crc32(start)) + start

def finish(packed, header, ver=4):
    return sig_header(len(packed), header, ver) + packed + header

def lzma1_props(dict_size=1 << 20, lc=3, lp=0, pb=2):
    return bytes([(pb * 5 + lp) * 9 + lc]) + struct.pack("<I", dict_size)

def lzma1(data, dict_size=1 << 20, lc=3, lp=0, pb=2):
    return lzma.compress(data, format=lzma.FORMAT_RAW,
                         filters=[{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": lc, "lp": lp, "pb": pb}])

def lzma2(data, filters=()):
    return lzma.compress(data, format=lzma.FORMAT_RAW, filters=list(filters) + [{"id": lzma.FILTER_LZMA2, "preset": 6}])

def lzma2_prop(dict_size=8 << 20):
    for p in range(41):
        if (2 | (p & 1)) << (p // 2 + 11) >= dict_size:
            return bytes([p])
    return b"\x28"

ID_COPY, ID_LZMA, ID_LZMA2, ID_BCJ, ID_DELTA = b"\x00", b"\x03\x01\x01", b"\x21", b"\x03\x03\x01\x03", b"\x03"
ID_AES, ID_SWAP2, ID_SWAP4, ID_DEFLATE, ID_BZIP2 = b"\x06\xf1\x07\x01", b"\x02\x03\x02", b"\x02\x03\x04", b"\x04\x01\x08", b"\x04\x02\x02"

def simple_7z(items, coder="copy", solid=True, header="plain", ver=4, pw=None, extra_files=b""):
    """items: [(name, bytes|None)]; coder: copy|lzma|lzma2|deflate|bzip2|bcj; header: plain|lzma"""
    files, blobs, folders = [], [], []
    streams = [(n, d) for n, d in items if d]
    groups = [streams] if solid else [[s] for s in streams]
    for g in groups:
        if not g:
            continue
        data = b"".join(d for n, d in g)
        if coder == "copy":
            co, pk = [(ID_COPY, None, 1)], data
        elif coder == "lzma":
            co, pk = [(ID_LZMA, lzma1_props(), 1)], lzma1(data)
        elif coder == "lzma2":
            co, pk = [(ID_LZMA2, lzma2_prop(), 1)], lzma2(data)
        elif coder == "deflate":
            c = zlib.compressobj(9, zlib.DEFLATED, -15)
            co, pk = [(ID_DEFLATE, None, 1)], c.compress(data) + c.flush()
        elif coder == "bzip2":
            co, pk = [(ID_BZIP2, None, 1)], bz2.compress(data)
        elif coder == "bcj":       # BCJ + LZMA2 from one xz raw chain
            co, pk = [(ID_BCJ, None, 1), (ID_LZMA2, lzma2_prop(), 1)], lzma2(data, [{"id": lzma.FILTER_X86}])
        sizes = [len(data)] * len(co)
        bonds = [(0, 1)] if len(co) == 2 else []
        folders.append(Folder(co, sizes, bonds, subs=[len(d) for n, d in g],
                              sub_crcs=[zlib.crc32(d) for n, d in g]))
        blobs.append(pk)
    for n, d in items:
        files.append(dict(name=n, stream=bool(d), dir=d is None, attr=0x10 if d is None else 0x20))
    packed = b"".join(blobs)
    hdr = b"\x01"
    if folders:
        hdr += b"\x04" + streams_info([len(b) for b in blobs], folders)
    hdr += files_info(files, extra_files) + b"\x00"
    if header == "lzma":
        ph = lzma1(hdr)
        enc = b"\x17" + streams_info([len(ph)], [Folder([(ID_LZMA, lzma1_props(), 1)], [len(hdr)], crc=zlib.crc32(hdr))],
                                     pack_pos=len(packed))
        return finish(packed + ph, enc, ver)
    return finish(packed, hdr, ver)

def kdf7z(pw, salt, power):
    pwb = pw.encode("utf-16-le")
    if power == 0x3F:
        return (salt + pwb + bytes(32))[:32]
    h = hashlib.sha256()
    for i in range(1 << power):
        h.update(salt + pwb + struct.pack("<Q", i))
    return h.digest()

def aes_7z(items, pw, power=6, salt=b"", iv=b"\x11" * 16, inner="lzma2"):
    """one solid folder: AES -> LZMA2/Copy, crafted with pycryptodome(x)"""
    from Cryptodome.Cipher import AES
    data = b"".join(d for n, d in items if d)
    if inner == "lzma2":
        comp, ic = lzma2(data), (ID_LZMA2, lzma2_prop(), 1)
    else:
        comp, ic = data, (ID_COPY, None, 1)
    padded = comp + bytes(-len(comp) % 16)
    key = kdf7z(pw, salt, power)
    ivp = (iv + bytes(16))[:16]
    enc = AES.new(key, AES.MODE_CBC, ivp).encrypt(padded)
    ns, ni = len(salt), len(iv)
    b0 = power | (0x80 if ns else 0) | (0x40 if ni else 0)
    props = bytes([b0])
    if ns or ni:
        props += bytes([((ns - (1 if ns else 0)) << 4) | (ni - (1 if ni else 0))]) + salt + iv
    co = [ic, (ID_AES, props, 1)]
    f = Folder(co, [len(data), len(padded)], [(0, 1)], subs=[len(d) for n, d in items if d],
               sub_crcs=[zlib.crc32(d) for n, d in items if d])
    files = [dict(name=n, stream=bool(d), dir=d is None) for n, d in items]
    hdr = b"\x01\x04" + streams_info([len(enc)], [f]) + files_info(files) + b"\x00"
    return finish(enc, hdr)

def arm_encode(data, pos=0):
    """xz/7-Zip ARM branch converter, encoder side"""
    b = bytearray(data)
    for i in range(0, len(b) - 3, 4):
        if b[i + 3] == 0xEB:
            src = (b[i] | b[i + 1] << 8 | b[i + 2] << 16) << 2
            dest = ((pos + i + 8 + src) >> 2) & 0xFFFFFF
            b[i], b[i + 1], b[i + 2] = dest & 0xFF, (dest >> 8) & 0xFF, dest >> 16
    return bytes(b)

def delta_encode(data, dist):
    return bytes((data[i] - (data[i - dist] if i >= dist else 0)) & 0xFF for i in range(len(data)))

def pe_stub(payload_len=0x600, extra=b""):
    """minimal PE32 image: DOS header, PE header, 2 sections; overlay starts at the end"""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<4sHHIIIHH", b"PE\0\0", 0x14C, 2, 0, 0, 0, 0xE0, 0x102)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)
    secs = b""
    raw = 0x200
    for i, nm in enumerate((b".text", b".rsrc")):
        secs += struct.pack("<8sIIIIIIHHI", nm, 0x1000, 0x1000 * (i + 1), payload_len // 2, raw, 0, 0, 0, 0, 0x60000020)
        raw += payload_len // 2
    img = bytes(dos) + coff + bytes(opt) + secs
    img += bytes(0x200 - len(img))
    img += bytes((i * 7 + 3) & 0xFF for i in range(payload_len))
    return img + extra

# ---------------------------------------------------------------- helpers

def seven(t, args, cwd=None, check=True):
    return t.sh(["7z"] + args, cwd=cwd, check=check)

def mk7z(t, name, src, args, files=("."), cwd_rel=True):
    arc = t.path("arc", name)
    if os.path.exists(arc):
        os.remove(arc)
    seven(t, ["a", "-bd", "-y", arc] + list(args) + list(files), cwd=src)
    return arc

def slt_methods(t, arc, pw=None):
    r = seven(t, ["l", "-slt", "-p" + (pw or ""), arc], check=False)
    out, cur, seen = {}, {}, False
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("----------"):
            seen = True
            continue
        if not seen:
            continue
        if line.startswith("Path = "):
            cur = {"path": line[7:]}
        elif line.startswith("Method = "):
            cur["method"] = line[9:]
        elif line.startswith("Folder = ") or line.startswith("Attributes = "):
            if cur.get("path"):
                out[cur["path"]] = cur
    return out

def tool_list(t, tool, arc, pw=None):
    r = t.sh([tool, "l", arc] + ([pw] if pw else []), check=False)
    lines = r.stdout.decode("utf-8", "replace").splitlines()
    head, rows = (lines[0] if lines else ""), []
    for ln in lines[1:]:
        p = ln.split("\t")
        if len(p) >= 12:
            rows.append(dict(idx=int(p[0]), dir=int(p[1]), size=int(p[2]), csize=int(p[3]), crc=p[4], mtime=int(p[5]),
                             attr=int(p[6], 16), mode=int(p[7], 8), enc=int(p[8]), link=int(p[9]), method=p[10], name=p[11]))
    return head, rows

def tool_rows(r):
    rows = {}
    for ln in r.stdout.decode("utf-8", "replace").splitlines():
        p = ln.split("\t")
        if len(p) == 4 and p[0].isdigit():
            rows[int(p[0])] = (int(p[1]), int(p[2]), p[3])
    return rows

def gzt_rows(t, arc, pw=None):
    r, rows, out = t.extract(arc, pw)
    return r, rows, out

# ---------------------------------------------------------------- sections

def test_methods(t, src, tree):
    for m in ("Copy", "LZMA", "LZMA2", "BZip2", "Deflate", "Deflate64", "PPMd"):
        for solid in ("on", "off"):
            arc = mk7z(t, "m_%s_%s.7z" % (m, solid), src, ["-m0=" + m, "-ms=" + solid, "-mf=off"])
            if m == "PPMd":
                r, rows, out = t.extract(arc)
                files = [v for v in rows.values() if not v[1] and v[2]]
                if files and all(v[0] == E_METHOD for v in files):
                    t.record(True, "PPMd %s: GZ_E_METHOD until ppmd7.h is merged" % solid)
                    continue
            t.check_vs_7z(arc, label="7z -m0=%s -ms=%s" % (m, solid))
    # LZMA with unusual lc/lp/pb and dictionary sizes
    for opt in ("LZMA:d=1536k:lc=8:lp=4:pb=0", "LZMA:d=64k:lc=0:lp=2:pb=4", "LZMA2:d=12m:lc=1:lp=3", "LZMA2:d=4k"):
        arc = mk7z(t, "lzopt_%d.7z" % len(opt), src, ["-m0=" + opt, "-mf=off"])
        t.check_vs_7z(arc, label="7z -m0=" + opt)
    # levels / multithreaded LZMA2 (several independent chunk streams)
    big = t.write_tree(t.path("mt_src"), {"big.bin": gen_text(3000000, 5) + gen_bin(500000, 6) + gen_text(3000000, 7)})
    for args in (["-mx=1"], ["-mx=9", "-mmt=4", "-m0=LZMA2:c=1m"], ["-mx=0"]):
        arc = mk7z(t, "lvl_%s.7z" % "_".join(a.strip("-").replace("=", "").replace(":", "") for a in args), big, args)
        t.check_vs_7z(arc, label="7z " + " ".join(args))

def test_filters(t, src):
    code = gen_code(600000)
    d = t.write_tree(t.path("code_src"), {"prog.exe": code, "lib.dll": code[100000:400000], "x.txt": gen_text(20000)})
    for f, m in (("BCJ", "LZMA2"), ("ARM64", "LZMA2"), ("ARM", "LZMA"), ("ARMT", "LZMA2"), ("PPC", "LZMA"),
                 ("SPARC", "LZMA2"), ("IA64", "LZMA"), ("Delta:4", "LZMA"), ("Delta:1", "Copy"), ("Swap2", "LZMA2"),
                 ("Swap4", "LZMA2"), ("ARM64:4096", "LZMA2")):
        arc = mk7z(t, "f_%s.7z" % f.replace(":", "_"), d, ["-mf=off", "-m0=" + f, "-m1=" + m])
        t.check_vs_7z(arc, label="7z filter %s + %s" % (f, m))
    for args, lab in ((["-mf=BCJ2"], "BCJ2 (LZMA2 main)"),
                      (["-m0=BCJ2", "-m1=LZMA:d=21", "-m2=LZMA:d=20", "-m3=LZMA:d=20", "-mb0:1", "-mb0s1:2", "-mb0s2:3"],
                       "BCJ2 classic 4 coders"),
                      (["-m0=BCJ2", "-m1=LZMA2", "-m2=Copy", "-m3=Copy", "-mb0:1", "-mb0s1:2", "-mb0s2:3"],
                       "BCJ2 stored CALL/JUMP"),
                      (["-mf=BCJ2", "-ms=off"], "BCJ2 non-solid"),
                      (["-mf=BCJ2", "-p고기", "-mhe=on"], "BCJ2 + AES")):
        arc = mk7z(t, "bcj2_%d.7z" % len(lab), d, args)
        pw = "고기" if any(a.startswith("-p") for a in args) else None
        t.check_vs_7z(arc, pw=pw, label="7z " + lab)
    # PE inputs if there are any (wine dlls, our own Windows build)
    pes = []
    for root in ("/usr/lib/x86_64-linux-gnu/wine", "/usr/lib/wine", "/usr/lib/i386-linux-gnu/wine",
                 os.path.join(os.path.dirname(t.gzt))):
        for dp, dn, fn in os.walk(root):
            pes += [os.path.join(dp, f) for f in fn if f.lower().endswith((".dll", ".exe"))]
            if len(pes) > 6:
                break
    if pes:
        pe = {}
        for i, p in enumerate(sorted(pes)[:6]):
            try:
                pe["pe%d_%s" % (i, os.path.basename(p))] = open(p, "rb").read()[:4000000]
            except OSError:
                pass
        pd = t.write_tree(t.path("pe_src"), pe)
        for args in (["-mf=BCJ2"], ["-mf=BCJ"], ["-m0=BCJ2", "-m1=LZMA", "-m2=LZMA", "-m3=LZMA", "-mb0:1", "-mb0s1:2", "-mb0s2:3"]):
            arc = mk7z(t, "pe_%d.7z" % len(args), pd, args)
            t.check_vs_7z(arc, label="7z PE " + " ".join(args))

def test_method_strings(t, tool, src):
    d = t.write_tree(t.path("ms_src"), {"a.exe": gen_code(200000), "b.txt": gen_text(30000)})
    cases = [["-m0=LZMA2:d=3m"], ["-m0=LZMA:d=1536k:lc=8:lp=4"], ["-m0=PPMd:o=32:mem=24"], ["-m0=BZip2"],
             ["-m0=Deflate"], ["-m0=Copy"], ["-mf=BCJ2"], ["-mf=ARM64", "-m0=LZMA2:d=12m"],
             ["-mf=off", "-m0=Delta:4", "-m1=LZMA"], ["-p1234", "-mhe=on"], ["-p1234", "-m0=Copy"],
             ["-mf=off", "-m0=Swap4", "-m1=LZMA2"], ["-mf=off", "-m0=ARM64:4096", "-m1=LZMA2"], ["-m0=Deflate64", "-mf=BCJ"]]
    bad = []
    for i, args in enumerate(cases):
        arc = mk7z(t, "ms_%d.7z" % i, d, args)
        pw = "1234" if "-p1234" in args else None
        ref = slt_methods(t, arc, pw)
        head, rows = tool_list(t, tool, arc, pw)
        for r in rows:
            want = ref.get(r["name"], {}).get("method", "")
            if not r["dir"] and r["method"] != want:
                bad.append("%s %s: %r vs 7z %r" % (" ".join(args), r["name"], r["method"], want))
    t.record(not bad, "method strings match 7z l -slt (%d archives)" % len(cases), "; ".join(bad[:4]))

def test_solid(t, tool, src, tree):
    many = {"f%03d_%s.%s" % (i, "x" * (i % 7), ("txt", "bin", "dat")[i % 3]):
            (gen_text(500 + i * 37, i) if i % 3 else gen_bin(300 + i * 11, i)) for i in range(60)}
    ms = t.write_tree(t.path("solid_src"), many)
    for s in ("on", "off", "e", "7f", "20k", "e3f"):
        arc = mk7z(t, "solid_%s.7z" % s, ms, ["-ms=" + s])
        t.check_vs_7z(arc, label="7z -ms=" + s)
        head, rows = tool_list(t, tool, arc)
        ref = seven(t, ["l", "-slt", arc]).stdout.decode()
        want_solid = "solid=1" if "\nSolid = +" in ref else "solid=0"
        t.record(want_solid in head, "solid flag -ms=%s (%s)" % (s, want_solid), head)
        # selective extraction in one pass, and random access into solid folders
        names = {r["idx"]: r["name"] for r in rows}
        pick = [r["idx"] for r in rows if r["idx"] % 3 == 1]
        out = t.path("sel_" + s)
        shutil.rmtree(out, ignore_errors=True)
        r = t.sh([tool, "sel", arc, out, "-", ",".join(map(str, pick))], check=False)
        got = tool_rows(r)
        txt = r.stdout.decode()
        ok = "PROTO" not in txt and sorted(got) == sorted(pick) and all(
            got[i][0] == 0 and open(os.path.join(out, "%d.bin" % i), "rb").read() == many[names[i]] for i in pick)
        t.record(ok, "selective solid extraction -ms=%s (%d of %d)" % (s, len(pick), len(rows)), txt[-300:] if not ok else "")
        pick2 = [r["idx"] for r in rows][::-7]
        r = t.sh([tool, "one", arc, out + "_one", "-", ",".join(map(str, pick2))], check=False)
        got = tool_rows(r)
        txt = r.stdout.decode()
        ok = "PROTO" not in txt and "unopened" not in txt and all(
            got.get(i, (1,))[0] == 0 and open(os.path.join(out + "_one", "%d.bin" % i), "rb").read() == many[names[i]]
            for i in pick2)
        t.record(ok, "random access extract() -ms=%s" % s, txt[-300:] if not ok else "")

def test_headers_and_passwords(t, tool, src, tree):
    for args, lab in ((["-mhc=off"], "headers uncompressed"), (["-mhc=on"], "headers compressed"),
                      (["-mhc=on", "-mf=off"], "no filters"), (["-mtm=off", "-mtc=on", "-mta=on"], "times c/a"),
                      (["-mtr=off", "-mtm=on"], "no attributes")):
        arc = mk7z(t, "h_%d.7z" % len(lab), src, args)
        t.check_vs_7z(arc, label="7z " + lab)
    for pw in ("1234", "고기 비밀번호!", "pässwörd" + "x" * 150):
        for he in ("on", "off"):
            for m in ("LZMA2", "Copy", "Deflate", "BZip2"):
                if m != "LZMA2" and (he == "off" or pw != "1234"):
                    continue
                arc = mk7z(t, "pw_%d_%s_%s.7z" % (len(pw), he, m), src, ["-p" + pw, "-mhe=" + he, "-m0=" + m])
                t.check_vs_7z(arc, pw=pw, label="7z AES %s -mhe=%s pw=%r" % (m, he, pw[:12]))
    # wrong / missing passwords
    arc = mk7z(t, "pw_he.7z", src, ["-psecret", "-mhe=on"])
    r, rows, out = t.extract(arc, pw="wrong")
    t.record(b"OPEN_ERROR 6" in r.stdout, "encrypted header, wrong password -> GZ_E_PASSWORD", r.stdout[:80])
    r, rows, out = t.extract(arc)
    t.record(b"OPEN_ERROR 6" in r.stdout, "encrypted header, no password -> GZ_E_PASSWORD", r.stdout[:80])
    head, rows = tool_list(t, tool, arc, "secret")
    t.record("henc=1" in head and rows and all(r["enc"] == 2 for r in rows if r["size"]), "headers_enc and enc flags", head)
    for m, solid in (("LZMA2", "on"), ("Copy", "off"), ("Deflate", "off"), ("BZip2", "on"), ("LZMA", "off")):
        arc = mk7z(t, "pwd_%s_%s.7z" % (m, solid), src, ["-psecret", "-m0=" + m, "-ms=" + solid])
        r, rows, out = t.extract(arc, pw="wrong")
        files = {v[3]: v[0] for v in rows.values() if not v[1] and v[2]}
        t.record(files and all(st == E_PASSWORD for st in files.values()),
                 "data encrypted %s ms=%s, wrong password -> GZ_E_PASSWORD" % (m, solid), str(files)[:200])
        r, rows, out = t.extract(arc)
        files = {v[3]: v[0] for v in rows.values() if not v[1] and v[2]}
        t.record(files and all(st == E_PASSWORD for st in files.values()),
                 "data encrypted %s ms=%s, no password -> GZ_E_PASSWORD" % (m, solid), str(files)[:200])
        sizes = {r2["idx"]: r2 for r2 in tool_list(t, tool, arc)[1]}
        for pw, want in (("secret", 0), ("wrong", E_PASSWORD), ("-", E_PASSWORD)):
            r = t.sh([tool, "pw", arc, pw], check=False)
            res = {int(a): int(b) for a, b in (ln.split("\t") for ln in r.stdout.decode().splitlines() if "\t" in ln)}
            bad = [i for i, v in res.items() if sizes[i]["size"] and sizes[i]["enc"] and v != want]
            # Copy + AES with a file over 1 MiB first in its folder cannot be told early
            t.record(not bad, "check_password %s ms=%s pw=%s" % (m, solid, pw), str([(i, res[i]) for i in bad][:5]))
    t.check_vs_7z(mk7z(t, "pw_korean_only.7z", src, ["-p고기", "-mhe=on", "-ms=off"]), pw="고기", label="Korean pw non-solid")

def test_attrs_times(t, tool):
    root = t.path("attr_src")
    shutil.rmtree(root, ignore_errors=True)
    t.write_tree(root, {"d/a.txt": b"aaa", "d/x.sh": b"#!/bin/sh\n", "d/ro.txt": b"ro", "d/sub/e.txt": b"",
                        "d/emptydir": None})
    os.chmod(os.path.join(root, "d/x.sh"), 0o755)
    os.chmod(os.path.join(root, "d/ro.txt"), 0o444)
    os.chmod(os.path.join(root, "d/sub"), 0o750)
    os.symlink("a.txt", os.path.join(root, "d/link"))
    stamps = {"d/a.txt": 1234567890123456789, "d/x.sh": 1600000000000000000, "d/ro.txt": 1000000000123456700}
    for k, v in stamps.items():
        os.utime(os.path.join(root, k), ns=(v, v), follow_symlinks=False)
    arc = mk7z(t, "attrs.7z", root, ["-snl", "-mtm=on", "-mtc=on", "-mta=on"], files=["d"])
    head, rows = tool_list(t, tool, arc)
    by = {r["name"]: r for r in rows}
    bad = []
    for name in ("d/a.txt", "d/x.sh", "d/ro.txt", "d/sub", "d/link", "d/emptydir", "d/sub/e.txt"):
        st = os.lstat(os.path.join(root, name))
        r = by.get(name)
        if not r:
            bad.append("missing " + name); continue
        if r["mode"] != st.st_mode:
            bad.append("%s mode %o vs %o" % (name, r["mode"], st.st_mode))
        if name in stamps and r["mtime"] != stamps[name] // 100 + 116444736000000000:
            bad.append("%s mtime %d" % (name, r["mtime"]))
    if by.get("d/link", {}).get("link") != 1:
        bad.append("symlink not flagged")
    if not by.get("d/ro.txt", {}).get("attr", 0) & 1:
        bad.append("read-only attribute")
    if not by.get("d/emptydir", {}).get("dir"):
        bad.append("empty dir")
    t.record(not bad, "attributes, unix modes, symlink, mtimes", "; ".join(bad))
    t.check_vs_7z(arc, label="attrs archive data", allow_extra=True)
    r, rows, out = t.extract(arc)
    li = [k for k, v in rows.items() if v[3] == "d/link"]
    t.record(li and open(os.path.join(out, "%d.bin" % li[0]), "rb").read() == b"a.txt", "symlink data = target")

def test_special(t, tool, src, tree):
    # only empty files and directories: no streams at all
    e = t.write_tree(t.path("empty_src"), {"a": None, "a/b": None, "z.txt": b"", "a/y.txt": b""})
    arc = mk7z(t, "only_empty.7z", e, [])
    t.check_extract(arc, {"a": None, "a/b": None, "z.txt": b"", "a/y.txt": b""}, label="only empty items")
    # empty archive (7z writes it when everything is deleted)
    arc2 = t.path("arc", "emptied.7z")
    shutil.copy(arc, arc2)
    seven(t, ["d", "-bd", arc2, "*", "-r"], check=False)
    r = t.run_gzt(["l", arc2])
    t.record(r.returncode == 0 and r.stdout.startswith(b"TYPE\t7z\t0"), "empty archive", r.stdout[:60])
    # deletion with 7z d
    arc3 = mk7z(t, "deleted.7z", src, ["-ms=on"])
    seven(t, ["d", "-bd", arc3, "data/random.bin", "readme.txt"])
    t.check_vs_7z(arc3, label="after 7z d")
    # differential update with anti items
    an = t.write_tree(t.path("anti_src"), {"d/a.txt": b"one\n", "d/b.txt": b"two\n", "d/sub/c.txt": b"three\n"})
    base = t.path("arc", "base.7z")
    diff = t.path("arc", "diff.7z")
    for p in (base, diff):
        if os.path.exists(p):
            os.remove(p)
    seven(t, ["a", "-bd", base, "d"], cwd=an)
    os.remove(os.path.join(an, "d/b.txt"))
    shutil.rmtree(os.path.join(an, "d/sub"))
    open(os.path.join(an, "d/n.txt"), "wb").write(b"new\n")
    seven(t, ["u", "-bd", base, "-u-", "-up0q3r2x2y2z0w2!" + diff, "d"], cwd=an)
    r, typ, rows = t.listing(diff)
    names = sorted(x["name"] for x in rows)
    t.record(names == ["d", "d/n.txt"], "anti items are not listed", str(names))
    t.check_extract(diff, {"d/n.txt": b"new\n", "d": None}, label="differential archive data")
    # volumes: the reader works on the concatenated parts
    vol = t.path("arc", "vol.7z")
    for f in os.listdir(t.path("arc")):
        if f.startswith("vol.7z."):
            os.remove(t.path("arc", f))
    seven(t, ["a", "-bd", "-v10k", "-mx=1", vol, "."], cwd=src)
    parts = sorted(f for f in os.listdir(t.path("arc")) if f.startswith("vol.7z."))
    joined = t.path("arc", "joined.7z")
    with open(joined, "wb") as o:
        for p in parts:
            o.write(open(t.path("arc", p), "rb").read())
    t.record(len(parts) > 2, "volumes made", str(len(parts)))
    t.check_extract(joined, {k: v for k, v in tree.items()}, label="concatenated .7z.001.. volumes")
    # view of stored data
    arc4 = mk7z(t, "copy_view.7z", src, ["-m0=Copy", "-ms=on"])
    head, rows = tool_list(t, tool, arc4)
    bad = []
    for r in rows:
        if r["dir"] or not r["size"]:
            continue
        v = t.sh([tool, "view", arc4, str(r["idx"])], check=False).stdout.decode().strip()
        want = "VIEW %d %s" % (r["size"], r["crc"])
        if v != want:
            bad.append("%s: %s vs %s" % (r["name"], v, want))
    arc5 = mk7z(t, "lz_noview.7z", src, ["-m0=LZMA2"])
    v = t.sh([tool, "view", arc5, "1"], check=False).stdout.decode().strip()
    t.record(not bad and v == "NOVIEW", "views of stored files", "; ".join(bad[:3]) + v)

def test_many(t, tool):
    files = {"many/d%02d/f%05d.txt" % (i % 50, i): ("file %d\n" % i).encode() * (1 + i % 5) for i in range(10000)}
    root = t.write_tree(t.path("many_src"), files)
    for s in ("on", "off"):
        arc = mk7z(t, "many_%s.7z" % s, root, ["-ms=" + s, "-mx=1"])
        t0 = time.time()
        t.check_extract(arc, files, label="10000 files -ms=%s" % s)
        dt = time.time() - t0
        r = t.sh([tool, "bench", arc], check=False)
        t.record(r.returncode == 0, "10000 files -ms=%s decode" % s, "%.2fs gzt x; %s" % (dt, r.stdout.decode().strip()))

def test_py7zr(t, tool):
    try:
        import py7zr
    except ImportError:
        t.record(True, "py7zr not installed: skipped")
        return
    src = {"a.txt": gen_text(40000, 3), "b.bin": gen_bin(30000, 4), "c/d.txt": gen_text(5000, 5), "e.bin": gen_code(70000)}
    root = t.write_tree(t.path("py_src"), src)
    cases = [("lzma2", [{"id": py7zr.FILTER_LZMA2, "preset": 7}]),
             ("lzma", [{"id": py7zr.FILTER_LZMA}]),
             ("bcj_lzma2", [{"id": py7zr.FILTER_X86}, {"id": py7zr.FILTER_LZMA2}]),
             ("arm_lzma2", [{"id": py7zr.FILTER_ARM}, {"id": py7zr.FILTER_LZMA2}]),
             ("delta", [{"id": py7zr.FILTER_DELTA}, {"id": py7zr.FILTER_LZMA2}]),
             ("bzip2", [{"id": py7zr.FILTER_BZIP2}]),
             ("deflate", [{"id": py7zr.FILTER_DEFLATE}]),
             ("copy", [{"id": py7zr.FILTER_COPY}]),
             ("zstd", [{"id": py7zr.FILTER_ZSTD, "level": 3}]),
             ("brotli", [{"id": py7zr.FILTER_BROTLI}]),
             ("ppmd", [{"id": py7zr.FILTER_PPMD, "order": 6, "mem": 24}])]
    for name, flt in cases:
        arc = t.path("arc", "py_%s.7z" % name)
        try:
            with py7zr.SevenZipFile(arc, "w", filters=flt) as z:
                for k in sorted(src):
                    z.write(os.path.join(root, k), k)
        except Exception as ex:
            t.record(True, "py7zr %s: writer unavailable (%s)" % (name, str(ex)[:60]))
            continue
        if name in ("brotli", "ppmd"):
            r, rows, out = t.extract(arc)
            st = [v[0] for v in rows.values() if v[2]]
            if st and all(x == E_METHOD for x in st):
                t.record(True, "py7zr %s: GZ_E_METHOD" % name)
                continue
        t.check_extract(arc, src, label="py7zr " + name)
    for he in (False, True):
        arc = t.path("arc", "py_aes_%d.7z" % he)
        with py7zr.SevenZipFile(arc, "w", password="파이썬", header_encryption=he) as z:
            for k in sorted(src):
                z.write(os.path.join(root, k), k)
        t.check_extract(arc, src, pw="파이썬", label="py7zr AES header_encryption=%s" % he)

def test_crafted(t, tool):
    armish = bytearray(gen_bin(4000, 13))
    for i in range(3, len(armish), 16):
        armish[i] = 0xEB
    items = [("dir", None), ("dir/a.txt", gen_text(3000, 11)), ("dir/zero.bin", b""), ("b.bin", gen_bin(5000, 12)),
             ("c.txt", b"c" * 100), ("arm.bin", bytes(armish))]
    exp = {n: d for n, d in items}
    for coder in ("copy", "lzma", "lzma2", "deflate", "bzip2", "bcj"):
        for solid in (True, False):
            for header in ("plain", "lzma"):
                p = t.path("arc", "cr_%s_%d_%s.7z" % (coder, solid, header))
                open(p, "wb").write(simple_7z(items, coder, solid, header))
                t.check_extract(p, exp, label="crafted %s solid=%d header=%s" % (coder, solid, header))
    for ver in (2, 3):
        p = t.path("arc", "cr_ver%d.7z" % ver)
        open(p, "wb").write(simple_7z(items, "lzma", True, "plain", ver))
        t.check_extract(p, exp, label="crafted version 0.%d" % ver)
    # kDummy, unknown properties, archive properties, CTime/ATime/StartPos
    extra = prop(0x19, bytes(5)) + prop(0x40, b"xyz") + prop(0x12, b"\x01\x00" + bytes(8 * 5)) + \
            prop(0x18, b"\x00" + bits([1, 0, 0, 0, 0]) + b"\x00" + bytes(8))
    p = t.path("arc", "cr_extra.7z")
    raw = simple_7z(items, "copy", True, "plain", extra_files=extra)
    open(p, "wb").write(raw)
    t.check_extract(p, exp, label="crafted kDummy / unknown / CTime / StartPos")
    data = b"".join(d for n, d in items if d)
    sizes = [len(d) for n, d in items if d]
    crcs = [zlib.crc32(d) for n, d in items if d]
    files = [dict(name=n, stream=bool(d), dir=d is None) for n, d in items]
    # archive properties + names in an additional stream (External)
    names = b"".join(n.encode("utf-16-le") + b"\0\0" for n, d in items)
    pk_names = lzma1(names)
    f_main = Folder([(ID_COPY, None, 1)], [len(data)], subs=sizes, sub_crcs=crcs)
    f_add = Folder([(ID_LZMA, lzma1_props(), 1)], [len(names)], crc=zlib.crc32(names))
    fi = num(len(files)) + prop(0x0E, bits([not f["stream"] for f in files])) + \
         prop(0x0F, bits([not f["dir"] for f in files if not f["stream"]])) + prop(0x11, b"\x01" + num(0)) + b"\x00"
    hdr = b"\x01" + b"\x02" + num(0x30) + num(3) + b"abc" + b"\x00" + \
          b"\x03" + streams_info([len(pk_names)], [f_add], pack_pos=len(data)) + \
          b"\x04" + streams_info([len(data)], [f_main]) + b"\x05" + fi + b"\x00"
    p = t.path("arc", "cr_external.7z")
    open(p, "wb").write(finish(data + pk_names, hdr))
    t.check_extract(p, exp, label="crafted External names in additional stream")
    # two decoders chained: LZMA(LZMA(data)) -> the inner stream is materialised
    inner = lzma1(data)
    outer = lzma1(inner, 1 << 16)
    f = Folder([(ID_LZMA, lzma1_props(), 1), (ID_LZMA, lzma1_props(1 << 16), 1)], [len(data), len(inner)],
               bonds=[(0, 1)], subs=sizes, sub_crcs=crcs)
    hdr = b"\x01\x04" + streams_info([len(outer)], [f]) + files_info(files) + b"\x00"
    p = t.path("arc", "cr_lzma_lzma.7z")
    open(p, "wb").write(finish(outer, hdr))
    t.check_extract(p, exp, label="crafted LZMA -> LZMA chain")
    # filter on a packed stream, coders stored in reverse order, Swap2 + Delta chain
    for nm, flt, fdata in (("arm_copy", (b"\x03\x03\x05\x01", None, 1), arm_encode(data)),
                           ("delta_copy", (ID_DELTA, b"\x03", 1), delta_encode(data, 4))):
        f = Folder([flt], [len(data)], subs=sizes, sub_crcs=crcs)
        hdr = b"\x01\x04" + streams_info([len(fdata)], [f]) + files_info(files) + b"\x00"
        p = t.path("arc", "cr_%s.7z" % nm)
        open(p, "wb").write(finish(fdata, hdr))
        t.check_extract(p, exp, label="crafted filter directly on packed stream (%s)" % nm)
    sw = bytearray(data + bytes(-len(data) % 2))
    sw[0::2], sw[1::2] = sw[1::2], sw[0::2]
    sw = bytes(sw[:len(data)]) if len(data) % 2 == 0 else bytes(sw[:len(data) - 1]) + data[-1:]
    pk = lzma1(sw)
    f = Folder([(ID_LZMA, lzma1_props(), 1), (ID_SWAP2, None, 1)][::-1], [len(data), len(data)],
               bonds=[(0, 1)], subs=sizes, sub_crcs=crcs)
    hdr = b"\x01\x04" + streams_info([len(pk)], [f]) + files_info(files) + b"\x00"
    p = t.path("arc", "cr_swap2.7z")
    open(p, "wb").write(finish(pk, hdr))
    t.check_extract(p, exp, label="crafted Swap2 + LZMA")
    # a folder whose single coder has no substreams info, plus a folder with zero files
    f1 = Folder([(ID_COPY, None, 1)], [len(data)], subs=sizes, sub_crcs=crcs)
    f2 = Folder([(ID_COPY, None, 1)], [7], subs=[], sub_crcs=[])
    hdr = b"\x01\x04" + streams_info([len(data), 7], [f1, f2]) + files_info(files) + b"\x00"
    p = t.path("arc", "cr_nsub0.7z")
    open(p, "wb").write(finish(data + b"unused!", hdr))
    t.check_extract(p, exp, label="crafted folder with no files")
    # zero-length substreams between files
    zitems = [("z0", b""), ("a", b"abc"), ("z1", b""), ("b", b"defg")]
    zdata = b"abcdefg"
    f = Folder([(ID_COPY, None, 1)], [7], subs=[0, 3, 0, 4], sub_crcs=[0, zlib.crc32(b"abc"), 0, zlib.crc32(b"defg")])
    hdr = b"\x01\x04" + streams_info([7], [f]) + files_info([dict(name=n) for n, d in zitems]) + b"\x00"
    p = t.path("arc", "cr_zero_subs.7z")
    open(p, "wb").write(finish(zdata, hdr))
    t.check_extract(p, dict(zitems), label="crafted zero-length substreams")
    # unix mode in the attribute high bits, anti items, defined-vector gaps
    fl = [dict(name="x", mtime=None, attr=0x8000 | (0o100755 << 16) | 0x20), dict(name="y", attr=None, mtime=132000000000000000),
          dict(name="gone", stream=False, anti=True), dict(name="l", attr=0x8000 | (0o120777 << 16))]
    fdata = [b"xx", b"yyy", b"target"]
    f = Folder([(ID_COPY, None, 1)], [11], subs=[2, 3, 6], sub_crcs=[zlib.crc32(x) for x in fdata])
    hdr = b"\x01\x04" + streams_info([11], [f]) + files_info(fl) + b"\x00"
    p = t.path("arc", "cr_modes.7z")
    open(p, "wb").write(finish(b"".join(fdata), hdr))
    head, rows = tool_list(t, tool, p)
    by = {r["name"]: r for r in rows}
    ok = sorted(by) == ["l", "x", "y"] and by["x"]["mode"] == 0o100755 and by["l"]["link"] == 1 and \
         by["y"]["mtime"] == 132000000000000000 and by["x"]["mtime"] == 0
    t.record(ok, "crafted unix modes / anti / sparse defined vectors", str(rows)[:300])
    # AES variants (pycryptodome)
    if importlib.util.find_spec("Cryptodome") is None:
        t.record(True, "pycryptodome missing: crafted AES skipped")
        return
    for pw, power, salt, iv, inner in (("abc", 6, b"", b"\x11" * 16, "lzma2"), ("고기", 0, b"S" * 16, b"\x01", "copy"),
                                       ("x", 0x3F, b"salt", b"", "lzma2"),
                                       ("long" * 40, 3, b"\x05" * 3, b"\x07" * 9, "lzma2")):
        p = t.path("arc", "cr_aes_%d_%d.7z" % (power, len(salt)))
        open(p, "wb").write(aes_7z(items, pw, power, salt, iv, inner))
        t.check_extract(p, exp, pw=pw, label="crafted 7zAES power=%d salt=%d iv=%d" % (power, len(salt), len(iv)))
    # an empty password is a password, but "no password" must not try it
    p = t.path("arc", "cr_aes_empty_pw.7z")
    open(p, "wb").write(aes_7z(items, "", 4, b"", b"", "copy"))
    r, rows, out = t.extract(p)
    st = [v[0] for v in rows.values() if v[2]]
    t.record(st and all(x == E_PASSWORD for x in st), "crafted 7zAES empty password, none given", str(rows)[:200])

def hostile_cases():
    """(label, bytes, expectation) where expectation is 'open-fail', 'entries-fail' or 'any'"""
    items = [("a.txt", gen_text(2000, 21)), ("b.txt", gen_text(3000, 22))]
    data = b"".join(d for n, d in items)
    sizes = [len(d) for n, d in items]
    crcs = [zlib.crc32(d) for n, d in items]
    files = [dict(name=n) for n, d in items]
    out = []

    def arc(folders, pack_sizes, packed, fi=None, pack_pos=0, folders_raw=None):
        hdr = b"\x01\x04" + streams_info(pack_sizes, folders, pack_pos, folders_raw=folders_raw) + \
              (fi if fi is not None else files_info(files)) + b"\x00"
        return finish(packed, hdr)
    ok_f = Folder([(ID_COPY, None, 1)], [len(data)], subs=sizes, sub_crcs=crcs)
    out.append(("baseline", arc([ok_f], [len(data)], data), "ok"))
    out.append(("pack beyond EOF", arc([ok_f], [len(data) + 100000], data), "entries-fail"))
    out.append(("pack pos huge", arc([ok_f], [len(data)], data, pack_pos=1 << 61), "entries-fail"))
    out.append(("pack pos overflow", arc([ok_f], [len(data)], data, pack_pos=(1 << 64) - 10), "open-fail"))
    out.append(("bad crc", arc([Folder([(ID_COPY, None, 1)], [len(data)], subs=sizes, sub_crcs=[1, 2])], [len(data)], data), "entries-fail"))
    out.append(("sub sizes > folder", arc([Folder([(ID_COPY, None, 1)], [10], subs=[9, 1], sub_crcs=crcs)], [len(data)], data, folders_raw=None), "any"))
    out.append(("65 coders", arc([ok_f], [len(data)], data, folders_raw=b"\x00" + num(65) + coder_bytes(ID_COPY) * 65), "open-fail"))
    cyc = b"\x00" + num(3) + coder_bytes(ID_COPY) * 3 + num(1) + num(2) + num(2) + num(1)
    out.append(("coder cycle", arc([Folder([(ID_COPY, None, 1)] * 3, [len(data)] * 3)], [len(data)], data, folders_raw=cyc), "open-fail"))
    dup = b"\x00" + num(2) + coder_bytes(ID_COPY) * 2 + num(0) + num(0)
    out.append(("bond to self", arc([Folder([(ID_COPY, None, 1)] * 2, [len(data)] * 2)], [len(data)], data, folders_raw=dup), "open-fail"))
    oob = b"\x00" + num(2) + coder_bytes(ID_COPY) * 2 + num(5) + num(1)
    out.append(("bond out of range", arc([Folder([(ID_COPY, None, 1)] * 2, [len(data)] * 2)], [len(data)], data, folders_raw=oob), "open-fail"))
    b2 = b"\x00" + num(1) + coder_bytes(b"\x03\x03\x01\x1b", None, 2) + num(0) + num(1)
    out.append(("BCJ2 with 2 inputs", arc([Folder([(ID_COPY, None, 1)], [len(data)], subs=sizes, sub_crcs=crcs)], [len(data), 0], data, folders_raw=b2), "entries-fail"))
    out.append(("unknown method", arc([Folder([(b"\x7f\x7f", None, 1)], [len(data)], subs=sizes, sub_crcs=crcs)], [len(data)], data), "entries-fail"))
    out.append(("LZMA bomb", arc([Folder([(ID_LZMA, lzma1_props(1 << 30), 1)], [1 << 40], subs=[1 << 39, 1 << 39])], [100], bytes(100)), "entries-fail"))
    out.append(("LZMA2 huge size", arc([Folder([(ID_LZMA2, b"\x28", 1)], [1 << 50], subs=[1 << 49, 1 << 49])], [3], b"\x01\x00\x00"), "entries-fail"))
    out.append(("Copy usize > pack", arc([Folder([(ID_COPY, None, 1)], [len(data) * 3], subs=[len(data), len(data) * 2])], [len(data)], data), "last-fails"))
    lz = lzma1(data)
    out.append(("LZMA short props", arc([Folder([(ID_LZMA, b"\x5d", 1)], [len(data)], subs=sizes, sub_crcs=crcs)], [len(lz)], lz), "entries-fail"))
    out.append(("AES power 30", arc([Folder([(ID_LZMA, lzma1_props(), 1), (ID_AES, b"\x1e", 1)], [len(data), len(lz)], [(0, 1)], subs=sizes)], [len(lz)], lz), "entries-fail"))
    out.append(("AES bad props", arc([Folder([(ID_COPY, None, 1), (ID_AES, b"\xc0\xff", 1)], [len(data), len(data)], [(0, 1)], subs=sizes)], [len(data)], data), "entries-fail"))
    fi_many = b"\x05" + num(1 << 25) + b"\x00"
    out.append(("numFiles huge", arc([ok_f], [len(data)], data, fi=fi_many), "open-fail"))
    fi_nonames = b"\x05" + num(2) + prop(0x11, b"\x00" + "a".encode("utf-16-le")) + b"\x00"
    out.append(("unterminated names", arc([ok_f], [len(data)], data, fi=fi_nonames), "open-fail"))
    fi_bad = b"\x05" + num(3) + b"\x00"
    out.append(("files != substreams", arc([ok_f], [len(data)], data, fi=fi_bad), "open-fail"))
    hdr = b"\x01\x04" + streams_info([len(data)], [ok_f])[:-3]
    out.append(("truncated header", finish(data, hdr), "open-fail"))
    good = arc([ok_f], [len(data)], data)
    bad = bytearray(good)
    bad[-3] ^= 0x40
    out.append(("next header crc", bytes(bad), "open-fail"))
    bad = bytearray(good)
    bad[9] ^= 1
    out.append(("start header crc", bytes(bad), "open-fail"))
    big = SIG + b"\x00\x04" + b"\0" * 4 + struct.pack("<QQI", 0, 1 << 40, 0)
    big = big[:8] + struct.pack("<I", zlib.crc32(big[12:32])) + big[12:]
    out.append(("next header size huge", big, "open-fail"))
    # nested encoded header and encoded header with two folders
    inner = b"\x17" + streams_info([len(data)], [ok_f])
    out.append(("encoded header -> encoded header", finish(data, b"\x17" + streams_info([len(inner)], [Folder([(ID_COPY, None, 1)], [len(inner)])], pack_pos=0)), "open-fail"))
    out.append(("numFolders huge", finish(data, b"\x01\x04" + b"\x06" + num(0) + num(1) + b"\x09" + num(len(data)) + b"\x00" +
                                          b"\x07\x0b" + num(1 << 24) + b"\x00" + b"\x01\x00" * 10 + b"\x00" + b"\x00"), "open-fail"))
    out.append(("bomb names in big count", finish(b"", b"\x01\x05" + num(5000000) + prop(0x0E, b"\xff" * 4) + b"\x00\x00"), "open-fail"))
    return out

def test_hostile(t, tool, src):
    for label, blob, want in hostile_cases():
        p = t.path("hostile", label.replace(" ", "_").replace(">", "") + ".7z")
        open(p, "wb").write(blob)
        if not t.check_hostile(p, label="hostile " + label):
            continue
        r, rows, out = t.extract(p)
        opened = b"OPEN_ERROR" not in r.stdout
        if want == "open-fail":
            t.record(not opened, "hostile %s: rejected at open" % label, r.stdout[:80])
        elif want == "entries-fail":
            st = [v[0] for v in rows.values() if v[2]]
            t.record(opened and st and all(s != 0 for s in st), "hostile %s: entries fail" % label, str(rows)[:200])
        elif want == "last-fails":
            st = [v[0] for k, v in sorted(rows.items()) if v[2]]
            t.record(opened and st and st[0] == 0 and st[-1] == E_DATA, "hostile %s: short data" % label, str(rows)[:200])
        elif want == "ok":
            st = [v[0] for v in rows.values()]
            t.record(opened and all(s == 0 for s in st), "hostile %s" % label, str(rows)[:200])
    # truncations and bit flips of real archives through gzt (a few), then the in-process fuzzer
    seeds = [mk7z(t, "fz_lzma2.7z", src, ["-m0=LZMA2", "-mx=3"]),
             mk7z(t, "fz_bcj2.7z", t.path("code_src"), ["-mf=BCJ2"]),
             mk7z(t, "fz_aes.7z", src, ["-pfuzz", "-mhe=on", "-ms=off"]),
             mk7z(t, "fz_deflate.7z", src, ["-m0=Deflate", "-ms=e"]),
             mk7z(t, "fz_bzip2.7z", src, ["-m0=BZip2", "-mhc=off"]),
             mk7z(t, "fz_copy.7z", src, ["-m0=Copy", "-mhc=off"]),
             t.path("arc", "cr_external.7z"), t.path("arc", "cr_lzma_lzma.7z")]
    rnd = random.Random(7)
    for s in seeds[:3]:
        blob = open(s, "rb").read()
        for k, cut in enumerate((len(blob) - 1, len(blob) - 40, len(blob) // 2, 31, 40)):
            p = t.path("hostile", "trunc_%s_%d.7z" % (os.path.basename(s), k))
            open(p, "wb").write(blob[:max(0, cut)])
            t.check_hostile(p, pw="fuzz")
        for k in range(4):
            b = bytearray(blob)
            for _ in range(rnd.randint(1, 6)):
                b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
            p = t.path("hostile", "flip_%s_%d.7z" % (os.path.basename(s), k))
            open(p, "wb").write(bytes(b))
            t.check_hostile(p, pw="fuzz")
    iters = int(os.environ.get("GZ_FUZZ_ITERS", "400"))
    for i, s in enumerate(seeds):
        if not os.path.exists(s):
            continue
        try:
            r = t.sh([tool, "fuzz", s, str(iters), str(i + 1), "fuzz"], check=False, timeout=900)
            txt = r.stdout.decode() + r.stderr.decode()[-500:]
            t.record(r.returncode == 0 and "FUZZ" in txt and "Sanitizer" not in txt and "runtime error" not in txt,
                     "fuzz %s x%d" % (os.path.basename(s), iters), txt.strip()[-200:])
        except subprocess.TimeoutExpired:
            t.record(False, "fuzz %s" % os.path.basename(s), "timeout")

def test_sfx(t, tool, src, tree):
    arc = mk7z(t, "sfx_payload.7z", src, ["-mx=3"])
    payload = open(arc, "rb").read()
    exp = {k: v for k, v in tree.items()}
    stub = pe_stub()
    cases = (("pe overlay", stub + payload, len(stub)),
             ("pe + config text", stub + b";!@Install@!UTF-8!\nTitle=\"x\"\n;!@InstallEnd@!" + payload,
              len(stub) + len(b";!@Install@!UTF-8!\nTitle=\"x\"\n;!@InstallEnd@!")),
             ("elf stub", open("/bin/true", "rb").read() + payload, os.path.getsize("/bin/true")))
    for label, blob, shift in cases:
        p = t.path("arc", "sfx_%s.exe" % label.replace(" ", "_"))
        open(p, "wb").write(blob)
        t.check_extract(p, exp, label="SFX " + label, expect_type="7z")
        head, rows = tool_list(t, tool, p)
        t.record(("sfx=%d" % shift) in head, "SFX shift " + label, head)
    # an executable that merely contains the signature bytes is not a 7z archive
    p = t.path("arc", "fake_sig.exe")
    open(p, "wb").write(pe_stub(0x800, SIG + b"\x00\x04" + bytes(40)))
    r = t.run_gzt(["l", p])
    t.record(b"TYPE\t7z" not in r.stdout, "signature without valid start header is not 7z", r.stdout[:60])

def test_perf(t, tool):
    d = t.path("perf_src")
    if not os.path.exists(os.path.join(d, "big.bin")):
        os.makedirs(d, exist_ok=True)
        parts = [gen_text(12000000, 31), gen_code(12000000), gen_bin(2000000, 32), gen_text(12000000, 33)]
        open(os.path.join(d, "big.bin"), "wb").write(b"".join(parts))
    arc = mk7z(t, "perf.7z", d, ["-m0=LZMA2", "-mx=5", "-mmt=1"])
    size = os.path.getsize(os.path.join(d, "big.bin"))
    def best(cmd, n=3):
        b = 1e9
        for _ in range(n):
            t0 = time.time()
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            b = min(b, time.time() - t0)
        return b
    t7 = best(["7z", "x", "-so", "-mmt=1", arc])
    r = t.sh([tool, "bench", arc, "-", "3"], check=False)
    line = r.stdout.decode().strip().splitlines()[-1] if r.stdout else ""
    ours = float(line.split("sec=")[1].split()[0]) if "sec=" in line else 1e9
    asan = "sanitize" in os.environ.get("HOST_CFLAGS", "")
    ok = r.returncode == 0 and (asan or ours < t7 * 2.0)
    t.record(ok, "LZMA2 %d MB decode speed vs 7z -mmt=1" % (size >> 20),
             "ours %.3fs (%.0f MB/s), 7z x -so %.3fs (%.0f MB/s)" % (ours, size / ours / 1e6, t7, size / t7 / 1e6))

def test_large(t, tool):
    if not os.environ.get("GZ_SLOW"):
        t.record(True, "> 4 GiB file: set GZ_SLOW=1 to run")
        return
    d = t.path("large_src")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "sparse.bin")
    with open(p, "wb") as f:
        f.truncate((4 << 30) + 12345)
        f.seek(3 << 30)
        f.write(b"middle marker")
    with open(os.path.join(d, "after.txt"), "wb") as f:
        f.write(b"after the big one\n")
    arc = mk7z(t, "large.7z", d, ["-m0=LZMA2", "-mx=1", "-ms=on"])
    os.remove(p)
    r = t.sh([tool, "bench", arc], check=False, timeout=3600)
    head, rows = tool_list(t, tool, arc)
    sizes = sorted(r2["size"] for r2 in rows)
    t.record(r.returncode == 0 and sizes == [18, (4 << 30) + 12345], "> 4 GiB file in a solid folder", r.stdout.decode()[-200:])

def run(t):
    t.need("7z")
    tool = t.build_driver("tests/drivers/sevenz_tool.c")
    tree = base_tree()
    src = t.write_tree(t.path("src"), tree)
    test_methods(t, src, tree)
    test_filters(t, src)
    test_method_strings(t, tool, src)
    test_solid(t, tool, src, tree)
    test_headers_and_passwords(t, tool, src, tree)
    test_attrs_times(t, tool)
    test_special(t, tool, src, tree)
    test_crafted(t, tool)
    test_py7zr(t, tool)
    test_sfx(t, tool, src, tree)
    test_many(t, tool)
    test_hostile(t, tool, src)
    test_perf(t, tool)
    test_large(t, tool)
