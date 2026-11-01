"""FAT12/16/32, exFAT and ext2/3/4 images: names (VFAT/8.3/UTF-16), layout variants
(fragmented chains, NoFatChain, extents, indirect blocks, inline data, htree, meta_bg),
metadata, random-access views, nested archives, hostile images."""
import os, io, mmap, random, shutil, struct, subprocess, zlib, zipfile, calendar

ENV = dict(os.environ, LANG="C.UTF-8", LC_ALL="C.UTF-8", TZ="UTC", MTOOLS_SKIP_CHECK="1")
FT_EPOCH = 11644473600

def blob(n, seed=1, text=False):
    rnd = random.Random(seed * 7919 + n)
    if not text:
        return rnd.randbytes(n)
    words = [b"\xea\xb3\xa0\xea\xb8\xb0", b"meat", b"grill", b"zip", b"fs", b"\n", b"cluster", b"inode"]
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(words) + b" "
    return bytes(out[:n])

def ft_of(unix, ns=0):
    return (unix + FT_EPOCH) * 10000000 + ns // 100

def dos_of(y, mo, d, h, mi, s):
    return ((y - 1980) << 25) | (mo << 21) | (d << 16) | (h << 11) | (mi << 5) | (s // 2)

def with_dirs(files):
    """{path: bytes} plus every parent directory as None"""
    out = dict(files)
    for k in files:
        parts = k.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            out.setdefault("/".join(parts[:i]), None)
    return out

def make_tree(root, files, mtime=None):
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    for k, v in sorted(files.items()):
        p = os.path.join(root, k)
        if v is None:
            os.makedirs(p, exist_ok=True)
        else:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(v)
            if mtime is not None:
                os.utime(p, (mtime, mtime))
    return root

# ---------------------------------------------------------------- driver helpers

def dump(t, drv, img, env=None):
    r = subprocess.run([drv, "l", img], capture_output=True, env=env, timeout=300)
    rows, typ, comment = {}, None, None
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        p = line.split("\t")
        if p[0] == "TYPE":
            typ = p[1]
        elif p[0] == "COMMENT":
            comment = p[1]
        elif len(p) >= 13 and p[0].isdigit():
            name, link = p[12], None
            if " -> " in name:
                name, link = name.split(" -> ", 1)
            rows[name] = dict(idx=int(p[0]), is_dir=int(p[1]), is_link=int(p[2]), usize=int(p[3]),
                              csize=int(p[4]), mk=int(p[5]), mtime=int(p[6]), attr=int(p[7]),
                              mode=int(p[8], 8), aux=int(p[9]), aux32=int(p[10]), flags=int(p[11]), link=link)
    return r, typ, comment, rows

def check_views(t, drv, img, label, expect_view=True, timeout=600):
    """extraction CRC == CRC of the random-access view read in shuffled chunks"""
    r = subprocess.run([drv, "v", img], capture_output=True, timeout=timeout)
    bad, n = [], 0
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        p = line.split("\t")
        if len(p) < 9 or not p[0].isdigit():
            continue
        n += 1
        st, size, crcx, kind, vs, crcv, err, name = int(p[1]), int(p[2]), p[3], p[4], int(p[5]), p[6], int(p[7]), p[8]
        if st:
            bad.append("%s: extract %d" % (name, st))
        elif kind != "view":
            if expect_view:
                bad.append("%s: no view" % name)
        elif vs != size or crcv != crcx or err:
            bad.append("%s: view size %d/%d crc %s/%s err %d" % (name, vs, size, crcv, crcx, err))
    return t.record(r.returncode == 0 and n and not bad, label, "; ".join(bad[:5]) or "%d files" % n)

def check_nested(t, drv, img, name, inner, label):
    """open a zip stored in the file system through its view (no temp file)"""
    r = subprocess.run([drv, "n", img, name], capture_output=True, timeout=120)
    out = r.stdout.decode("utf-8", "replace").splitlines()
    got = {}
    for line in out[1:]:
        p = line.split("\t")
        if len(p) == 5:
            got[p[4]] = (int(p[1]), int(p[2]), p[3])
    want = {k: (0, len(v), "%08x" % zlib.crc32(v)) for k, v in inner.items()}
    ok = r.returncode == 0 and out and out[0].startswith("TYPE\tZIP") and got == want
    return t.record(ok, label, "" if ok else (out[:3], len(got), len(want)))

def stream_crc(t, drv, img, name):
    r = subprocess.run([drv, "x", img, name], capture_output=True, timeout=600)
    p = r.stdout.decode().strip().split("\t")
    return (int(p[0]), int(p[1]), p[2]) if len(p) == 3 else None

def zip_bytes(files):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in files.items():
            z.writestr(k, v)
    return bio.getvalue()

def survive(t, drv, img, timeout=30):
    """list, extract every entry and read every view (driver: no disk writes); None when fine"""
    try:
        for cmd in ("l", "v"):
            r = subprocess.run([drv, cmd, img], capture_output=True, timeout=timeout)
            err = r.stderr.decode(errors="replace")
            if r.returncode not in (0, 1) or "Sanitizer" in err or "runtime error" in err:
                return "%s rc=%d %s" % (cmd, r.returncode, err[-300:])
    except subprocess.TimeoutExpired:
        return "timeout"
    return None

def hostile(t, drv, img, label=None):
    why = survive(t, drv, img)
    return t.record(why is None, label or "hostile " + os.path.basename(img), why or "")

def fuzz(t, drv, img, label, regions, n, seed):
    """bit-flipped / truncated variants must not crash, hang or leak (run under ASan/UBSan too)"""
    data = open(img, "rb").read()
    rnd = random.Random(seed)
    bad = []
    tmp = t.path("fuzz_%s.img" % label)
    for k in range(n):
        d = bytearray(data)
        if k % 8 == 7:
            d = d[:rnd.randrange(512, len(d))]
        else:
            for _ in range(rnd.choice((1, 2, 4, 16, 64))):
                off, ln = rnd.choice(regions)
                pos = off + rnd.randrange(max(1, min(ln, len(d) - off)))
                if pos < len(d):
                    if rnd.random() < 0.3:
                        d[pos] = rnd.choice((0, 0xFF, 0x7F, 0x80, 1))
                    else:
                        d[pos] ^= 1 << rnd.randrange(8)
        with open(tmp, "wb") as f:
            f.write(d)
        why = survive(t, drv, tmp)
        if why:
            shutil.copy(tmp, t.path("fuzzfail_%s_%d.img" % (label, k)))
            bad.append("%d %s" % (k, why))
    os.remove(tmp)
    return t.record(not bad, "fuzz %s x%d" % (label, n), "; ".join(bad[:4]))

# ---------------------------------------------------------------- FAT

FAT_FILES = {
    "readme.txt": blob(5000, 1, True),
    "UPPER.TXT": b"upper case 8.3\n",
    "MixedCase.Txt": b"mixed\n",
    "문서/보고서.txt": blob(120000, 2, True),
    "문서/사진/고기.jpg": blob(70000, 3),
    "empty.txt": b"",
    "deep/a/b/c/d/e.bin": blob(30000, 4),
    "A long file name with spaces, commas and more than 60 characters in it.dat": blob(2000, 5),
    "日本語/ファイル.txt": "テキスト".encode(),
    "big.bin": blob(1 << 20, 6),
}
for _i in range(300):
    FAT_FILES["many/file number %04d.txt" % _i] = ("content %d\n" % _i).encode() * (1 + _i % 7)

class Img:
    """copy-on-write map of an image file; save() writes a sparse copy (images are mostly zeros)"""
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.d = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_COPY)
    def save(self, path=None):
        dst = path or self.path
        z, n = bytes(1 << 16), len(self.d)
        with open(dst + ".tmp", "wb") as f:
            for off in range(0, n, 1 << 16):
                ch = self.d[off:off + (1 << 16)]
                if ch != z[:len(ch)]:
                    f.seek(off)
                    f.write(ch)
            f.truncate(n)
        os.replace(dst + ".tmp", dst)

class FatImg(Img):
    """minimal FAT reader for fixtures and hostile patches"""
    def __init__(self, path):
        Img.__init__(self, path)
        b = self.d
        self.bps, self.spc = struct.unpack_from("<H", b, 11)[0], b[13]
        rsvd, nf, rootent, tot16, f16 = struct.unpack_from("<HBHHxH", b, 14)
        self.fatsz = f16 or struct.unpack_from("<I", b, 36)[0]
        self.fat = rsvd * self.bps
        self.nfats = nf
        rootsec = (rootent * 32 + self.bps - 1) // self.bps
        self.root = (rsvd + nf * self.fatsz) * self.bps
        self.heap = self.root + rootsec * self.bps
        self.cs = self.bps * self.spc
        tot = tot16 or struct.unpack_from("<I", b, 32)[0]
        ncl = (tot - rsvd - nf * self.fatsz - rootsec) // self.spc
        self.bits = 32 if not f16 else (12 if ncl <= 4084 else 16)
    def get(self, c):
        if self.bits == 16:
            return struct.unpack_from("<H", self.d, self.fat + 2 * c)[0]
        if self.bits == 32:
            return struct.unpack_from("<I", self.d, self.fat + 4 * c)[0] & 0x0FFFFFFF
        v = struct.unpack_from("<H", self.d, self.fat + c + c // 2)[0]
        return v >> 4 if c & 1 else v & 0xFFF
    def set(self, c, v):
        for k in range(self.nfats):
            base = self.fat + k * self.fatsz * self.bps
            if self.bits == 16:
                struct.pack_into("<H", self.d, base + 2 * c, v)
            elif self.bits == 32:
                struct.pack_into("<I", self.d, base + 4 * c, v)
            else:
                o = base + c + c // 2
                w = struct.unpack_from("<H", self.d, o)[0]
                w = (w & 0x000F) | (v << 4) if c & 1 else (w & 0xF000) | v
                struct.pack_into("<H", self.d, o, w)
    def chain(self, c):
        out, eoc = [], {12: 0xFF8, 16: 0xFFF8, 32: 0x0FFFFFF8}[self.bits]
        while 2 <= c < eoc and len(out) < 1 << 22:
            out.append(c)
            c = self.get(c)
        return out
    def find(self, short):
        """offset of the directory entry with 11-byte 8.3 name short"""
        i = self.d.find(short)
        while i >= 0 and (i - self.root) % 32:
            i = self.d.find(short, i + 1)
        return i

def mk_fat(t, name, bits, size_kb, files, extra=(), label="GOGI", mtime=None):
    img = t.path(name)
    if os.path.exists(img):
        os.remove(img)
    t.sh(["mkfs.vfat", "-C", "-F", str(bits), "-n", label] + list(extra) + [img, str(size_kb)], env=ENV)
    src = make_tree(t.path(name + "_src"), files, mtime)
    tops = [os.path.join(src, x) for x in sorted(os.listdir(src))]
    if tops:
        t.sh(["mcopy", "-s", "-m", "-Q", "-i", img] + tops + ["::/"], env=ENV)
    return img

def fat_tests(t, drv):
    when = calendar.timegm((2021, 3, 4, 5, 6, 8))
    exp = with_dirs(FAT_FILES)
    for bits, kb, extra in ((12, 8192, []), (16, 32768, []), (32, 65536, []), (32, 300000, ["-S", "4096", "-s", "1"])):
        tag = "fat%d%s" % (bits, "_4k" if extra else "")
        img = mk_fat(t, tag + ".img", bits, kb, FAT_FILES, extra, label="GOGI%d" % bits, mtime=when)
        t.check_extract(img, exp, expect_type="FAT%d" % bits, label=tag + " extract")
        r, typ, comment, rows = dump(t, drv, img)
        rm = rows.get("readme.txt", {})
        ok = comment == "GOGI%d" % bits and rm.get("mk") == 2 and rm.get("mtime") == dos_of(2021, 3, 4, 5, 6, 8) \
            and rm.get("attr") == 0x20 and rows.get("문서", {}).get("attr") == 0x10
        t.record(ok, tag + " label/time/attr", "%s %s" % (comment, rm))
        check_views(t, drv, img, tag + " views")
        if bits == 16 and t.tool("7z"):
            t.check_vs_7z(img, label=tag + " vs 7z")

    # partition-table look-alikes: mkfs.vfat --mbr (its partition starts at sector 0) stays FAT;
    # a table pointing further in is a real MBR, left to the partition map reader
    img = mk_fat(t, "fat_mbr.img", 16, 16384, {"a.txt": b"a"}, ["--mbr=y"])
    t.check_extract(img, {"a.txt": b"a"}, expect_type="FAT16", label="mkfs.vfat --mbr stays FAT")
    fi = FatImg(img)
    struct.pack_into("<BxxxBxxxII", fi.d, 446, 0x80, 0x0C, 2048, 8192)
    fi.save(t.path("fat_mbr_real.img"))
    r, typ, rows = t.listing(t.path("fat_mbr_real.img"))
    t.record(not (typ or "").startswith("FAT"), "partition table past sector 0 is not FAT", str(typ))

    # fragmented chains (deleted small files leave holes the big file fills), nested zip, 8.3 OEM names
    inner = {"in/%03d.txt" % i: blob(3000 + i * 37, 100 + i, True) for i in range(60)}
    inner["photo.bin"] = blob(150000, 7)
    zdata = zip_bytes(inner)
    small = {"frag/s%02d.bin" % i: blob(3000, 200 + i) for i in range(48)}
    files = dict(small)
    files.update({"OEMNAME.TXT": b"oem name\n", "CASEA.TXT": b"a\n", "CASEB.TXT": b"b\n", "KANJI.TXT": b"k\n",
                  "Long Name File.txt": b"long\n"})
    for bits in (16, 32):
        img = mk_fat(t, "frag%d.img" % bits, bits, 40000 if bits == 16 else 70000, files, ["-s", "2"] if bits == 16 else [])
        t.sh(["mdel", "-i", img] + ["::/frag/s%02d.bin" % i for i in range(0, 48, 2)], env=ENV)
        if bits == 32:                                             # FSInfo next-free hint -> fill the holes
            fi = FatImg(img)
            struct.pack_into("<I", fi.d, struct.unpack_from("<H", fi.d, 48)[0] * fi.bps + 492, 2)
            fi.save()
        zp = t.path("frag%d_inner.zip" % bits)
        with open(zp, "wb") as f:
            f.write(zdata)
        t.sh(["mcopy", "-i", img, zp, "::/frag/inner.zip"], env=ENV)
        fi = FatImg(img)
        o = fi.find(b"INNER   ZIP")
        cl = struct.unpack_from("<H", fi.d, o + 26)[0] | (struct.unpack_from("<H", fi.d, o + 20)[0] << 16 if bits == 32 else 0)
        ch = fi.chain(cl)
        runs = 1 + sum(1 for a, b in zip(ch, ch[1:]) if b != a + 1)
        t.record(runs > 3, "frag%d chain is fragmented" % bits, "%d runs" % runs)
        # 8.3 names in the OEM code page (CP949), KANJI 0x05 escape, NT case bits, broken LFN checksum
        hanja = bytes([0xE5, 0xA1]).decode("cp949")
        o = fi.find(b"OEMNAME TXT"); fi.d[o:o + 11] = "한글이름".encode("cp949") + b"TXT"
        o = fi.find(b"KANJI   TXT"); fi.d[o:o + 11] = b"\x05\xa1KJ    TXT"
        o = fi.find(b"CASEA   TXT"); fi.d[o + 12] = 0x08
        o = fi.find(b"CASEB   TXT"); fi.d[o + 12] = 0x10
        lp = fi.d.find("Long ".encode("utf-16-le"))
        slot = lp - 1
        fi.d[slot + 13] ^= 0x5A
        nslot = slot + 32
        while fi.d[nslot + 11] == 0x0F:
            nslot += 32
        sn = bytes(fi.d[nslot:nslot + 11])
        short = sn[:8].rstrip().decode() + ("." + sn[8:].rstrip().decode() if sn[8:].strip() else "")
        fi.save()
        want = {k: v for k, v in small.items() if int(k[6:8]) % 2}
        want.update({"frag/inner.zip": zdata, "한글이름.TXT": b"oem name\n", "casea.TXT": b"a\n", "CASEB.txt": b"b\n",
                     hanja + "KJ.TXT": b"k\n", short: b"long\n"})
        t.check_extract(img, with_dirs(want), acp=949, label="frag%d extract (OEM names, deleted files)" % bits)
        check_views(t, drv, img, "frag%d views" % bits)
        check_nested(t, drv, img, "frag/inner.zip", inner, "frag%d nested zip via run-list view" % bits)

    # FAT32 with mirroring disabled: the active FAT (here the second) is the one to follow
    act = {"x/a.bin": blob(90000, 14), "b.txt": blob(3000, 15, True)}
    img = mk_fat(t, "fat32_active.img", 32, 40000, act)
    fi = FatImg(img)
    fi.d[fi.fat + 8:fi.fat + fi.fatsz * fi.bps] = bytes(fi.fatsz * fi.bps - 8)
    struct.pack_into("<H", fi.d, 40, 0x81)
    fi.save()
    t.check_extract(img, with_dirs(act), label="fat32 active FAT #2 (mirroring off)")

    # FAT32 with > 1M clusters: table read on demand
    img = mk_fat(t, "fat32_big.img", 32, 600000, {"x/a.bin": blob(70000, 9)}, ["-s", "1"])
    t.sh(["mcopy", "-i", img, zp, "::/x/inner.zip"], env=ENV)
    fi = FatImg(img)
    t.record(fi.fatsz * fi.bps // 4 > (1 << 20), "fat32 table > 1M entries", str(fi.fatsz * fi.bps // 4))
    t.check_extract(img, with_dirs({"x/a.bin": blob(70000, 9), "x/inner.zip": zdata}), label="fat32 >1M clusters")
    check_nested(t, drv, img, "x/inner.zip", inner, "fat32 >1M clusters nested zip")

    # hostile: cyclic chain, chain out of range, directory cycle, absurd BPB
    base = mk_fat(t, "host16.img", 16, 8192, {"LOOPDIR/INNER/f.bin": blob(9000, 11), "g.bin": blob(20000, 12),
                                               "h.bin": blob(5000, 13)}, ["-s", "1"])
    fi = FatImg(base)
    o = fi.find(b"G       BIN"); c = struct.unpack_from("<H", fi.d, o + 26)[0]
    ch = fi.chain(c); fi.set(ch[-1], ch[0])                       # cycle after the last cluster
    o = fi.find(b"H       BIN"); c = struct.unpack_from("<H", fi.d, o + 26)[0]
    fi.set(c, 0xFFF0)                                              # reserved value
    o = fi.find(b"INNER      "); po = fi.find(b"LOOPDIR    ")
    struct.pack_into("<H", fi.d, o + 26, struct.unpack_from("<H", fi.d, po + 26)[0])   # INNER -> LOOPDIR
    fi.save(t.path("host16_bad.img"))
    r, rows, out = t.extract(t.path("host16_bad.img"), timeout=30)
    names = {v[3]: v for v in rows.values()}
    ok = r.returncode == 0 and names.get("g.bin", (0,))[0] == 0 and names.get("h.bin", (0,))[0] != 0 \
        and "LOOPDIR/INNER" in names and len(rows) < 10
    t.record(ok, "fat hostile chains/dir cycle", str(sorted(names.items()))[:300])
    fi = FatImg(base)
    struct.pack_into("<H", fi.d, 22, 0xFFFF)                       # sectors per FAT
    fi.save(t.path("host16_fatsz.img"))
    hostile(t, drv, t.path("host16_fatsz.img"))
    fi = FatImg(base)
    fi.d[13] = 128; struct.pack_into("<H", fi.d, 17, 0xFFF0)       # absurd cluster / root sizes
    fi.save(t.path("host16_bpb.img"))
    hostile(t, drv, t.path("host16_bpb.img"))
    f12 = mk_fat(t, "fuzz12.img", 12, 1440, {"d/x.txt": b"x" * 3000, "Long name 파일.txt": b"y" * 5000})
    fi = FatImg(f12)
    fuzz(t, drv, f12, "fat12", [(0, 512), (fi.fat, fi.fatsz * fi.bps), (fi.root, fi.heap - fi.root), (fi.heap, 8 * fi.cs)], 64, 1)
    f32 = mk_fat(t, "fuzz32.img", 32, 34000, {"d/e/x.txt": b"x" * 3000, "긴 이름의 파일.txt": b"y" * 5000})
    fi = FatImg(f32)
    fuzz(t, drv, f32, "fat32", [(0, 1024), (fi.fat, 4096), (fi.heap, 8 * fi.cs)], 64, 2)

# ---------------------------------------------------------------- exFAT

def ex_sum16(data):
    sm = 0
    for i, byte in enumerate(data):
        if i not in (2, 3):
            sm = ((((sm & 1) << 15) | (sm >> 1)) + byte) & 0xFFFF
    return sm

class ExFat(Img):
    """Populates an empty mkfs.exfat image (no mount needed): contiguous NoFatChain files and
    directories, FAT-chained fragmented files, ValidDataLength < DataLength, timestamps."""
    def __init__(self, path):
        Img.__init__(self, path)
        b = self.d
        self.bps = 1 << b[108]
        self.cs = self.bps << b[109]
        self.fat = struct.unpack_from("<I", b, 80)[0] * self.bps
        self.heap = struct.unpack_from("<I", b, 88)[0] * self.bps
        self.ncl = struct.unpack_from("<I", b, 92)[0]
        self.root = struct.unpack_from("<I", b, 96)[0]
        self.root_chain = self.chain(self.root)
        rd = b"".join(self.rdc(c) for c in self.root_chain)
        self.root_used = 0
        for off in range(0, len(rd), 32):
            ty = rd[off]
            if ty == 0:
                break
            if ty == 0x81:
                self.bm_clus, self.bm_len = struct.unpack_from("<IQ", rd, off + 20)
            if ty == 0x82:
                up_clus, up_len = struct.unpack_from("<IQ", rd, off + 20)
            self.root_used = off + 32
        self.bitmap = bytearray(self.rdchain(self.bm_clus, self.bm_len))
        up = self.rdchain(up_clus, up_len)
        self.up = list(range(65536))
        i = k = 0
        while k + 2 <= len(up) and i < 65536:
            v = struct.unpack_from("<H", up, k)[0]
            k += 2
            if v == 0xFFFF and k + 2 <= len(up):
                i += struct.unpack_from("<H", up, k)[0]
                k += 2
            else:
                self.up[i] = v
                i += 1
        self.cursor = 2
    def coff(self, c):
        return self.heap + (c - 2) * self.cs
    def rdc(self, c):
        return bytes(self.d[self.coff(c):self.coff(c) + self.cs])
    def wrc(self, c, data):
        self.d[self.coff(c):self.coff(c) + self.cs] = data.ljust(self.cs, b"\0")
    def fget(self, c):
        return struct.unpack_from("<I", self.d, self.fat + 4 * c)[0]
    def fset(self, c, v):
        struct.pack_into("<I", self.d, self.fat + 4 * c, v)
    def chain(self, c):
        out = [c]
        while self.fget(c) < 0xFFFFFFF8 and len(out) <= self.ncl:
            c = self.fget(c)
            out.append(c)
        return out
    def rdchain(self, c, n):
        return b"".join(self.rdc(x) for x in self.chain(c))[:n]
    def used(self, c):
        return self.bitmap[(c - 2) >> 3] >> ((c - 2) & 7) & 1
    def mark(self, c):
        self.bitmap[(c - 2) >> 3] |= 1 << ((c - 2) & 7)
    def alloc(self, n, frag=False):
        out, c = [], self.cursor
        if frag:                                   # every other free cluster
            while len(out) < n:
                if not self.used(c):
                    out.append(c)
                    c += 1
                c += 1
        else:
            while any(self.used(x) for x in range(c, c + n)):
                c += 1
            out = list(range(c, c + n))
        for x in out:
            self.mark(x)
        assert out[-1] - 2 < self.ncl
        self.cursor = out[-1] + 1
        return out
    def link(self, cl):
        for a, b in zip(cl, cl[1:]):
            self.fset(a, b)
        self.fset(cl[-1], 0xFFFFFFFF)
    def write_data(self, cl, data):
        for i, c in enumerate(cl):
            self.wrc(c, data[i * self.cs:(i + 1) * self.cs])
    def entry_set(self, name, attr, first, dlen, vdl, nofat, ts, inc=0, utc=0):
        u = name.encode("utf-16-le")
        units = [struct.unpack_from("<H", u, i)[0] for i in range(0, len(u), 2)]
        h = 0
        for ch in units:
            ch = self.up[ch]
            for byte in (ch & 0xFF, ch >> 8):
                h = ((((h & 1) << 15) | (h >> 1)) + byte) & 0xFFFF
        nent = (len(units) + 14) // 15
        f = bytearray(32)
        f[0], f[1] = 0x85, 1 + nent
        struct.pack_into("<HHIII", f, 4, attr, 0, ts, ts, ts)
        f[20], f[21], f[22], f[23], f[24] = inc, inc, utc, utc, utc
        st = bytearray(32)
        st[0], st[1], st[3] = 0xC0, 0x01 | (0x02 if nofat else 0), len(units)
        struct.pack_into("<HxxQxxxxIQ", st, 4, h, vdl, first, dlen)
        out = f + st
        for k in range(nent):
            n = bytearray(32)
            n[0] = 0xC1
            part = u[30 * k:30 * k + 30]
            n[2:2 + len(part)] = part
            out += n
        struct.pack_into("<H", out, 2, ex_sum16(out))
        return bytes(out)
    def build(self, node, prefix, opts):
        out = b""
        for name in sorted(node):
            v, path = node[name], prefix + name
            ts, inc, utc = opts.get("time", {}).get(path, (dos_of(2020, 1, 2, 3, 4, 6), 0, 0))
            attr = opts.get("attr", {}).get(path)
            frag = path in opts.get("frag", ())
            if isinstance(v, dict):
                sub = self.build(v, path + "/", opts)
                n = max(1, -(-len(sub) // self.cs))
                cl = self.alloc(n, frag)
                self.write_data(cl, sub)
                if frag:
                    self.link(cl)
                out += self.entry_set(name, attr or 0x10, cl[0], n * self.cs, n * self.cs, not frag, ts, inc, utc)
            elif not v:
                out += self.entry_set(name, attr or 0x20, 0, 0, 0, False, ts, inc, utc)
            else:
                vdl = opts.get("vdl", {}).get(path, len(v))
                cl = self.alloc(-(-len(v) // self.cs), frag)
                self.write_data(cl, v)
                if frag:
                    self.link(cl)
                out += self.entry_set(name, attr or 0x20, cl[0], len(v), vdl, not frag, ts, inc, utc)
        return out
    def populate(self, files, **opts):
        tree = {}
        for k, v in files.items():
            node, parts = tree, k.split("/")
            for p in parts[:-1]:
                node = node.setdefault(p, {})
            if v is None:
                node.setdefault(parts[-1], {})
            else:
                node[parts[-1]] = v
        ents = self.build(tree, "", opts)
        while len(self.root_chain) * self.cs < self.root_used + len(ents) + 32:   # grow the root (FAT chain)
            c = self.alloc(1, True)[0]
            self.fset(self.root_chain[-1], c)
            self.fset(c, 0xFFFFFFFF)
            self.wrc(c, b"")
            self.root_chain.append(c)
        rd = bytearray(b"".join(self.rdc(c) for c in self.root_chain))
        rd[self.root_used:self.root_used + len(ents)] = ents
        self.write_data(self.root_chain, bytes(rd))
        self.write_data(self.chain(self.bm_clus), bytes(self.bitmap))
        self.save()
    def find_set(self, data, name):
        i = bytes(data).find(name.encode("utf-16-le"))
        return i - 66 if i >= 0 else -1          # name entry + 2, two entries after the file entry

def mk_exfat(t, name, size, files, mkfs=(), **opts):
    img = t.path(name)
    if os.path.exists(img):
        os.remove(img)
    with open(img, "wb") as f:
        f.truncate(size)
    t.sh(["mkfs.exfat", "-q"] + list(mkfs) + [img])
    ExFat(img).populate(files, **opts)
    r = t.sh(["fsck.exfat", "-n", img], check=False)
    t.record(r.returncode == 0, name + " fsck.exfat", r.stdout.decode(errors="replace")[-300:])
    return img

def exfat_tests(t, drv):
    files = dict(FAT_FILES)
    files["vdl/partial.bin"] = blob(50000, 21)
    files["frag/chained.bin"] = blob(300000, 22)
    files["readonly hidden.txt"] = b"rh\n"
    files["빈폴더"] = None
    files["fragdir/x.txt"] = b"in a FAT-chained directory\n"
    tm = {"readme.txt": (dos_of(2022, 7, 8, 9, 10, 10), 100, 0x80 | 36),     # 09:10:11.00 at UTC+9
          "UPPER.TXT": (dos_of(2019, 12, 31, 23, 59, 58), 0, 0),              # local time
          "MixedCase.Txt": (dos_of(2001, 2, 3, 4, 5, 6), 57, 0x80 | 0x7C)}    # UTC-1h
    img = mk_exfat(t, "exfat.img", 48 << 20, files, ["-L", "고기 볼륨"], frag={"frag/chained.bin", "fragdir"},
                   vdl={"vdl/partial.bin": 20000}, time=tm, attr={"readonly hidden.txt": 0x23})
    exp = with_dirs(files)
    exp["vdl/partial.bin"] = files["vdl/partial.bin"][:20000] + bytes(30000)
    t.check_extract(img, exp, expect_type="exFAT", label="exfat extract")
    r, typ, comment, rows = dump(t, drv, img)
    f = lambda n, k: rows.get(n, {}).get(k)
    ok = comment == "고기 볼륨" and f("readme.txt", "mk") == 1 and \
        f("readme.txt", "mtime") == ft_of(calendar.timegm((2022, 7, 8, 0, 10, 11))) and \
        f("UPPER.TXT", "mk") == 2 and f("UPPER.TXT", "mtime") == dos_of(2019, 12, 31, 23, 59, 58) and \
        f("MixedCase.Txt", "mtime") == ft_of(calendar.timegm((2001, 2, 3, 5, 5, 6))) + 5700000 and \
        f("readonly hidden.txt", "attr") == 0x23 and f("빈폴더", "is_dir") == 1 and \
        f("frag/chained.bin", "flags") == 0 and f("big.bin", "flags") == 1
    t.record(ok, "exfat label/time/attr/flags", "%s %s" % (comment, {k: rows.get(k) for k in tm}))
    check_views(t, drv, img, "exfat views")
    # nested zip in a contiguous file and in a FAT-chained one
    inner = {"in/%03d.txt" % i: blob(2000 + i, 300 + i, True) for i in range(40)}
    zd = zip_bytes(inner)
    img2 = mk_exfat(t, "exfat_nested.img", 16 << 20, {"a.zip": zd, "b/c.zip": zd}, frag={"b/c.zip"})
    check_nested(t, drv, img2, "a.zip", inner, "exfat nested zip (NoFatChain)")
    check_nested(t, drv, img2, "b/c.zip", inner, "exfat nested zip (FAT chain)")
    # damaged main boot region: the backup region (sectors 12..23) is used
    x = ExFat(img2)
    struct.pack_into("<I", x.d, 88, 7)                      # cluster heap offset: nonsense
    x.save(t.path("exfat_backup.img"))
    check_nested(t, drv, t.path("exfat_backup.img"), "a.zip", inner, "exfat backup boot region")
    # > 1M clusters: FAT read on demand; many entries make the root grow past one cluster
    big = {"d%02d/f%03d.txt" % (i % 10, i): blob(700 + i, 400 + i) for i in range(400)}
    big["chained.bin"] = blob(200000, 23)
    img3 = mk_exfat(t, "exfat_big.img", 640 << 20, big, ["-c", "512"], frag={"chained.bin", "d03"})
    t.check_extract(img3, with_dirs(big), label="exfat 512-byte clusters, on-demand FAT")
    check_views(t, drv, img3, "exfat on-demand views")

    # hostile: cyclic chain, NoFatChain run past the heap, directory pointing at the root, bad checksum
    hf = {"loop/inner/f.bin": blob(9000, 31), "g.bin": blob(20000, 32), "h.bin": blob(20000, 33), "k.bin": b"k" * 100}
    base = mk_exfat(t, "exfat_host.img", 8 << 20, hf, frag={"g.bin", "loop/inner"})
    x = ExFat(base)
    rd = bytearray(b"".join(x.rdc(c) for c in x.root_chain))
    g = x.find_set(rd, "g.bin")
    gch = x.chain(struct.unpack_from("<I", rd, g + 32 + 20)[0])
    x.fset(gch[1], gch[0])                                   # cycle
    h = x.find_set(rd, "h.bin")
    struct.pack_into("<I", rd, h + 32 + 20, x.ncl - 1)      # NoFatChain run past the end of the heap
    struct.pack_into("<H", rd, h + 2, ex_sum16(rd[h:h + 96]))
    rd[x.find_set(rd, "k.bin") + 2] ^= 0xFF                 # broken set checksum: entry skipped
    lc = struct.unpack_from("<I", rd, x.find_set(rd, "loop") + 32 + 20)[0]
    x.write_data(x.root_chain, bytes(rd))
    ld = bytearray(x.rdc(lc))
    i = x.find_set(ld, "inner")
    struct.pack_into("<I", ld, i + 32 + 20, x.root)         # loop/inner -> root directory
    ld[i + 32 + 1] = 0x03
    struct.pack_into("<H", ld, i + 2, ex_sum16(ld[i:i + 96]))
    x.wrc(lc, bytes(ld))
    bad = t.path("exfat_host_bad.img")
    x.save(bad)
    r, rows, out = t.extract(bad, timeout=30)
    names = {v[3]: v for v in rows.values()}
    ok = r.returncode == 0 and names.get("g.bin", (0,))[0] != 0 and names.get("h.bin", (0,))[0] != 0 \
        and "k.bin" not in names and "loop/inner" in names and len(rows) < 8
    t.record(ok, "exfat hostile chains/dir cycle/checksum", str(sorted(names.items()))[:300])
    # absurd boot sector values (boot checksum fixed so the region is accepted)
    for k, pokes in enumerate(([(92, "<I", 0xFFFFFFF5), (72, "<Q", 1 << 50), (84, "<I", 0x10000000)],
                               [(84, "<I", 0xFFFFFFFF)], [(96, "<I", 0xFFFFFFF0)], [(72, "<Q", 1 << 62)],
                               [(109, "<B", 16)], [(88, "<I", 0xFFFFFFFF)])):
        d = bytearray(open(base, "rb").read())
        for off, fm, val in pokes:
            struct.pack_into(fm, d, off, val)
        bps = 1 << d[108]
        c = 0
        for j in range(11 * bps):
            if j not in (106, 107, 112):
                c = ((0x80000000 if c & 1 else 0) + (c >> 1) + d[j]) & 0xFFFFFFFF
        for j in range(0, bps, 4):
            struct.pack_into("<I", d, 11 * bps + j, c)
        p = t.path("exfat_absurd%d.img" % k)
        with open(p, "wb") as fo:
            fo.write(d)
        hostile(t, drv, p)
    x = ExFat(base)
    fuzz(t, drv, base, "exfat", [(0, 12 * x.bps), (x.fat, 4096), (x.coff(x.root), x.cs), (x.heap, 16 * x.cs)], 64, 3)

# ---------------------------------------------------------------- ext2/3/4

LONGDIR = "long_directory_name_for_slow_symlink_testing_purposes"
EXT_FILES = {
    "readme.txt": blob(5000, 41, True),
    "문서/보고서.txt": blob(120000, 42, True),
    "문서/사진/고기.jpg": blob(70000, 43),
    "empty.txt": b"",
    "tiny.txt": b"x",
    "inline59.txt": blob(59, 44, True),
    "inline100.txt": blob(100, 45, True),
    "deep/a/b/c/d/e/f/g/h.bin": blob(30000, 46),
    "big.bin": blob(3 << 20, 47),
    "日本語/ファイル.txt": "テキスト".encode(),
    "Ünïcödé name.txt": b"unicode\n",
    LONGDIR + "/target.txt": b"slow symlink target\n",
    "future.txt": b"2100\n",
}
EXT_LINKS = {"fastlink": "readme.txt", "slowlink": LONGDIR + "/target.txt", "dangling": "nowhere/" + "z" * 300}
NS_TIME = 1600000000123456789
FUTURE = 4102444800 + 7                              # 2100-01-01: needs the epoch bits

def ext_src(t, name, files, links=EXT_LINKS, sparse=None):
    src = make_tree(t.path(name + "_src"), files)
    for k, v in links.items():
        os.symlink(v, os.path.join(src, k))
    if "readme.txt" in files:
        os.link(os.path.join(src, "readme.txt"), os.path.join(src, "hardlink.txt"))
        os.utime(os.path.join(src, "readme.txt"), ns=(NS_TIME, NS_TIME))
    if "future.txt" in files:
        os.utime(os.path.join(src, "future.txt"), (FUTURE, FUTURE))
    if "tiny.txt" in files and os.geteuid() == 0:
        os.chown(os.path.join(src, "tiny.txt"), 1234, 5678)
    if "문서/보고서.txt" in files:
        os.chmod(os.path.join(src, "문서/보고서.txt"), 0o600)
    if "deep" in {k.split("/")[0] for k in files}:
        os.chmod(os.path.join(src, "deep"), 0o700)
    for k, (size, parts) in (sparse or {}).items():
        with open(os.path.join(src, k), "wb") as f:
            f.truncate(size)
            for off, data in parts:
                f.seek(off)
                f.write(data)
    return src

def mk_ext(t, name, src, size, opts=()):
    img = t.path(name)
    if os.path.exists(img):
        os.remove(img)
    t.sh(["mke2fs", "-q", "-F"] + list(opts) + ["-d", src, img, size], env=ENV)
    return img

def ext_expected(files, extra=None):
    exp = with_dirs(files)
    if "readme.txt" in files:
        exp["hardlink.txt"] = files["readme.txt"]
    exp.update(extra or {})
    return exp

def check_rdump(t, img, label, inline=False):
    """debugfs's own extraction must match ours byte for byte (regular files)"""
    out = t.path("rdump_" + os.path.basename(img))
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    t.sh(["debugfs", "-R", "rdump / " + out, img], env=ENV)
    ref = t.read_tree(out)
    r, rows, gout = t.extract(img)
    mine = {}
    for i, (st, isdir, size, name) in rows.items():
        p = os.path.join(gout, "%d.bin" % i)
        if not isdir and os.path.exists(p) and not os.path.islink(os.path.join(out, name)):
            mine[name] = open(p, "rb").read()
    for k, v in mine.items():   # debugfs 1.47 dumps inline files shorter than 60 bytes as all of i_block
        if inline and len(v) < 60 and len(ref.get(k, b"")) == 60 and ref[k][:len(v)] == v and not any(ref[k][len(v):]):
            ref[k] = v
    ok = r.returncode == 0 and ref == mine
    diff = sorted(set(ref) ^ set(mine))[:5] + [k for k in ref if k in mine and ref[k] != mine[k]][:5]
    return t.record(ok, label + " vs debugfs rdump", "" if ok else str(diff))

def sparse_crc(size, parts):
    crc, pos, z = 0, 0, bytes(1 << 24)
    for off, data in sorted(parts) + [(size, b"")]:
        while pos < off:
            n = min(len(z), off - pos)
            crc = zlib.crc32(z[:n] if n < len(z) else z, crc)
            pos += n
        crc = zlib.crc32(data, crc)
        pos += len(data)
    return "%08x" % crc

def ext_tests(t, drv):
    # files > 4 GiB, sparse: only streamed / read through views by the driver (never written to disk)
    G4 = 1 << 32
    sp_parts = [(0, b"HEAD"), (2 << 30, blob(65536, 48)), (G4 - 2, b"<4G>"), (G4 + (1 << 20) - 4, b"TAIL")]
    ssrc = ext_src(t, "ext_sparse", {"a.txt": b"a"}, links={}, sparse={"sparse.bin": (G4 + (1 << 20), sp_parts)})
    for tag, opts in (("extents", ["-t", "ext4"]), ("indirect", ["-t", "ext3"])):
        img = mk_ext(t, "sparse_%s.img" % tag, ssrc, "16M", opts)
        r, ty, comment, rows = dump(t, drv, img)
        st = stream_crc(t, drv, img, "sparse.bin")
        t.record(st == (0, G4 + (1 << 20), sparse_crc(G4 + (1 << 20), sp_parts)) and
                 rows.get("sparse.bin", {}).get("csize", 1 << 40) < (1 << 20), "4 GiB+ sparse file (%s)" % tag, str(st))
        rr = subprocess.run([drv, "r", img, "sparse.bin", str(G4 - 2), "4", str(G4 + (1 << 20) - 4), "4",
                             str(2 << 30), "65536", "4", "100"], capture_output=True, timeout=60)
        want = ["SIZE\t%d" % (G4 + (1 << 20))] + ["0\t%08x" % zlib.crc32(x) for x in
                                                   (b"<4G>", b"TAIL", sp_parts[1][1], bytes(100))]
        t.record(rr.stdout.decode().split("\n")[:5] == want, "sparse view reads (%s)" % tag, rr.stdout.decode()[:200])

    src = ext_src(t, "ext4", EXT_FILES)
    variants = [("ext4", "64M", ["-t", "ext4"], "ext4", True),
                ("ext4_1k", "64M", ["-t", "ext4", "-b", "1024"], "ext4", True),
                ("ext4_noext", "64M", ["-t", "ext4", "-O", "^extent,^64bit"], "ext4", True),
                ("ext3", "64M", ["-t", "ext3"], "ext3", True),
                ("ext2_128", "64M", ["-t", "ext2", "-I", "128", "-b", "1024"], "ext2", True),
                ("ext4_inline", "64M", ["-t", "ext4", "-O", "inline_data", "-I", "512"], "ext4", False),
                ("ext4_64k", "64M", ["-t", "ext4", "-b", "65536", "-O", "^has_journal"], "ext4", False),
                ("ext4_bigalloc", "64M", ["-t", "ext4", "-O", "bigalloc", "-C", "16384"], "ext4", False)]
    exp = ext_expected(EXT_FILES)
    for tag, size, opts, typ, sev in variants:
        img = mk_ext(t, tag + ".img", src, size, opts)
        ns = 0 if "128" in opts else NS_TIME % 10**9
        if ns:      # mke2fs -d stores whole seconds: set nanoseconds and the epoch bits (2100) by hand
            t.sh(["debugfs", "-w", "-R", "sif /readme.txt mtime_extra %d" % (ns << 2), img])
            t.sh(["debugfs", "-w", "-R", "sif /future.txt mtime_extra 1", img])
        t.check_extract(img, exp, expect_type=typ, allow_extra=True, label=tag + " extract")
        r, ty, comment, rows = dump(t, drv, img)
        f = lambda n, k: rows.get(n, {}).get(k)
        issues = []
        for k, v in EXT_LINKS.items():
            if f(k, "link") != v or f(k, "is_link") != 1 or f(k, "mode") & 0o170000 != 0o120000:
                issues.append("link " + k)
        if f("문서/보고서.txt", "mode") != 0o100600 or f("deep", "mode") != 0o40700 or f("big.bin", "mode") & 0o777 != 0o644:
            issues.append("modes")
        if f("tiny.txt", "aux") != (5678 << 32 | 1234) and os.geteuid() == 0:
            issues.append("uid/gid %s" % f("tiny.txt", "aux"))
        if f("readme.txt", "mtime") != ft_of(NS_TIME // 10**9, ns) or f("readme.txt", "mk") != 1:
            issues.append("mtime %s" % f("readme.txt", "mtime"))
        if ns and f("future.txt", "mtime") != ft_of(FUTURE):
            issues.append("epoch bits %s" % f("future.txt", "mtime"))
        if f("hardlink.txt", "usize") != 5000 or f("big.bin", "usize") != 3 << 20:
            issues.append("sizes")
        t.record(not issues and ty == typ, tag + " metadata", "; ".join(issues))
        check_rdump(t, img, tag, "inline_data" in opts)
        if sev and t.tool("7z"):
            ref, out = t.sevenzip_extract(img)
            if ref.returncode == 0:
                ref7 = {k: v for k, v in t.read_tree(out).items() if not k.startswith("[SYS]")}
                t.check_extract(img, ref7, allow_extra=True, label=tag + " vs 7z")

    # views of every file (the sparse one is skipped: 4 GiB of CRC twice), nested zip
    inner = {"in/%03d.txt" % i: blob(2000 + i, 500 + i, True) for i in range(40)}
    files = dict(EXT_FILES)
    files["arc/inner.zip"] = zip_bytes(inner)
    with open(t.path("islands_src.bin"), "wb") as fo:
        for i in range(2400):                         # 2400 extents: tree depth 2 with 1 KiB blocks
            fo.write(blob(1024, 600 + i % 7))
            fo.write(bytes(1024))
    files["islands.bin"] = open(t.path("islands_src.bin"), "rb").read()
    src2 = ext_src(t, "ext_views", files)
    for tag, opts in (("v_ext4_1k", ["-t", "ext4", "-b", "1024"]), ("v_ext2_1k", ["-t", "ext2", "-b", "1024"]),
                      ("v_inline", ["-t", "ext4", "-O", "inline_data"])):
        img = mk_ext(t, tag + ".img", src2, "64M", opts)
        check_views(t, drv, img, tag + " views")
        check_nested(t, drv, img, "arc/inner.zip", inner, tag + " nested zip")
        if tag == "v_ext4_1k":
            ex = t.sh(["debugfs", "-R", "ex /islands.bin", img]).stdout.decode()
            t.record(" 2/ 2 " in ex, "extent tree depth 2", ex[:80])
            t.check_extract(img, {"islands.bin": files["islands.bin"]}, allow_extra=True, label=tag + " islands")
        if tag == "v_inline":
            st = t.sh(["debugfs", "-R", "stat /inline100.txt", img]).stdout.decode()
            sd = t.sh(["debugfs", "-R", "stat /日本語", img]).stdout.decode()
            t.record("0x10000000" in st and "0x10000000" in sd, "inline data used for files and dirs", st[:60])

    # triple indirect blocks: data past 64 MiB of a 1 KiB-block ext2 file
    tri = [(0, b"start"), (70 << 20, blob(5000, 49)), ((1 << 30) + 12345, b"one gig")]
    src3 = ext_src(t, "ext_tri", {"a.txt": b"a"}, links={}, sparse={"tri.bin": ((1 << 30) + 20000, tri)})
    img = mk_ext(t, "ext2_triple.img", src3, "16M", ["-t", "ext2", "-b", "1024"])
    st = stream_crc(t, drv, img, "tri.bin")
    t.record(st == (0, (1 << 30) + 20000, sparse_crc((1 << 30) + 20000, tri)), "ext2 triple indirect", str(st))

    # htree directory, meta_bg with descriptors in several meta groups, unwritten extents
    many = {"big dir/entry with a fairly long name %05d.txt" % i: ("%d\n" % i).encode() for i in range(3000)}
    src4 = ext_src(t, "ext_htree", many, links={})
    img = mk_ext(t, "ext4_htree.img", src4, "64M", ["-t", "ext4"])
    t.sh(["e2fsck", "-fyD", img], check=False)
    r, ty, comment, rows = dump(t, drv, img)
    t.record(rows.get("big dir", {}).get("aux32", 0) & 0x1000, "htree index present", str(rows.get("big dir")))
    t.check_extract(img, with_dirs(many), allow_extra=True, label="ext4 htree directory")
    img = mk_ext(t, "ext4_metabg.img", src4, "300M", ["-t", "ext4", "-b", "1024", "-O", "64bit,meta_bg,^resize_inode",
                                                      "-N", "4096", "-L", "메타"])
    hdr = t.sh(["dumpe2fs", "-h", img]).stdout.decode()
    t.record("meta_bg" in hdr, "meta_bg feature set", "")
    t.check_extract(img, with_dirs(many), allow_extra=True, label="ext4 meta_bg")
    r, ty, comment, rows = dump(t, drv, img)
    t.record(comment == "메타", "ext volume label", str(comment))
    src6 = ext_src(t, "ext_unwritten", {"a.txt": b"a"}, links={})
    img = mk_ext(t, "ext4_unwritten.img", src6, "16M", ["-t", "ext4", "-b", "1024"])
    empty = t.path("empty_file")
    open(empty, "wb").close()
    t.sh(["debugfs", "-w", "-R", "write %s prealloc" % empty, img])
    t.sh(["debugfs", "-w", "-R", "fallocate /prealloc 0 39", img])
    t.sh(["debugfs", "-w", "-R", "sif /prealloc size 40000", img])
    ex = t.sh(["debugfs", "-R", "ex /prealloc", img]).stdout.decode()
    t.check_extract(img, {"prealloc": bytes(40000), "a.txt": b"a"}, allow_extra=True, label="unwritten extents read as zeros")
    t.record("Uninit" in ex, "fallocate made unwritten extents", ex[-80:])

    # encrypted inode, deleted inode still linked, directory cycle, extent outside the volume
    hs = {"secret.txt": b"secret", "ghost.txt": b"ghost", "ok.txt": b"fine", "loop/sub/f.txt": b"f",
          "far.bin": blob(20000, 50)}
    src5 = ext_src(t, "ext_host", hs, links={})
    base = mk_ext(t, "ext_host.img", src5, "8M", ["-t", "ext4", "-b", "1024"])
    bad = t.path("ext_host_bad.img")
    shutil.copy(base, bad)
    for cmd in ("sif /secret.txt flags 0x80800", "sif /ghost.txt links_count 0", "ln /loop /loop/sub/cycle",
                "sif /far.bin block[5] 0x7ffffff0"):
        t.sh(["debugfs", "-w", "-R", cmd, bad])
    r, rows, out = t.extract(bad, timeout=30)
    names = {v[3]: v for v in rows.values()}
    ok = r.returncode == 0 and names.get("secret.txt", (0,))[0] == 5 and "ghost.txt" not in names \
        and names.get("ok.txt", (1,))[0] == 0 and "loop/sub/cycle" in names and names.get("far.bin", (0,))[0] != 0 \
        and len(rows) < 12
    t.record(ok, "ext hostile inodes/dir cycle/extent range", str(sorted(names.items()))[:400])
    # absurd superblock values
    for k, (off, fm, val) in enumerate(((1024 + 0, "<I", 0xFFFFFFFF), (1024 + 4, "<I", 0xFFFFFFFF),
                                         (1024 + 40, "<I", 0xFFFFFFFF), (1024 + 32, "<I", 1), (1024 + 24, "<I", 6),
                                         (1024 + 88, "<H", 4096), (1024 + 0xFE, "<H", 0x8000),
                                         (1024 + 0x150, "<I", 0xFFFF))):
        d = bytearray(open(base, "rb").read())
        struct.pack_into(fm, d, off, val)
        p = t.path("ext_absurd%d.img" % k)
        with open(p, "wb") as fo:
            fo.write(d)
        hostile(t, drv, p)
    fz = mk_ext(t, "ext_fuzz.img", src5, "2M", ["-t", "ext4", "-b", "1024", "-N", "64"])
    fz2 = mk_ext(t, "ext_fuzz2.img", src5, "2M", ["-t", "ext2", "-b", "1024", "-N", "64"])
    fuzz(t, drv, fz, "ext4", [(1024, 1024), (2048, 1024), (0, 300 * 1024)], 64, 4)
    fuzz(t, drv, fz2, "ext2", [(1024, 1024), (2048, 1024), (0, 300 * 1024)], 64, 5)

def run(t):
    have = lambda *tools: all(t.tool(x) for x in tools)
    groups = [(fat_tests, ("mkfs.vfat", "mcopy", "mdel")), (exfat_tests, ("mkfs.exfat", "fsck.exfat")),
              (ext_tests, ("mke2fs", "debugfs", "e2fsck", "dumpe2fs"))]
    if not any(have(*tools) for fn, tools in groups):
        t.skip("needs dosfstools + mtools, exfatprogs or e2fsprogs")
    drv = t.build_driver("tests/drivers/fs1_dump.c")
    for fn, tools in groups:
        if have(*tools):
            fn(t, drv)
        else:
            t.record(True, "%s skipped (missing %s)" % (fn.__name__, " ".join(tools)))
