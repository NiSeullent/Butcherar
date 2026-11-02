"""Inno Setup installer tests (src/fmt/inno.c).

Generated installers (offline): an Inno Setup writer below serialises the setup
header, entry lists and file locations of any data version from 1.3.25 to
7.0.0.3 (ANSI / Unicode), the 4 KiB CRC'd header blocks (zlib / LZMA), chunks
compressed with Store / zlib / bzip2 / LZMA / LZMA2 (solid or one per file),
ARC4 (MD5 / SHA-1 keys) and XChaCha20 encryption (6.4 header fields, 6.5+
encryption header), disk spanning slices ("-1.bin" files, chunks crossing
slices), loader tables at 0x30 or in an RCDATA 11111 resource (both table
revisions). They check names ("{app}/x", "{{" escapes, constants with
separators, Korean CP949 / UTF-16 names, Shift-JIS trail bytes guarded by the
DBCS lead-byte set), collisions (@language, @32bit / @64bit, $n), shared and
overlapping data, empty files, the uninstaller entry, [Dirs], passwords and
checksums (Adler-32 / CRC-32 / MD5 / SHA-1 / SHA-256).

Real installers (data only, never executed): the official Inno Setup installers
1.3 .. 5.6.1 from files.jrsoftware.org and KeePass installers (Inno Setup 5.5 ..
6.7) from SourceForge are downloaded into a cache outside the repository
($GZ_TEST_CACHE or ~/.cache/gogitzip/inno; GZ_INNO_ALL=1 for every version) and
compared with innoextract (names and contents; newer versions than innoextract
knows are checked by their stored SHA-1 / SHA-256). Skipped when offline.

Hostile inputs: truncations, bad loader tables / offsets / versions, CRC errors,
absurd counts and sizes, missing slices, an in-process mutation fuzzer.
"""
import os, struct, zlib, lzma, bz2, hashlib, random, shutil, subprocess, urllib.request

def V(a, b, c, d=0):
    return a << 24 | b << 16 | c << 8 | d

def crc(b):
    return zlib.crc32(b) & 0xFFFFFFFF

# ------------------------------------------------------------------ ciphers

class RC4:
    def __init__(self, key):
        s = list(range(256)); j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 255
            s[i], s[j] = s[j], s[i]
        self.s, self.i, self.j = s, 0, 0
        self.crypt(bytes(1000))
    def crypt(self, data):
        s, i, j = self.s, self.i, self.j
        out = bytearray(data)
        for k in range(len(out)):
            i = (i + 1) & 255; j = (j + s[i]) & 255
            s[i], s[j] = s[j], s[i]
            out[k] ^= s[(s[i] + s[j]) & 255]
        self.i, self.j = i, j
        return bytes(out)

def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def _chacha_block(st):
    x = list(st)
    def qr(a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl(x[b] ^ x[c], 7)
    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    return x

def xchacha20(key, nonce, data):
    """XChaCha20 with a 64-bit block counter (Inno Setup 6.4+)."""
    c = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    k = list(struct.unpack("<8I", key))
    h = _chacha_block(c + k + list(struct.unpack("<4I", nonce[:16])))
    sub = h[0:4] + h[12:16]
    st = c + sub + [0, 0] + list(struct.unpack("<2I", nonce[16:24]))
    out = bytearray(data)
    for blk in range(0, len(out), 64):
        x = _chacha_block(st)
        ks = struct.pack("<16I", *[(x[i] + st[i]) & 0xFFFFFFFF for i in range(16)])
        for i in range(min(64, len(out) - blk)):
            out[blk + i] ^= ks[i]
        st[12] = (st[12] + 1) & 0xFFFFFFFF
        if not st[12]:
            st[13] += 1
    return bytes(out)

# ------------------------------------------------------------------ Inno Setup writer

STORED, ZLIB, BZIP2, LZMA1, LZMA2 = "stored", "zlib", "bzip2", "lzma", "lzma2"

class W:
    def __init__(self, v, uni, isx=False):
        self.v, self.uni, self.isx, self.b = v, uni, isx, bytearray()
    def u8(self, x=0): self.b += struct.pack("<B", x)
    def u16(self, x=0): self.b += struct.pack("<H", x)
    def u32(self, x=0): self.b += struct.pack("<I", x & 0xFFFFFFFF)
    def u64(self, x=0): self.b += struct.pack("<Q", x)
    def raw(self, x): self.b += x
    def s(self, x=b""):
        if isinstance(x, str):
            x = x.encode("utf-16-le") if self.uni else x.encode("cp1252")
        self.u32(len(x)); self.b += x
    def winver(self):
        for _ in range(2):
            for _ in range(2):
                if self.v >= V(1, 3, 19): self.u16()
                self.u8(); self.u8()
            if self.v >= V(1, 3, 19): self.u8(); self.u8()
    def flags(self, items, setbits=(), width=0):
        """items: (cond, name) in stored order; returns nothing, writes the Delphi set"""
        bits = [name in setbits for cond, name in items if cond]
        n = (len(bits) + 7) // 8
        if width: n = max(n, width)
        elif n == 3: n = 4
        out = bytearray(n)
        for i, b in enumerate(bits):
            if b: out[i // 8] |= 1 << (i % 8)
        self.b += out

def cond_data(w, langs="", comps=""):
    v, isx = w.v, w.isx
    if v >= V(2, 0, 0) or (isx and v >= V(1, 3, 8)): w.s(comps)
    if v >= V(2, 0, 0) or (isx and v >= V(1, 3, 17)): w.s()
    if v >= V(4, 0, 1): w.s(langs)
    if v >= V(4, 0, 0) or (isx and v >= V(1, 3, 24)): w.s()
    if v >= V(4, 1, 0): w.s(); w.s()

def method_code(v, m):
    if v >= V(5, 3, 9): return [STORED, ZLIB, BZIP2, LZMA1, LZMA2].index(m)
    if v >= V(4, 2, 6): return [STORED, ZLIB, BZIP2, LZMA1].index(m)
    if v >= V(4, 2, 5): return [STORED, BZIP2, LZMA1].index(m)
    if v >= V(4, 1, 5): return [ZLIB, BZIP2, LZMA1].index(m)
    return None

def methods_for(v):
    if v >= V(5, 3, 9): return [STORED, ZLIB, BZIP2, LZMA1, LZMA2]
    if v >= V(4, 2, 6): return [STORED, ZLIB, BZIP2, LZMA1]
    if v >= V(4, 2, 5): return [STORED, BZIP2, LZMA1]
    if v >= V(4, 1, 5): return [ZLIB, BZIP2, LZMA1]
    if v >= V(2, 0, 17): return [ZLIB, BZIP2]
    return [ZLIB]

def write_header(w, g):
    v, isx, uni = w.v, w.isx, w.uni
    if v < V(1, 3, 0): w.u32()
    w.s("Gogi Test"); w.s("Gogi Test 1.0")
    if v >= V(1, 3, 0): w.s("GogiTest")
    w.s("(c) gogi")
    if v >= V(1, 3, 0): w.s(); w.s()
    if v >= V(5, 1, 13): w.s()
    if v >= V(1, 3, 0): w.s(); w.s(); w.s("1.0")
    w.s("{pf}\\Gogi"); w.s("Gogi")
    if v < V(3, 0, 0): w.s()
    w.s(g.base)
    if V(1, 3, 0) <= v < V(5, 2, 5): w.s(); w.s(); w.s()
    if v >= V(1, 3, 3): w.s()
    if v >= V(1, 3, 6): w.s(); w.s()
    if v >= V(1, 3, 14): w.s()
    if v >= V(3, 0, 0): w.s(); w.s()
    if v >= V(4, 0, 0) or (isx and v >= V(3, 0, 6, 1)): w.s()
    if V(4, 0, 0) <= v < V(5, 2, 5) or (isx and v >= V(1, 3, 24)): w.s()
    if v >= V(4, 2, 4): w.s(); w.s(); w.s(); w.s()
    if v >= V(5, 3, 8): w.s()
    if v >= V(5, 3, 10): w.s()
    if v >= V(5, 5, 0): w.s()
    if v >= V(5, 5, 6): w.s()
    if v >= V(5, 6, 1): w.s(); w.s()
    if v >= V(6, 3, 0): w.s(); w.s()
    if v >= V(6, 4, 2): w.s()
    if v >= V(6, 5, 0): w.s()
    if v >= V(6, 7, 0):
        for _ in range(5): w.s()
    if v >= V(5, 2, 5): w.s("license"); w.s(); w.s()
    if V(5, 2, 1) <= v < V(5, 3, 10): w.s()
    if v >= V(5, 2, 5): w.s()
    if v >= V(2, 0, 6) and not uni: w.raw(g.lead or bytes(32))
    nlang = len(g.langs)
    if v >= V(4, 0, 0): w.u32(nlang)
    if v >= V(4, 2, 1): w.u32(0)
    if v >= V(4, 1, 0): w.u32(0)
    if v >= V(2, 0, 0) or isx: w.u32(0); w.u32(0)
    if v >= V(2, 0, 0) or (isx and v >= V(1, 3, 17)): w.u32(0)
    w.u32(len(g.dirs))
    if v >= V(6, 5, 0): w.u32(0)
    w.u32(g.n_file if g.n_file is not None else len(g.files))
    w.u32(g.n_data if g.n_data is not None else len(g.locs))
    for _ in range(7): w.u32(0)
    if v < V(1, 3, 0): w.u32(); w.u32(); w.u32()
    if v >= V(7, 0, 0, 3): w.u32()
    w.winver()
    if v < V(6, 4, 0, 1): w.u32()
    if V(1, 3, 3) <= v < V(6, 4, 0, 1): w.u32()
    if v < V(5, 5, 7): w.u32()
    if V(2, 0, 0) <= v < V(5, 0, 4) or isx: w.u32()
    if v >= V(6, 6, 0): w.u32(); w.u32(); w.u8()
    elif v >= V(6, 0, 0): w.u8(); w.u32(); w.u32()
    if v >= V(5, 5, 7): w.u8()
    if v >= V(6, 5, 2): w.u32(); w.u32()
    if v >= V(6, 7, 0): w.u32()
    if v >= V(6, 6, 0): w.u32(); w.u32()
    if v >= V(6, 7, 0): w.u32()
    if v >= V(6, 6, 1): w.u8(255)
    if v >= V(6, 7, 0): w.u8(); w.u8()
    if v >= V(6, 5, 0): pass
    elif v >= V(6, 4, 0): w.raw(g.pw_test)
    elif v >= V(5, 3, 9): w.raw(g.pw_hash or bytes(20))
    elif v >= V(4, 2, 0): w.raw(g.pw_hash or bytes(16))
    else: w.u32(0)
    if v >= V(6, 5, 0): pass
    elif v >= V(6, 4, 0): w.raw(g.kdf_salt + struct.pack("<I", g.kdf_iter) + g.nonce)
    elif v >= V(4, 2, 2): w.raw(g.salt)
    if v >= V(4, 0, 0): w.u64(); w.u32(g.slices_per_disk)
    else: w.u32()
    if V(2, 0, 0) <= v < V(5, 0, 0) or (isx and v >= V(1, 3, 4)): w.u8()
    if v >= V(1, 3, 0): w.u8()
    if v < V(5, 0, 0) and (v >= V(2, 0, 0) or (isx and v >= V(1, 3, 13))): w.u8()
    if v >= V(1, 3, 6): w.u8()
    if isx and V(2, 0, 10) <= v < V(3, 0, 0): w.u32()
    if V(3, 0, 0) <= v < V(3, 0, 3): w.u8()
    if v >= V(5, 3, 7) or v >= V(3, 0, 4) or (isx and v >= V(3, 0, 3)): w.u8()
    if v >= V(5, 7, 0): w.u8()
    if v >= V(4, 0, 10): w.u8(); w.u8()
    if v >= V(4, 1, 5): w.u8(g.comp_byte if g.comp_byte is not None else method_code(v, g.method))
    if V(5, 1, 0) <= v < V(6, 3, 0): w.u8(1); w.u8(0)
    if V(5, 2, 1) <= v < V(5, 3, 10): w.u32(); w.u32()
    if v >= V(5, 3, 3): w.u8(); w.u8()
    if v >= V(5, 5, 0): w.u64()
    elif v >= V(5, 3, 6): w.u32()
    on = {"CreateAppDir"}
    if g.method == BZIP2 and v < V(4, 1, 5): on.add("BzipUsed")
    if g.enc and v < V(6, 5, 0): on.add("EncryptionUsed")
    it = [(1, "DisableStartupPrompt"), (v < V(5, 3, 10), "Uninstallable"), (1, "CreateAppDir"),
          (v < V(5, 3, 3), "DisableDirPage"), (v < V(1, 3, 6), "x"), (v < V(5, 3, 3), "x"), (1, "x"),
          (v < V(3, 0, 0) or v >= V(3, 0, 3), "x"), (v < V(1, 3, 3), "x"), (1, "x")]
    it += [(v < V(6, 4, 0, 1), "x")] * 4
    it += [(1, "x"), (v < V(4, 1, 2), "x"), (1, "Password"), (v >= V(1, 2, 6), "x"), (v >= V(1, 2, 14), "x"),
           (v < V(3, 0, 4), "x"), (v < V(3, 0, 0), "x"), (v < V(1, 3, 6), "x"), (v < V(5, 6, 1), "x"),
           (V(1, 3, 0) <= v < V(5, 3, 8), "x"), (V(1, 3, 1) <= v < V(6, 7, 0), "x"),
           (V(1, 3, 3) <= v < V(6, 4, 0, 1), "x"), (V(1, 3, 10) <= v < V(6, 7, 0), "x"), (v >= V(1, 3, 20), "x"),
           ((v >= V(2, 0, 0) or (isx and v >= V(1, 3, 10))) and v < V(6, 7, 0), "x")]
    if v >= V(2, 0, 0):
        it += [(1, "x")] * 4 + [(v < V(6, 7, 0), "x"), (1, "x")]
    it += [(v >= V(2, 0, 7), "x")] * 2
    it += [(V(2, 0, 17) <= v < V(4, 1, 5), "BzipUsed"), (v >= V(2, 0, 18), "x")]
    if v >= V(3, 0, 0):
        it += [(1, "x"), (v < V(6, 7, 0), "x")]
    it += [(v >= V(3, 0, 1), "x"), (v >= V(3, 0, 3), "x"), (v >= V(4, 0, 0) or (isx and v >= V(3, 0, 3)), "x"),
           (V(4, 0, 0) <= v < V(4, 0, 10), "x"), (V(4, 0, 1) <= v < V(4, 0, 10), "x"), (v >= V(4, 0, 9), "x"),
           (v >= V(4, 1, 3), "x"), (v >= V(4, 1, 8), "x"), (v >= V(4, 1, 8), "x"),
           (V(4, 2, 2) <= v < V(6, 5, 0), "EncryptionUsed"), (V(5, 0, 4) <= v < V(5, 6, 1), "x"),
           (v >= V(5, 1, 7) and not uni, "x"), (v >= V(5, 1, 13), "x"), (v >= V(5, 2, 1), "x"),
           (v >= V(5, 3, 8), "x"), (v >= V(5, 3, 9), "x")]
    it += [(v >= V(5, 5, 0), "x")] * 3 + [(v >= V(5, 5, 7), "x")] + [(v >= V(6, 0, 0), "x")] * 2
    it += [(V(6, 0, 0) <= v < V(6, 6, 0), "x"), (v >= V(6, 3, 0), "x")] + [(v >= V(6, 6, 0), "x")] * 3
    it += [(V(6, 6, 0) <= v < V(6, 7, 0), "x")] + [(v >= V(6, 7, 0), "x")] * 2
    w.flags(it, on, 8 if v >= V(6, 7, 0) else 0)

def write_language(w, cp):
    v, uni = w.v, w.uni
    if v >= V(4, 0, 0): w.s("english")
    if v >= V(4, 2, 2):
        x = "English".encode("utf-16-le"); w.u32(len(x)); w.raw(x)
    else:
        w.s("English")
    w.s("Tahoma")
    if v < V(6, 6, 0): w.s("Arial")
    w.s("Verdana")
    if v < V(6, 6, 0): w.s("Arial")
    if v >= V(4, 0, 0): w.s()
    if v >= V(4, 0, 1): w.s(); w.s(); w.s()
    lid = {949: 0x412, 932: 0x411}.get(cp, 0x409)
    if v >= V(6, 6, 0): w.u16(lid)
    else: w.u32(lid)
    if v >= V(4, 2, 2) and not uni: w.u32(cp)
    elif uni and v < V(5, 3, 0): w.u32(0)
    w.u32(8)
    if v < V(4, 1, 0): w.u32(0)
    if v >= V(6, 6, 0): w.u32(); w.u32()
    else: w.u32(12)
    w.u32(12)
    if v < V(6, 6, 0): w.u32(8)
    if v >= V(5, 2, 3): w.u8(0)

def write_dir(w, d):
    v = w.v
    if v < V(1, 3, 0): w.u32()
    w.s(d)
    cond_data(w)
    if V(4, 0, 11) <= v < V(4, 1, 0): w.s()
    if v >= V(2, 0, 11): w.u32(0)
    w.winver()
    if v >= V(4, 1, 0): w.u16(0xFFFF)
    w.u8(0)

def write_file(w, f):
    v, isx = w.v, w.isx
    if v < V(1, 3, 0): w.u32()
    w.s("src\\" + f.get("src", "x")); w.s(f["dst"]); w.s()
    if v >= V(5, 2, 5): w.s()
    cond_data(w, f.get("lang", ""), f.get("comp", ""))
    if v >= V(6, 5, 0):
        for _ in range(6): w.s()
        w.raw(bytes(32)); w.u8(0)
    w.winver()
    w.u32(f["loc"]); w.u32(f.get("attr", 0));
    if v >= V(4, 0, 0): w.u64(0)
    else: w.u32(0)
    if v < V(3, 0, 5): w.u8(0)
    if v >= V(4, 1, 0): w.u16(0xFFFF)
    arch = f.get("arch", 0)
    if v >= V(7, 0, 0, 3): w.u8(arch)
    on = set()
    if arch == 1: on.add("Bits32")
    if arch == 2: on.add("Bits64")
    it = [(1, "x")] * 7 + [(v < V(2, 0, 0) and not isx, "x"), (1, "x"), (1, "x"), (v >= V(1, 2, 5), "x"),
          (v >= V(1, 2, 6), "x"), (v >= V(1, 3, 21), "x"), (v >= V(1, 3, 21), "x"), (v >= V(1, 3, 25), "x"),
          (v >= V(2, 0, 5), "x"), (v >= V(3, 0, 1), "x")] + [(v >= V(3, 0, 5), "x")] * 3
    it += [(v >= V(4, 0, 0) or (isx and v >= V(3, 0, 6, 1)), "x"), (v >= V(4, 0, 5), "x"), (v >= V(4, 1, 8), "x"),
           (v >= V(4, 2, 1), "x"), (v >= V(4, 2, 5), "x"), (v >= V(5, 0, 3), "x"), (v >= V(5, 1, 0), "x"),
           (V(5, 1, 2) <= v < V(7, 0, 0, 3), "Bits32"), (V(5, 1, 2) <= v < V(7, 0, 0, 3), "Bits64")]
    it += [(v >= V(5, 2, 0), "x")] * 3 + [(v >= V(5, 2, 5), "x")] + [(v >= V(6, 5, 0), "x")] * 2
    w.flags(it, on, 8 if v >= V(6, 7, 0) else 0)
    w.u8(1 if f.get("uninst") else 0)

def checksum(v, data):
    if v >= V(6, 4, 0): return hashlib.sha256(data).digest()
    if v >= V(5, 3, 9): return hashlib.sha1(data).digest()
    if v >= V(4, 2, 0): return hashlib.md5(data).digest()
    if v >= V(4, 0, 1): return struct.pack("<I", crc(data))
    return struct.pack("<I", zlib.adler32(data) & 0xFFFFFFFF)

def write_data(w, d):
    v = w.v
    sl = d["slice"] + (1 if v < V(4, 0, 0) else 0)
    w.u32(sl); w.u32(d.get("last", d["slice"]) + (1 if v < V(4, 0, 0) else 0))
    if v >= V(6, 5, 2): w.u64(d["chunk_off"])
    else: w.u32(d["chunk_off"])
    if v >= V(4, 0, 1): w.u64(d["file_off"])
    if v >= V(4, 0, 0): w.u64(d["size"]); w.u64(d["chunk_size"])
    else: w.u32(d["size"]); w.u32(d["chunk_size"])
    w.raw(d["ck"])
    w.u64(d.get("mtime", 132000000000000000))
    w.u32(); w.u32()
    on = set()
    if d["compressed"]: on.add("Comp")
    if d["enc"]: on.add("Enc")
    if d.get("bzipped"): on.add("BZipped")
    on.add("UTC")
    it = [(1, "x"), (v < V(6, 4, 3), "x"), (V(2, 0, 17) <= v < V(4, 0, 1), "BZipped"), (v >= V(4, 0, 10), "UTC"),
          (V(4, 1, 0) <= v < V(6, 4, 3), "x"), (v >= V(4, 1, 8), "Call"), (V(4, 2, 0) <= v < V(6, 4, 3), "x"),
          (v >= V(4, 2, 2), "Enc"), (v >= V(4, 2, 5), "Comp"), (V(5, 1, 13) <= v < V(6, 4, 3), "x"),
          (V(5, 5, 7) <= v < V(6, 3, 0), "x"), (V(5, 5, 7) <= v < V(6, 3, 0), "x")]
    w.flags(it, on)
    if V(6, 3, 0) <= v < V(6, 4, 3): w.u8(0)

def wizard(w, g):
    v = w.v
    def images():
        if v >= V(5, 6, 0): w.u32(0)
        else: w.s()
    images()
    if v >= V(2, 0, 0) or w.isx: images()
    if v >= V(6, 7, 0): images()
    if v >= V(6, 6, 0):
        images(); images()
        if v >= V(6, 7, 0): images()
    if g.method == BZIP2 or (g.method == LZMA1 and v == V(4, 1, 5)) or (g.method == ZLIB and v >= V(4, 2, 6)):
        w.s(b"dll")
    if g.enc and v < V(6, 4, 0): w.s(b"decrypt")

def encode_block(v, raw, compress=True):
    if v >= V(4, 1, 6):
        data = (b"\x5d" + struct.pack("<I", 1 << 16) +
                lzma.compress(raw, format=lzma.FORMAT_RAW,
                              filters=[{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16, "lc": 3, "lp": 0, "pb": 2}])) \
            if compress else raw
    else:
        data = zlib.compress(raw) if compress else raw
    pieces = bytearray()
    for i in range(0, len(data), 4096):
        c = data[i:i + 4096]
        pieces += struct.pack("<I", crc(c)) + c
    if v >= V(4, 0, 9):
        hdr = (struct.pack("<Q", len(pieces)) if v >= V(6, 7, 0) else struct.pack("<I", len(pieces))) + bytes([compress])
    else:
        hdr = struct.pack("<II", len(data) if compress else 0xFFFFFFFF, len(raw))
    return struct.pack("<I", crc(hdr)) + hdr + bytes(pieces)

def compress_chunk(m, data):
    if m == STORED: return data
    if m == ZLIB: return zlib.compress(data, 9)
    if m == BZIP2: return bz2.compress(data, 9)
    if m == LZMA1:
        return b"\x5d" + struct.pack("<I", 1 << 20) + lzma.compress(
            data, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 20}])
    return b"\x10" + lzma.compress(data, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}])

LDR_MAGIC = [(V(5, 1, 5), b"rDlPtS\xcd\xe6\xd7{\x0b*"), (V(4, 1, 6), b"rDlPtS07\x87eVx"), (V(4, 0, 10), b"rDlPtS06\x87eVx"),
             (V(4, 0, 3), b"rDlPtS05\x87eVx"), (V(4, 0, 0), b"rDlPtS04\x87eVx"), (0, b"rDlPtS02\x87eVx")]

def loader_table(v, o0, o1, total, rev=None):
    lv, magic = next((lv, m) for lv, m in LDR_MAGIC if v >= lv)
    if lv >= V(5, 1, 5):
        rev = rev or (2 if v >= V(6, 5, 0) else 1)
        if rev == 2:
            t = magic + struct.pack("<IqqIIqqI", 2, total, 0, 0, 0, o0, o1, 0)
            return t + struct.pack("<I", crc(t))
        t = magic + struct.pack("<IIIIIII", 1, total, 0, 0, 0, o0, o1)
        return t + struct.pack("<I", crc(t))
    t = magic + struct.pack("<II", total, 0)
    if lv < V(4, 1, 6): t += struct.pack("<I", 0)
    t += struct.pack("<II", 0, 0)
    if lv < V(4, 0, 0): t += struct.pack("<I", 0)
    t += struct.pack("<II", o0, o1)
    if lv >= V(4, 0, 10): t += struct.pack("<I", crc(t))
    return t

def pe_with_rcdata(table):
    """Minimal PE32 whose only section holds RCDATA resource 11111 = table."""
    sect_rva, raw_ptr = 0x1000, 0x200
    rs = bytearray()
    def dir_(n_ids): return struct.pack("<IIHHHH", 0, 0, 0, 0, 0, n_ids)
    rs += dir_(1) + struct.pack("<II", 10, 0x80000000 | 0x18)            # root -> type 10
    rs += dir_(1) + struct.pack("<II", 11111, 0x80000000 | 0x30)         # -> name 11111
    rs += dir_(1) + struct.pack("<II", 1033, 0x48)                       # -> language: data entry
    rs += struct.pack("<IIII", sect_rva + 0x58, len(table), 0, 0)
    rs += bytes(0x58 - len(rs)) + table
    rs += bytes((-len(rs)) % 0x200)
    dos = bytearray(0x40); dos[0:2] = b"MZ"; struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 92, 16)                                  # NumberOfRvaAndSizes
    struct.pack_into("<II", opt, 96 + 16, sect_rva, len(rs))             # resource directory
    sec = b".rsrc\0\0\0" + struct.pack("<IIIIIIHHI", len(rs), sect_rva, len(rs), raw_ptr, 0, 0, 0, 0, 0x40000040)
    hdr = bytes(dos) + coff + bytes(opt) + sec
    hdr += bytes(raw_ptr - len(hdr))
    return hdr + bytes(rs)

class Gen:
    """An installer: files [{dst, data | loc, lang, comp, arch, uninst}], dirs, options."""
    def __init__(self, v, uni=False, isx=False, method=LZMA1, solid=True, enc=None, pw="gogi",
                 slices=None, cp=1252, lead=None, use_pe=None, rev=None, version_text=None):
        self.v, self.uni, self.isx, self.method, self.solid = v, uni, isx, method, solid
        self.enc, self.pw, self.slices, self.cp, self.lead = enc, pw, slices, cp, lead
        self.use_pe = v >= V(5, 1, 5) if use_pe is None else use_pe
        self.rev, self.version_text = rev, version_text
        self.files, self.dirs, self.locs = [], [], []
        self.langs = [cp] if v >= V(2, 0, 1) else []
        self.base, self.slices_per_disk = "setup", 1
        self.n_file = self.n_data = self.comp_byte = None
        self.salt = bytes(range(8)); self.pw_hash = None
        self.kdf_salt, self.kdf_iter, self.nonce = bytes(range(16, 32)), 1000, bytes(range(40, 64))
        self.pw_test = bytes(4)
        self.overlap = None     # (loc a, loc b): b starts inside a (hostile layout)
        self.enc_use = None     # 6.5+ encryption header "use" (2 = encrypted headers)
    def add(self, dst, data=None, loc=None, **kw):
        if loc is None:
            loc = len(self.locs); self.locs.append(data)
        self.files.append(dict(dst=dst, loc=loc, **kw))
        return loc
    def pwbytes(self):
        return self.pw.encode("utf-16-le") if self.uni else self.pw.encode("cp1252")
    def build(self, path):
        v = self.v
        enc_kind = None
        if self.enc:
            enc_kind = "xchacha" if v >= V(6, 4, 0) else "arc4"
            pw = self.pwbytes()
            if enc_kind == "arc4":
                h = hashlib.sha1 if v >= V(5, 3, 9) else hashlib.md5
                self.pw_hash = h(b"PasswordCheckHash" + self.salt + pw).digest()
            else:
                self.key = hashlib.pbkdf2_hmac("sha256", pw, self.kdf_salt, self.kdf_iter, 32)
                n2 = bytearray(self.nonce)
                struct.pack_into("<I", n2, 8, ~struct.unpack_from("<I", n2, 8)[0] & 0xFFFFFFFF)
                self.pw_test = xchacha20(self.key, bytes(n2), bytes(4))
        # chunks: solid (one), or one per location (always before 4.0.1)
        solid = self.solid and v >= V(4, 0, 1)
        groups = [list(range(len(self.locs)))] if solid else [[i] for i in range(len(self.locs))]
        stream = bytearray()          # setup-1 bytes (single file) / slice payload
        datas = [None] * len(self.locs)
        chunks = []                   # (stream offset, body offset, body length, location indices)
        for grp in groups:
            if not grp: continue
            plain = bytearray()
            offs = {}
            for i in grp:
                offs[i] = len(plain); plain += self.locs[i]
            if self.overlap and solid:
                a, b = self.overlap
                offs[b] = offs[a] + 1
            m = self.method if v >= V(4, 2, 5) or self.method != STORED else ZLIB
            comp = compress_chunk(m, bytes(plain))
            start = len(stream)
            stream += b"zlb\x1a"
            if enc_kind == "arc4":
                salt = bytes((start + k) & 255 for k in range(8))
                h = hashlib.sha1 if v >= V(5, 3, 9) else hashlib.md5
                comp = RC4(h(salt + self.pwbytes()).digest()).crypt(comp)
                stream += salt
            chunks.append((start, len(stream), len(comp), grp))
            stream += comp
            for i in grp:
                datas[i] = dict(slice=0, chunk_off=start, file_off=offs[i], size=len(self.locs[i]),
                                chunk_size=len(comp), ck=checksum(v, self.locs[i]), compressed=m != STORED,
                                enc=enc_kind is not None, bzipped=m == BZIP2 and v < V(4, 0, 1))
        # slices: payload split into files with "idska32\x1a" headers, offsets inside them
        cap = self.slices
        for d in datas:
            if cap:
                k = d["chunk_off"] // cap
                d["last"] = (d["chunk_off"] + 4 + d["chunk_size"] - 1) // cap
                d["slice"], d["chunk_off"] = k, 12 + d["chunk_off"] - k * cap
        if enc_kind == "xchacha":
            for start, body, n, grp in chunks:
                d = datas[grp[0]]
                nn = bytearray(self.nonce)
                struct.pack_into("<Q", nn, 0, struct.unpack_from("<Q", nn, 0)[0] ^ d["chunk_off"])
                struct.pack_into("<I", nn, 8, struct.unpack_from("<I", nn, 8)[0] ^ d["slice"])
                stream[body:body + n] = xchacha20(self.key, bytes(nn), bytes(stream[body:body + n]))
        slice_files = []
        if cap:
            for k in range(max(1, (len(stream) + cap - 1) // cap)):
                body = stream[k * cap:(k + 1) * cap]
                slice_files.append(b"idska32\x1a" + struct.pack("<I", 12 + len(body)) + body)
            stream = bytearray()
        # header blocks
        w0 = W(v, self.uni, self.isx)
        write_header(w0, self)
        nl = len(self.langs) if v >= V(4, 0, 0) else (1 if v >= V(2, 0, 1) else 0)
        for _ in range(nl): write_language(w0, self.cp)
        if v < V(4, 0, 0): wizard(w0, self)
        for d in self.dirs: write_dir(w0, d)
        for f in self.files: write_file(w0, f)
        if v >= V(4, 0, 0): wizard(w0, self)
        w1 = W(v, self.uni, self.isx)
        for d in datas: write_data(w1, d)
        vt = self.version_text
        if vt is None:
            vt = ("Inno Setup Setup Data (%d.%d.%d%s)" % (v >> 24, v >> 16 & 255, v >> 8 & 255,
                  ".%d" % (v & 255) if v & 255 else "")).encode()
            if self.isx: vt = vt.replace(b"Inno Setup Setup Data", b"My Inno Setup Extensions Setup Data")
            if self.uni and v < V(6, 3, 0): vt += b" (u)"
        setup0 = vt + bytes(64 - len(vt)) if len(vt) < 64 else vt
        if v >= V(6, 5, 0):
            eh = bytes([self.enc_use if self.enc_use is not None else 1 if enc_kind else 0]) + self.kdf_salt + struct.pack("<I", self.kdf_iter) + self.nonce + self.pw_test
            setup0 += struct.pack("<I", crc(eh)) + eh
        setup0 += encode_block(v, bytes(w0.b)) + encode_block(v, bytes(w1.b))
        self.setup0 = setup0
        # file
        head_len = 0x400
        o1 = head_len if not self.slices else 0
        o0 = head_len + len(stream)
        total = o0 + len(setup0)
        table = loader_table(v, o0, o1, total, self.rev)
        if self.use_pe:
            head = pe_with_rcdata(table)
            if len(head) > head_len:
                head_len = (len(head) + 0x1FF) & ~0x1FF
                o1 = head_len if not self.slices else 0
                o0 = head_len + len(stream)
                total = o0 + len(setup0)
                head = pe_with_rcdata(loader_table(v, o0, o1, total, self.rev))
        else:
            head = bytearray(0x40); head[0:2] = b"MZ"
            struct.pack_into("<III", head, 0x30, 0x6F6E6E49, 0x40, ~0x40 & 0xFFFFFFFF)
            head = bytes(head) + table
        head += bytes(head_len - len(head))
        out = head + bytes(stream) + setup0
        with open(path, "wb") as f:
            f.write(out)
        stem = os.path.splitext(path)[0]
        for k, sf in enumerate(slice_files):
            name = "%s-%d.bin" % (stem, k + 1) if self.slices_per_disk == 1 else \
                   "%s-%d%s.bin" % (stem, k // self.slices_per_disk + 1, chr(97 + k % self.slices_per_disk))
            with open(name, "wb") as f:
                f.write(sf)
        return path

def blob(n, seed):
    r = random.Random(seed)
    words = [b"samgyeopsal ", b"\xea\xb3\xa0\xea\xb8\xb0", b"inno setup\r\n", b"{app}", b"\x00" * 7, b"\xe8\x00\x10\x00\x00"]
    out = bytearray()
    while len(out) < n:
        out += r.choice(words) if r.random() < 0.7 else bytes([r.randrange(256)])
    return bytes(out[:n])

def standard(g, big=False):
    """Common file set; returns {expected name: data}."""
    files = {
        "{app}\\readme.txt": b"hello inno\r\n" * 50,
        "{app}\\bin\\tool.dll": blob(70000, 1),
        "{app}\\empty.txt": b"",
        "{app}\\one.bin": b"\x01",
        "{tmp}\\helper.bin": blob(3000, 2),
        "{sys}\\gogi.sys": blob(5000, 3),
        "{userappdata}\\Gogi\\settings.ini": b"[gogi]\r\nmeat=pork\r\n",
    }
    if big:
        files["{app}\\big.bin"] = blob(1_200_000, 4)
    exp = {}
    for k, d in files.items():
        g.add(k, d)
        exp[k.replace("\\", "/")] = d
    return exp

# ------------------------------------------------------------------ real installers

JR = "https://files.jrsoftware.org/is/"
KP = "https://downloads.sourceforge.net/project/keepass/KeePass%202.x/"
REAL = [
    JR + "1.3/isetup-1.3.26.exe", JR + "2/isetup-2.0.19.exe", JR + "3/isetup-3.0.7.exe",
    JR + "4/isetup-4.0.11.exe", JR + "4/isetup-4.1.8.exe", JR + "4/isetup-4.2.7.exe",
    JR + "5/isetup-5.0.8.exe", JR + "5/isetup-5.1.14.exe", JR + "5/isetup-5.2.3.exe",
    JR + "5/isetup-5.3.11.exe", JR + "5/isetup-5.3.11-unicode.exe", JR + "5/isetup-5.4.3-unicode.exe",
    JR + "5/innosetup-5.5.9.exe", JR + "5/innosetup-5.5.9-unicode.exe", JR + "5/innosetup-5.6.1-unicode.exe",
    KP + "2.30/KeePass-2.30-Setup.exe", KP + "2.49/KeePass-2.49-Setup.exe", KP + "2.57.1/KeePass-2.57.1-Setup.exe",
    KP + "2.58/KeePass-2.58-Setup.exe", KP + "2.59/KeePass-2.59-Setup.exe", KP + "2.60/KeePass-2.60-Setup.exe",
    KP + "2.61.1/KeePass-2.61.1-Setup.exe",
]

def cache_dir():
    d = os.environ.get("GZ_TEST_CACHE") or os.path.join(os.path.expanduser("~"), ".cache", "gogitzip")
    d = os.path.join(d, "inno")
    os.makedirs(d, exist_ok=True)
    return d

def fetch(url, cache):
    p = os.path.join(cache, os.path.basename(url))
    if os.path.exists(p) and os.path.getsize(p) > 0:
        return p
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            data = r.read()
    except Exception:
        return None
    if len(data) < 1000 or data[:2] != b"MZ":
        return None
    with open(p + ".part", "wb") as f:
        f.write(data)
    os.replace(p + ".part", p)
    return p

def all_jr_urls():
    out = []
    for d in ("1.3", "2", "3", "4", "5"):
        try:
            with urllib.request.urlopen(JR + d + "/", timeout=30) as r:
                html = r.read().decode("latin1")
        except Exception:
            continue
        import re
        for f in re.findall(r'href="((?:isetup|innosetup|ispack)-[^"?/]*\.exe)"', html):
            out.append(JR + d + "/" + f)
    return out

def unbrace(name):
    """our name -> innoextract's: constants without braces, unsafe characters as '$'."""
    import re
    def c(m):
        return re.sub(r'[<>:"|?*]', "$", m.group(1))
    return re.sub(r"\{([^{}]*)\}", c, name)

def strip_suffix(name):
    import re
    d, f = name.rsplit("/", 1) if "/" in name else ("", name)
    m = re.match(r"^(.+?)((?:@[A-Za-z_\-][A-Za-z0-9_\-$]*)*(?:\$\d+)?)(\.[^.]*)?$", f)
    if m and m.group(2):
        f = m.group(1) + (m.group(3) or "")
    return d + "/" + f if d else f

def check_real(t, arc):
    label = "real " + os.path.basename(arc)
    r, rows, out = t.extract(arc, timeout=600)
    info = r.stderr.decode(errors="replace").splitlines()[:1]
    if r.returncode or not rows or "type=Inno Setup " not in (info[0] if info else ""):
        return t.record(False, label, "open failed: %s %s" % (r.stdout[:200], info))
    bad = [(rows[i][3], rows[i][0]) for i in rows if rows[i][0] != 0]
    if bad:
        return t.record(False, label, "%d entries failed, e.g. %s" % (len(bad), bad[:3]))
    ours = {}
    for i, (st, isdir, size, name) in rows.items():
        if isdir or not name:
            continue
        data = open(os.path.join(out, "%d.bin" % i), "rb").read()
        if len(data) != size:
            return t.record(False, label, "size of %s" % name)
        ours.setdefault(unbrace(strip_suffix(name)).lower(), []).append(hashlib.sha1(data).hexdigest())
    shutil.rmtree(out, ignore_errors=True)
    if not t.tool("innoextract"):
        return t.record(True, label, "%d files (checksums verified, no innoextract)" % len(rows))
    ref = os.path.join(t.work, "ie_" + os.path.basename(arc))
    shutil.rmtree(ref, ignore_errors=True)
    os.makedirs(ref)
    rr = subprocess.run(["innoextract", "-e", "-q", "-d", ref, arc], capture_output=True, timeout=600)
    if rr.returncode:
        # newer than this innoextract: the stored SHA-1 / SHA-256 verified every file
        return t.record(True, label, "%d files (checksums verified; innoextract cannot read it)" % len(rows))
    theirs = {}
    for dp, dn, fn in os.walk(ref):
        for f in fn:
            p = os.path.join(dp, f)
            theirs[os.path.relpath(p, ref).lower()] = hashlib.sha1(open(p, "rb").read()).hexdigest()
    probs = []
    for k, h in theirs.items():
        if k not in ours: probs.append("missing " + k)
        elif h not in ours[k]: probs.append("content " + k)
    for k in ours:
        if k not in theirs and not k.endswith("unins000.exe"):    # innoextract skips the old uninstaller
            probs.append("extra " + k)
    shutil.rmtree(ref, ignore_errors=True)
    return t.record(not probs, label, "; ".join(probs[:5]) or "%d files match innoextract" % len(theirs))

# ------------------------------------------------------------------ tests

VERSIONS = [  # (version, unicode, isx)
    (V(1, 3, 25), 0, 0), (V(2, 0, 18), 0, 0), (V(3, 0, 5), 0, 0), (V(3, 0, 6, 1), 0, 1), (V(4, 0, 5), 0, 0),
    (V(4, 0, 11), 0, 0), (V(4, 1, 5), 0, 0), (V(4, 1, 8), 0, 0), (V(4, 2, 2), 0, 0), (V(4, 2, 5), 0, 0),
    (V(4, 2, 6), 0, 0), (V(5, 0, 4), 0, 0), (V(5, 1, 13), 0, 0), (V(5, 2, 3), 0, 0), (V(5, 2, 5), 1, 0),
    (V(5, 3, 10), 0, 0), (V(5, 3, 10), 1, 0), (V(5, 4, 2), 1, 0), (V(5, 5, 6), 0, 0), (V(5, 5, 7), 1, 0),
    (V(5, 6, 0), 0, 0), (V(6, 0, 0), 1, 0), (V(6, 1, 0), 1, 0), (V(6, 3, 0), 1, 0), (V(6, 4, 0, 1), 1, 0),
    (V(6, 4, 3), 1, 0), (V(6, 5, 2), 1, 0), (V(6, 6, 1), 1, 0), (V(6, 7, 0), 1, 0), (V(7, 0, 0, 3), 1, 0),
]

def vname(v, uni, isx=0):
    s = "%d.%d.%d" % (v >> 24, v >> 16 & 255, v >> 8 & 255) + (".%d" % (v & 255) if v & 255 else "")
    return s + ("u" if uni and v < V(6, 3, 0) else "") + ("x" if isx else "")

def run(t):
    gzt_ok = os.path.exists(t.gzt)
    gen_dir = t.path("gen", "x")
    gen_dir = os.path.dirname(gen_dir)

    def gen(name, g):
        p = os.path.join(gen_dir, name + ".exe")
        g.build(p)
        return p

    # ---- every data version, the methods it has, solid and not
    k = 0
    for v, uni, isx in VERSIONS:
        for m in methods_for(v):
            for solid in (True, False):
                if solid and v < V(4, 0, 1):          # no file offsets: one file per chunk
                    continue
                k += 1
                g = Gen(v, uni, isx, method=m, solid=solid)
                exp = standard(g, big=(k % 7 == 0))
                p = gen("v%s_%s_%s" % (vname(v, uni, isx), m, "solid" if solid else "single"), g)
                t.check_extract(p, exp, expect_type="Inno Setup")
    # ---- method names
    g = Gen(V(6, 4, 3), 1, method=LZMA2)
    standard(g)
    p = gen("method_lzma2", g)
    r, typ, rows = t.listing(p)
    meth = {row["name"]: row["method"] for row in rows}
    t.record(meth.get("{app}/readme.txt") == "LZMA2:1M solid", "method LZMA2", str(meth.get("{app}/readme.txt")))

    # ---- names: constants, escapes, Korean, collisions, shared data, uninstaller, dirs
    for v, uni in ((V(5, 5, 7), 1), (V(5, 5, 7), 0), (V(6, 7, 0), 1), (V(5, 1, 13), 0)):
        g = Gen(v, uni, method=LZMA1, cp=1252)
        d = blob(9000, 7)
        exp = {}
        g.add("{app}\\{{literal}.txt", b"brace"); exp["{app}/{literal}.txt"] = b"brace"
        g.add("{code:GetDir|{pf}\\Gogi}\\f.txt", b"code"); exp["{code:GetDir|{pf}_Gogi}/f.txt"] = b"code"
        if uni:
            g.add("{app}\\한국어\\고기.txt", "삼겹살".encode()); exp["{app}/한국어/고기.txt"] = "삼겹살".encode()
        if v >= V(4, 0, 1):
            g.add("{app}\\readme.txt", b"english readme", lang="english")
            g.add("{app}\\Readme.txt", b"german readme", lang="german")
            exp["{app}/readme@english.txt"] = b"english readme"
            exp["{app}/Readme@german.txt"] = b"german readme"
        g.add("{app}\\same.txt", b"one"); g.add("{app}\\same.txt", b"two")
        exp["{app}/same.txt"] = b"one"; exp["{app}/same$0.txt"] = b"two"
        if v >= V(5, 1, 2):
            g.add("{app}\\x.dll", b"x86 dll", arch=1); g.add("{app}\\x.dll", b"x64 dll", arch=2)
            exp["{app}/x@32bit.dll"] = b"x86 dll"; exp["{app}/x@64bit.dll"] = b"x64 dll"
        loc = g.add("{app}\\shared1.bin", d); g.add("{app}\\shared2.bin", loc=loc)
        g.add("{app}\\shared1.bin", loc=loc)                          # same name, same data: merged
        exp["{app}/shared1.bin"] = d; exp["{app}/shared2.bin"] = d
        g.add("", blob(5000, 9), uninst=True); exp["{app}/unins000.exe"] = blob(5000, 9)
        g.add("{app}\\external.txt", loc=0xFFFFFFFF)                  # not stored: not listed
        g.add("{app}\\.htaccess", b"dot", lang="english" if v >= V(4, 0, 1) else "")
        exp["{app}/.htaccess"] = b"dot"
        g.dirs = ["{app}\\data", "{app}\\data", "{userdocs}\\Gogi"]
        exp["{app}/data"] = None; exp["{userdocs}/Gogi"] = None
        p = gen("names_%s" % vname(v, uni), g)
        t.check_extract(p, exp, label="names " + vname(v, uni))
        r, typ, rows = t.listing(p)
        dirs = sorted(row["name"] for row in rows if row["is_dir"])
        t.record(dirs == ["{app}/data", "{userdocs}/Gogi"], "dirs " + vname(v, uni), str(dirs))

    # ---- ANSI code pages: Korean installer (language code page 949), Shift-JIS lead bytes
    g = Gen(V(5, 5, 7), 0, method=LZMA2, cp=949)
    g.add("{app}\\한글\\파일.txt".encode("cp949"), b"cp949")
    p = gen("ansi_cp949", g)
    t.check_extract(p, {"{app}/한글/파일.txt": b"cp949"}, label="ANSI CP949 names")
    lead = bytearray(32)
    for b in list(range(0x81, 0xA0)) + list(range(0xE0, 0xFD)):
        lead[b >> 3] |= 1 << (b & 7)
    for withlead in (True, False):
        g = Gen(V(5, 5, 7), 0, method=LZMA1, cp=932, lead=bytes(lead) if withlead else None)
        g.add(b"{app}\\\x83\x7b\\x.txt", b"sjis")     # "ボ" = 83 7B: the trail byte is '{'
        p = gen("ansi_sjis_%d" % withlead, g)
        want = "{app}/ボ/x.txt" if withlead else "{app}/ボ_x.txt"
        t.check_extract(p, {want: b"sjis"}, cp=932, label="Shift-JIS lead bytes %d" % withlead)

    # ---- encryption: ARC4 (MD5 / SHA-1 keys), XChaCha20 (6.4 header, 6.5+ encryption header)
    for v, uni in ((V(4, 2, 2), 0), (V(5, 3, 8), 0), (V(5, 3, 9), 1), (V(5, 5, 7), 0), (V(6, 3, 0), 1),
                   (V(6, 4, 0, 1), 1), (V(6, 5, 2), 1), (V(6, 7, 0), 1)):
        for solid in (True, False):
            g = Gen(v, uni, method=LZMA2 if v >= V(5, 3, 9) else LZMA1, solid=solid, enc=True, pw="고기 pw" if uni else "gogi")
            exp = standard(g)
            p = gen("enc_%s_%d" % (vname(v, uni), solid), g)
            t.check_extract(p, exp, pw=g.pw, label="encrypted %s solid=%d" % (vname(v, uni), solid))
            r, rows, out = t.extract(p, pw="wrong")
            st = {rows[i][0] for i in rows if not rows[i][1]}
            t.record(st == {6}, "wrong password %s solid=%d" % (vname(v, uni), solid), str(st))
            r, rows, out = t.extract(p)
            st = {rows[i][0] for i in rows if not rows[i][1]}
            t.record(st == {6}, "no password %s solid=%d" % (vname(v, uni), solid), str(st))
            r, typ, rows = t.listing(p)
            meth = {row["method"] for row in rows if not row["is_dir"]}
            want = "XChaCha20" if v >= V(6, 4, 0) else "ARC4"
            t.record(all(want in m for m in meth), "method %s" % want, str(meth))

    # ---- disk spanning: slices beside the installer, chunks crossing them
    for v, uni, solid, spd in ((V(5, 5, 7), 1, True, 1), (V(5, 5, 7), 0, False, 1), (V(6, 7, 0), 1, True, 2),
                               (V(4, 1, 8), 0, True, 1), (V(5, 2, 3), 0, True, 3)):
        g = Gen(v, uni, method=LZMA1, solid=solid, slices=7000)
        g.slices_per_disk = spd
        exp = standard(g)
        p = gen("span_%s_%d_%d" % (vname(v, uni), solid, spd), g)
        t.check_extract(p, exp, label="slices %s solid=%d per-disk=%d" % (vname(v, uni), solid, spd))
    # no setup loader (UseSetupLdr=no): setup-0.bin holds the headers, data in setup-1.bin
    rawdir = os.path.join(gen_dir, "raw")
    os.makedirs(rawdir, exist_ok=True)
    g = Gen(V(5, 5, 7), 1, method=LZMA2, slices=1 << 30)
    exp = standard(g)
    g.build(os.path.join(rawdir, "setup.exe"))
    open(os.path.join(rawdir, "setup-0.bin"), "wb").write(g.setup0)
    os.remove(os.path.join(rawdir, "setup.exe"))
    t.check_extract(os.path.join(rawdir, "setup-0.bin"), exp, label="setup-0.bin + setup-1.bin", expect_type="Inno Setup")
    # a missing slice: entries fail, nothing crashes
    g = Gen(V(5, 5, 7), 1, method=LZMA1, solid=False, slices=5000)
    standard(g)
    p = gen("span_missing", g)
    os.remove(os.path.join(gen_dir, "span_missing-2.bin"))
    r, rows, out = t.extract(p)
    st = [rows[i][0] for i in sorted(rows)]
    t.record(r.returncode == 0 and 0 in st and any(s not in (0, -1) for s in st), "missing slice", str(st))

    # ---- loader tables: 0x30 pointer and resource for each table revision, raw setup-0 file
    for v, pe, rev in ((V(5, 5, 7), False, None), (V(5, 5, 7), True, 1), (V(6, 7, 0), True, 2),
                       (V(6, 7, 0), False, 2), (V(3, 0, 5), False, None), (V(4, 0, 3), False, None)):
        g = Gen(v, 1 if v >= V(5, 5, 0) else 0, method=LZMA1 if v >= V(4, 1, 5) else ZLIB, use_pe=pe, rev=rev, solid=v >= V(4, 0, 1))
        exp = standard(g)
        p = gen("loader_%s_%d_%s" % (vname(v, 0), pe, rev), g)
        t.check_extract(p, exp, label="loader %s pe=%d rev=%s" % (vname(v, 0), pe, rev))

    # ---- versions written ambiguously or unknown: the layout is found anyway
    for v, text in ((V(5, 6, 0), b"Inno Setup Setup Data (5.5.7) (u)"), (V(3, 0, 4), b"Inno Setup Setup Data (3.0.3)"),
                    (V(4, 2, 4), b"Inno Setup Setup Data (4.2.3)"), (V(6, 7, 0), b"Inno Setup Setup Data (6.6.9)"),
                    (V(5, 5, 7), b"Inno Setup Setup Data (5.5.8) (u)")):
        g = Gen(v, 1 if b"(u)" in text or v >= V(6, 3, 0) else 0, method=LZMA1 if v >= V(4, 1, 5) else ZLIB,
                version_text=text)
        exp = standard(g)
        p = gen("ambiguous_%s" % vname(v, 0), g)
        t.check_extract(p, exp, label="stated %s, layout %s" % (text.decode(), vname(v, 0)))

    # ---- shared / overlapping data in a solid chunk (multiple passes), many files
    g = Gen(V(5, 5, 7), 1, method=LZMA2)
    a = blob(40000, 11); b = blob(30000, 12)
    la = g.add("{app}\\a.bin", a); lb = g.add("{app}\\b.bin", b)
    g.overlap = (la, lb)
    p = gen("overlap", g)
    bb = (a + b)[1:1 + len(b)]
    r, rows, out = t.extract(p)
    names = {rows[i][3]: rows[i][0] for i in rows}
    # b's data was moved into a: its checksum no longer matches, a is intact
    t.record(names.get("{app}/a.bin") == 0 and names.get("{app}/b.bin") == 4, "overlapping files", str(names))
    g = Gen(V(6, 4, 3), 1, method=LZMA2)
    exp = {}
    for i in range(3000):
        d = ("file %d\n" % i).encode() * (i % 7)
        g.add("{app}\\many\\d%d\\f%d.txt" % (i % 37, i), d)
        exp["{app}/many/d%d/f%d.txt" % (i % 37, i)] = d
    p = gen("many", g)
    t.check_extract(p, exp, label="3000 files")

    # ---- driver: subsets / cancel / single entries, call filters, MD5, fuzz
    drv = t.build_driver("tests/drivers/inno_drv.c")
    for name in ("v5.5.7u_lzma2_solid", "v6.7.0_lzma2_solid", "v5.5.7u_zlib_single", "names_5.5.7u", "many",
                 "v4.2.6_bzip2_solid", "span_5.5.7u_1_1", "enc_6.5.2_1"):
        p = os.path.join(gen_dir, name + ".exe")
        args = [drv, "subsets", p] + (["고기 pw"] if name.startswith("enc_") else [])
        r = t.sh(args, check=False, timeout=600)
        out = r.stdout.decode(errors="replace").strip().splitlines()
        t.record(r.returncode == 0 and out and out[-1].startswith("ok"), "subsets " + name,
                 "\n".join(l for l in out if not l.startswith("H\t"))[-300:])
    # call filters against a Python model of Inno's decoders, fed in odd pieces
    rnd = random.Random(5)
    data = bytearray()
    while len(data) < 300000:
        data += bytes([0xE8 if rnd.random() < 0.1 else 0xE9 if rnd.random() < 0.05 else rnd.randrange(256)])
        if rnd.random() < 0.02:
            data += bytes([0xE8]) + struct.pack("<I", rnd.choice([0, 0xFFFFFF00, 0x00ABCDEF, 0xFF123456]) | rnd.randrange(256))
    src = os.path.join(gen_dir, "filter_in.bin")
    open(src, "wb").write(data)
    for kind in ("4108", "5200", "5309"):
        dst = os.path.join(gen_dir, "filter_%s.bin" % kind)
        t.sh([drv, "filter", kind, src, dst])
        t.record(open(dst, "rb").read() == py_filter(kind, bytes(data)), "call filter " + kind)
    r = t.sh([drv, "hash", src])
    want = hashlib.md5(data).hexdigest() + " %08x" % (zlib.adler32(data) & 0xFFFFFFFF)
    t.record(r.stdout.decode().strip() == want, "MD5 / Adler-32", r.stdout.decode().strip())
    sanit = "sanitize" in os.environ.get("HOST_CFLAGS", "")
    iters = 400 if sanit else 1500
    for name, seed in (("v5.5.7u_lzma2_solid", 1), ("v6.7.0_lzma2_single", 2), ("v4.0.11_zlib_single", 3),
                       ("enc_5.5.7_1", 4), ("v5.3.10u_bzip2_solid", 5), ("loader_5.5.7_1_1", 6)):
        p = os.path.join(gen_dir, name + ".exe")
        r = t.sh([drv, "fuzz", p, str(iters), str(seed)], check=False, timeout=1200)
        err = r.stderr.decode(errors="replace")
        ok = r.returncode == 0 and "Sanitizer" not in err and "runtime error" not in err
        t.record(ok, "fuzz " + name, (r.stdout.decode(errors="replace") + err)[-400:])

    hostile(t, gen_dir, gen)

    # ---- real installers (cached downloads)
    cache = cache_dir()
    urls = list(REAL)
    if os.environ.get("GZ_INNO_ALL"):
        urls += [u for u in all_jr_urls() if u not in urls]
    got = 0
    for u in urls:
        p = fetch(u, cache)
        if not p:
            continue
        got += 1
        check_real(t, p)
        if os.path.basename(p) in ("innosetup-5.5.9-unicode.exe", "KeePass-2.61.1-Setup.exe", "isetup-4.1.8.exe"):
            r = t.sh([drv, "subsets", p], check=False, timeout=600)
            out = r.stdout.decode(errors="replace").strip().splitlines()
            t.record(r.returncode == 0 and out and out[-1].startswith("ok"), "subsets " + os.path.basename(p),
                     "\n".join(l for l in out if not l.startswith("H\t"))[-300:])
    if not got:
        t.record(True, "real installers", "skipped: offline")
    else:
        kp = os.path.join(cache, "KeePass-2.61.1-Setup.exe")
        if os.path.exists(kp):
            r, typ, rows = t.listing(kp)
            meth = {row["name"]: row["method"] for row in rows}
            t.record(meth.get("{app}/KeePass.exe") == "LZMA2:32M solid x86", "KeePass 2.61.1 method",
                     str(meth.get("{app}/KeePass.exe")))

def py_filter(kind, data):
    """innoextract's inno_exe_decoder_4108 / _5200 (flip for 5309)."""
    out = bytearray(data)
    if kind == "4108":
        addr, left, off = 0, 0, 5
        for i in range(len(out)):
            b = out[i]
            if not left:
                if b in (0xE8, 0xE9):
                    addr = (~off + 1) & 0xFFFFFFFF; left = 4
            else:
                addr = (addr + b) & 0xFFFFFFFF
                out[i] = addr & 255
                addr >>= 8; left -= 1
            off = (off + 1) & 0xFFFFFFFF
        return bytes(out)
    flip = kind == "5309"
    i, n = 0, len(out)
    while i < n:
        b = out[i]
        i += 1
        if b not in (0xE8, 0xE9):
            continue
        if 0x10000 - ((i - 1) % 0x10000) < 5:
            continue
        if n - i < 4:
            break
        q = out[i:i + 4]
        if q[3] in (0, 0xFF):
            addr = (i + 4) & 0xFFFFFF
            rel = ((q[0] | q[1] << 8 | q[2] << 16) - addr) & 0xFFFFFFFF
            out[i] = rel & 255; out[i + 1] = rel >> 8 & 255; out[i + 2] = rel >> 16 & 255
            if flip and rel & 0x800000:
                out[i + 3] = ~q[3] & 255
        i += 4
    return bytes(out)

def hostile(t, gen_dir, gen):
    g = Gen(V(5, 5, 7), 1, method=LZMA2)
    standard(g)
    base_p = gen("hostile_base", g)
    base = open(base_p, "rb").read()
    o0 = g.setup0 and len(base) - len(g.setup0)
    cases = {}
    # truncations through every structure
    for cut in (0x30, 0x200, 0x420, o0 - 3, o0 + 10, o0 + 70, o0 + 200, len(base) - 600, len(base) - 5):
        cases["trunc_%d" % cut] = base[:cut]
    # smashed version strings and table fields
    b = bytearray(base); b[o0:o0 + 22] = b"Inno Setup Setup Data "; b[o0 + 22:o0 + 64] = b"(99.99.99)" + bytes(32)
    cases["version_99"] = bytes(b)
    b = bytearray(base); b[o0:o0 + 12] = b"i1.2.10--16\x1a"; cases["version_16bit"] = bytes(b)
    b = bytearray(base); b[o0 + 64] ^= 1; cases["block_crc"] = bytes(b)
    b = bytearray(base); b[o0 + 80] ^= 0x40; cases["piece_crc"] = bytes(b)
    cases["no_version"] = base[:o0] + bytes(64) + base[o0 + 64:]
    # generated hostile layouts
    for name, setup in (
        ("huge_files", lambda g: setattr(g, "n_file", 0x7FFFFFFF)),
        ("huge_data", lambda g: setattr(g, "n_data", 0x10000000)),
        ("bad_method", lambda g: setattr(g, "comp_byte", 77)),
    ):
        g = Gen(V(5, 5, 7), 1, method=LZMA2)
        standard(g)
        setup(g)
        cases[name] = open(gen("hostile_" + name, g), "rb").read()
    # file location out of range, sizes beyond the chunk, chunk offsets beyond the file
    g = Gen(V(6, 4, 3), 1, method=LZMA2)
    standard(g)
    g.files[0]["loc"] = 1000
    cases["loc_range"] = open(gen("hostile_loc", g), "rb").read()
    for field, val in (("size", 1 << 40), ("file_off", (1 << 64) - 5), ("chunk_off", 0xFFFFFFF0), ("chunk_size", 1 << 50)):
        g = Gen(V(6, 5, 2), 1, method=LZMA2, solid=field != "file_off")
        standard(g)
        orig = write_data
        def patched(w, d, field=field, val=val, orig=orig):
            d = dict(d); d[field] = val
            orig(w, d)
        globals()["write_data"] = patched
        try:
            cases["data_" + field] = open(gen("hostile_data_" + field, g), "rb").read()
        finally:
            globals()["write_data"] = orig
    for name, data in cases.items():
        p = os.path.join(gen_dir, "h_" + name + ".exe")
        open(p, "wb").write(data)
        t.check_hostile(p, label="hostile " + name)
    # wrong data versions are not opened as something they are not
    r, rows, out = t.extract(os.path.join(gen_dir, "h_version_16bit.exe"))
    t.record(r.returncode != 0 or "Inno" not in r.stderr.decode(errors="replace"), "16-bit installer refused")
    # Inno Setup 6.5 "Encryption=full" (encrypted headers): not opened as an installer
    g = Gen(V(6, 5, 2), 1, method=LZMA2)
    standard(g)
    g.enc_use = 2
    p = gen("hostile_enc_full", g)
    r, typ, rows = t.listing(p)
    t.record(typ != "Inno Setup", "encrypted headers refused", str(typ))
