"""NTFS images: boot sector / $MFT geometry variants (512/4096-byte sectors, 512 B..64 KiB
clusters), names (Win32 / POSIX / DOS 8.3), hard links, alternate data streams, sparse files,
LZNT1 compressed files, WOF system compression (XPRESS 4K/8K/16K, LZX), reparse points and
Interix symlinks, EFS, attribute lists (fragmented files, many links), a fragmented and
attribute-listed $MFT, files > 4 GiB, metafiles in [SYSTEM], random-access views, threads,
nested archives, MBR container, hostile images.

Fixtures come from mkntfs + ntfscp (no mount) and, when FUSE works, from a ntfs-3g mount
(compression, sparse files, links, attributes); special structures are patched in with the
small NTFS editor below. 7-Zip and ntfscat (libntfs-3g) are the references."""
import os, io, random, shutil, struct, subprocess, zlib, zipfile, contextlib

ENV = dict(os.environ, LANG="C.UTF-8", LC_ALL="C.UTF-8", TZ="UTC")
FT_EPOCH = 11644473600
GZ_E_METHOD = 5

def blob(n, seed=1, text=False):
    rnd = random.Random(seed * 7919 + n)
    if not text:
        return rnd.randbytes(n)
    words = [b"\xea\xb3\xa0\xea\xb8\xb0", b"meat", b"grill", b"zip", b"ntfs", b"\n", b"cluster", b"record"]
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(words) + b" "
    return bytes(out[:n])

def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]

# ---------------------------------------------------------------- small NTFS editor

def decode_runs(mp):
    """mapping pairs -> [(vcn, lcn or None, len)]"""
    out, i, vcn, lcn = [], 0, 0, 0
    while i < len(mp) and mp[i]:
        ls, os_ = mp[i] & 15, mp[i] >> 4
        i += 1
        ln = int.from_bytes(mp[i:i + ls], "little"); i += ls
        if os_:
            lcn += int.from_bytes(mp[i:i + os_], "little", signed=True); i += os_
            out.append((vcn, lcn, ln))
        else:
            out.append((vcn, None, ln))
        vcn += ln
    return out

def encode_runs(runs):
    out, prev = bytearray(), 0
    for vcn, lcn, ln in runs:
        lb = ln.to_bytes((ln.bit_length() + 8) // 8, "little")
        if lcn is None:
            out += bytes([len(lb)]) + lb
            continue
        d = lcn - prev
        n = 1
        while not (-(1 << (8 * n - 1)) <= d < (1 << (8 * n - 1))):
            n += 1
        out += bytes([len(lb) | (n << 4)]) + lb + d.to_bytes(n, "little", signed=True)
        prev = lcn
    return bytes(out + b"\0")

class Vol:
    """minimal NTFS reader / patcher (whole image in memory)"""
    def __init__(self, path):
        self.path = path
        self.d = bytearray(open(path, "rb").read())
        b = self.d
        self.ss = u16(b, 11)
        spc = b[13]
        self.cs = self.ss * (spc if spc <= 0x80 else 1 << (256 - spc))
        v = struct.unpack_from("b", b, 0x40)[0]
        self.rs = v * self.cs if v > 0 else 1 << -v
        self.mft_lcn, self.mirr_lcn = u64(b, 0x30), u64(b, 0x38)
        r0 = self.unfix(bytearray(b[self.mft_lcn * self.cs:self.mft_lcn * self.cs + self.rs]))
        self.mft_runs = []
        for a in self.attrs(r0):
            if a["type"] == 0x80 and a["nonres"] and not a["name"]:
                self.mft_runs += decode_runs(r0[a["off"] + u16(r0, a["off"] + 0x20):a["off"] + a["len"]])
                self.mft_size = u64(r0, a["off"] + 0x30)
        self.nrec = self.mft_size // self.rs

    def save(self, path=None):
        with open(path or self.path, "wb") as f:
            f.write(self.d)

    @staticmethod
    def unfix(rec):
        uo, un = u16(rec, 4), u16(rec, 6)
        st = len(rec) // (un - 1)
        for i in range(1, un):
            p = i * st - 2
            rec[p:p + 2] = rec[uo + 2 * i:uo + 2 * i + 2]
        return rec

    @staticmethod
    def fix(rec):
        uo, un = u16(rec, 4), u16(rec, 6)
        st = len(rec) // (un - 1)
        usn = (u16(rec, uo) + 1) & 0xFFFF or 1
        struct.pack_into("<H", rec, uo, usn)
        for i in range(1, un):
            p = i * st - 2
            rec[uo + 2 * i:uo + 2 * i + 2] = rec[p:p + 2]
            struct.pack_into("<H", rec, p, usn)
        return rec

    def phys(self, runs, off, n):
        """[(image offset, length)] of bytes [off, off + n) of a run-mapped stream"""
        out = []
        while n:
            vcn = off // self.cs
            for v, l, ln in runs:
                if v <= vcn < v + ln:
                    inr = off - v * self.cs
                    take = min(n, ln * self.cs - inr)
                    out.append((l * self.cs + inr, take))
                    off += take; n -= take
                    break
            else:
                raise ValueError("offset not mapped")
        return out

    def rec_raw(self, n):
        return b"".join(bytes(self.d[o:o + l]) for o, l in self.phys(self.mft_runs, n * self.rs, self.rs))

    def get(self, n):
        return self.unfix(bytearray(self.rec_raw(n)))

    def put_raw(self, n, rec):
        pos = 0
        for o, l in self.phys(self.mft_runs, n * self.rs, self.rs):
            self.d[o:o + l] = rec[pos:pos + l]
            pos += l

    def put(self, n, rec):
        raw = self.fix(bytearray(rec))
        self.put_raw(n, raw)
        if n < 4:                                   # keep $MFTMirr in step
            o = self.mirr_lcn * self.cs + n * self.rs
            self.d[o:o + self.rs] = raw

    @staticmethod
    def attrs(rec):
        out, p = [], u16(rec, 0x14)
        while p + 8 <= len(rec) and u32(rec, p) != 0xFFFFFFFF:
            ln = u32(rec, p + 4)
            if ln < 0x18:
                break
            nl, no = rec[p + 9], u16(rec, p + 10)
            out.append(dict(off=p, type=u32(rec, p), len=ln, nonres=rec[p + 8],
                            name=rec[p + no:p + no + 2 * nl].decode("utf-16le"), inst=u16(rec, p + 14)))
            p += ln
        return out

    def names(self, rec):
        out = []
        for a in self.attrs(rec):
            if a["type"] == 0x30 and not a["nonres"]:
                v = a["off"] + u16(rec, a["off"] + 0x14)
                out.append((rec[v + 0x42:v + 0x42 + 2 * rec[v + 0x40]].decode("utf-16le"), u64(rec, v)))
        return out

    def find(self, name):
        for n in range(self.nrec):
            raw = self.rec_raw(n)
            if raw[:4] != b"FILE" or not (u16(raw, 0x16) & 1):
                continue
            rec = self.get(n)
            if any(nm == name for nm, _ in self.names(rec)):
                return u64(rec, 0x20) & 0xFFFFFFFFFFFF if u64(rec, 0x20) else n   # base record
        raise KeyError(name)

    def attr(self, rec, type_, name=""):
        for a in self.attrs(rec):
            if a["type"] == type_ and a["name"] == name:
                return a
        raise KeyError(type_)

    def runs_of(self, rec, a):
        o = a["off"]
        return decode_runs(rec[o + u16(rec, o + 0x20):o + a["len"]])

    def data_of(self, rec, a):
        o = a["off"]
        if not a["nonres"]:
            v = o + u16(rec, o + 0x14)
            return bytes(rec[v:v + u32(rec, o + 0x10)])
        size = u64(rec, o + 0x30)
        out = bytearray()
        for v, l, ln in self.runs_of(rec, a):
            out += bytes(ln * self.cs) if l is None else self.d[l * self.cs:(l + ln) * self.cs]
        return bytes(out[:size])

    def free_clusters(self, n, after=0):
        """first run of n free clusters (from $Bitmap) at or after cluster 'after'"""
        rec = self.get(6)
        bm = self.data_of(rec, self.attr(rec, 0x80))
        total = len(self.d) // self.cs - 2
        run = 0
        for c in range(after, total):
            if bm[c >> 3] & (1 << (c & 7)):
                run = 0
            else:
                run += 1
                if run == n:
                    return c - n + 1
        raise ValueError("no space")

    def set_bitmap(self, lcn, n):
        rec = self.get(6)
        bm_runs = self.runs_of(rec, self.attr(rec, 0x80))
        for c in range(lcn, lcn + n):
            for o, _ in self.phys(bm_runs, c >> 3, 1):
                self.d[o] |= 1 << (c & 7)

def set_attr_runs(vol, rec, a, runs, lowest=0):
    """replace the mapping pairs of non-resident attribute a (must fit in the record)"""
    o, mo = a["off"], u16(rec, a["off"] + 0x20)
    mp = encode_runs(runs)
    newlen = (mo + len(mp) + 7) & ~7
    body = bytes(rec[o:o + mo]) + mp + bytes(newlen - mo - len(mp))
    rest = bytes(rec[o + a["len"]:u32(rec, 0x18)])
    used = o + newlen + len(rest)
    if used > vol.rs:
        raise ValueError("runs do not fit")
    rec[o:o + newlen + len(rest)] = body + rest
    struct.pack_into("<I", rec, o + 4, newlen)
    struct.pack_into("<Q", rec, o + 0x10, lowest)
    struct.pack_into("<Q", rec, o + 0x18, (runs[-1][0] + runs[-1][2] - 1) if runs else 0)
    struct.pack_into("<I", rec, 0x18, used)
    return rec

def nonres_attr(type_, inst, lowest, runs, sizes=(0, 0, 0)):
    """non-resident attribute (no name); sizes = (allocated, data, initialized)"""
    mp = encode_runs(runs)
    ln = (0x40 + len(mp) + 7) & ~7
    a = bytearray(ln)
    struct.pack_into("<IIBBHHH", a, 0, type_, ln, 1, 0, 0x40, 0, inst)
    struct.pack_into("<QQHH", a, 0x10, lowest, runs[-1][0] + runs[-1][2] - 1, 0x40, 0)
    struct.pack_into("<QQQ", a, 0x28, *sizes)
    a[0x40:0x40 + len(mp)] = mp
    return bytes(a)

def res_attr(type_, inst, value):
    ln = (0x18 + len(value) + 7) & ~7
    a = bytearray(ln)
    struct.pack_into("<IIBBHHHIHBB", a, 0, type_, ln, 0, 0, 0x18, 0, inst, len(value), 0x18, 0, 0)
    a[0x18:0x18 + len(value)] = value
    return bytes(a)

def al_entry(type_, vcn, ref, inst, name=""):
    nm = name.encode("utf-16le")
    ln = (0x1A + len(nm) + 7) & ~7
    e = bytearray(ln)
    struct.pack_into("<IHBBQQH", e, 0, type_, ln, len(name), 0x1A, vcn, ref, inst)
    e[0x1A:0x1A + len(nm)] = nm
    return bytes(e)

def splice_attr(vol, rec, off, oldlen, new):
    """replace oldlen bytes of attributes at off with new (0 = insert)"""
    used = u32(rec, 0x18)
    tail = bytes(rec[off + oldlen:used])
    nu = off + len(new) + len(tail)
    if nu > vol.rs:
        raise ValueError("record full")
    rec[off:nu] = new + tail
    if nu < used:
        rec[nu:used] = bytes(used - nu)
    struct.pack_into("<I", rec, 0x18, nu)
    return rec

def make_ext_record(vol, recno, base_ref, attr_bytes):
    rs = vol.rs
    rec = bytearray(rs)
    rec[0:4] = b"FILE"
    un = rs // 512 + 1
    aoff = (0x30 + 2 * un + 7) & ~7
    struct.pack_into("<HHQHHHH", rec, 4, 0x30, un, 0, 1, 0, aoff, 1)
    struct.pack_into("<IIQHHI", rec, 0x18, aoff + len(attr_bytes) + 8, rs, base_ref, 1, 0, recno)
    struct.pack_into("<H", rec, 0x30, 1)
    rec[aoff:aoff + len(attr_bytes)] = attr_bytes
    struct.pack_into("<I", rec, aoff + len(attr_bytes), 0xFFFFFFFF)
    return rec

def runs_from_clusters(cl):
    runs, vcn = [], 0
    for c in cl:
        if runs and runs[-1][1] + runs[-1][2] == c:
            runs[-1] = (runs[-1][0], runs[-1][1], runs[-1][2] + 1)
        else:
            runs.append((vcn, c, 1))
        vcn += 1
    return runs

def fragment_mft(src, dst, pieces=12, with_al=False):
    """copy src to dst and scatter the $MFT (after the first 32 records) over free clusters;
    with_al: the tail of the runlist moves to extension record 16 through an attribute list"""
    shutil.copy(src, dst)
    v = Vol(dst)
    rec0 = v.get(0)
    a = v.attr(rec0, 0x80)
    runs = v.runs_of(rec0, a)
    cl = [l + i for _, l, n in runs for i in range(n)]
    keep = max(2, (32 * v.rs + v.cs - 1) // v.cs)
    new, rest = cl[:keep], cl[keep:]
    step = max(1, (len(rest) + pieces - 1) // pieces)
    pos = 0
    for i in range(0, len(rest), step):
        chunk = rest[i:i + step]
        dstc = v.free_clusters(len(chunk), after=pos)
        for k, c in enumerate(chunk):
            v.d[(dstc + k) * v.cs:(dstc + k + 1) * v.cs] = v.d[c * v.cs:(c + 1) * v.cs]
            v.d[c * v.cs:(c + 1) * v.cs] = bytes(v.cs)        # stale copies must not be read
        v.set_bitmap(dstc, len(chunk))
        new += [dstc + k for k in range(len(chunk))]
        pos = dstc + len(chunk) + 7
    nruns = runs_from_clusters(new)
    v.mft_runs = nruns
    if not with_al:
        set_attr_runs(v, rec0, a, nruns)
        v.put(0, rec0)
        v.save()
        return len(nruns)
    half = len(nruns) // 2
    xv = nruns[half][0]
    seq0 = u16(rec0, 0x10)
    ext = 16
    assert not (u16(v.rec_raw(ext), 0x16) & 1)
    v.put(ext, make_ext_record(v, ext, seq0 << 48, nonres_attr(0x80, 0, xv, nruns[half:])))
    set_attr_runs(v, rec0, v.attr(rec0, 0x80), nruns[:half])
    ents = []
    for x in v.attrs(rec0):
        ents.append((x["type"], x["name"], 0, al_entry(x["type"], 0, seq0 << 48, x["inst"], x["name"])))
    ents.append((0x80, "", xv, al_entry(0x80, xv, ext | 1 << 48, 0)))
    ents.sort(key=lambda e: e[:3])
    inst = u16(rec0, 0x28)
    struct.pack_into("<H", rec0, 0x28, inst + 1)
    after_si = [x for x in v.attrs(rec0) if x["type"] > 0x20][0]["off"]
    splice_attr(v, rec0, after_si, 0, res_attr(0x20, inst, b"".join(e[3] for e in ents)))
    v.put(0, rec0)
    v.save()
    return len(nruns)

# ---------------------------------------------------------------- helpers

def fuse_ok(t):
    if hasattr(t, "_ntfs_fuse"):
        return t._ntfs_fuse
    ok = False
    if os.environ.get("GZ_NTFS_NOFUSE"):
        pass
    elif shutil.which("ntfs-3g") and shutil.which("umount") and os.path.exists("/dev/fuse"):
        img = mkntfs(t, "fuse_probe.img", 4)
        mnt = t.path("fuse_probe_mnt", "x")
        mnt = os.path.dirname(mnt)
        r = subprocess.run(["ntfs-3g", img, mnt], capture_output=True, timeout=60)
        if r.returncode == 0:
            ok = os.path.ismount(mnt)
            subprocess.run(["umount", mnt], capture_output=True)
    t._ntfs_fuse = ok
    return ok

@contextlib.contextmanager
def mounted(t, img):
    mnt = os.path.dirname(t.path(os.path.basename(img) + "_mnt", "x"))
    t.sh(["ntfs-3g", "-o", "streams_interface=windows", img, mnt])
    try:
        yield mnt
    finally:
        for _ in range(5):
            if subprocess.run(["umount", mnt], capture_output=True).returncode == 0:
                break

def mkntfs(t, name, size_mb, sector=512, cluster=4096, label="GOGI"):
    img = t.path(name)
    if os.path.exists(img):
        os.remove(img)
    with open(img, "wb") as f:
        f.truncate(size_mb << 20)
    t.sh(["mkntfs", "-F", "-f", "-q", "-s", str(sector), "-c", str(cluster), "-L", label, img], env=ENV)
    return img

def populate(t, mnt, files):
    """files: {path: bytes | None (dir)}"""
    for k in sorted(files):
        p = os.path.join(mnt, k)
        if files[k] is None:
            os.makedirs(p, exist_ok=True)
        else:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(files[k])

def dump(t, drv, img):
    r = subprocess.run([drv, "l", img], capture_output=True, timeout=300)
    rows, typ, comment = {}, None, None
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        p = line.split("\t")
        if p[0] == "TYPE":
            typ = p[1]
        elif p[0] == "COMMENT":
            comment = p[1]
        elif len(p) >= 11 and p[0].isdigit():
            name, link = p[10], None
            if " -> " in name:
                name, link = name.split(" -> ", 1)
            rows[name] = dict(idx=int(p[0]), is_dir=int(p[1]), is_link=int(p[2]), aux=int(p[3]),
                              usize=int(p[4]), csize=int(p[5]), mk=int(p[6]), mtime=int(p[7]),
                              attr=int(p[8]), method=p[9], link=link)
    return r, typ, comment, rows

def check_views(t, drv, img, label, no_view=()):
    """extraction CRC == CRC of the random-access view read in shuffled chunks"""
    r = subprocess.run([drv, "v", img], capture_output=True, timeout=600)
    bad, n, nv = [], 0, 0
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        p = line.split("\t")
        if len(p) < 9 or not p[0].isdigit():
            continue
        n += 1
        st, size, crcx, kind, vs, crcv, err, name = int(p[1]), int(p[2]), p[3], p[4], int(p[5]), p[6], int(p[7]), p[8]
        if st:
            bad.append("%s: extract %d" % (name, st))
        elif kind != "view":
            if not any(name.startswith(x) for x in no_view):
                bad.append("%s: no view" % name)
        elif vs != size or crcv != crcx or err:
            bad.append("%s: view size %d/%d crc %s/%s err %d" % (name, vs, size, crcv, crcx, err))
        else:
            nv += 1
    return t.record(r.returncode == 0 and n and not bad, label, "; ".join(bad[:5]) or "%d files, %d views" % (n, nv))

def stream_crc(drv, img, name, timeout=600):
    r = subprocess.run([drv, "x", img, name], capture_output=True, timeout=timeout)
    p = r.stdout.decode().strip().split("\t")
    return (int(p[0]), int(p[1]), p[2]) if len(p) == 3 else None

def check_threads(t, drv, img, label, n=8):
    r = subprocess.run([drv, "m", img, str(n)], capture_output=True, timeout=600)
    out = r.stdout.decode().strip()
    return t.record(r.returncode == 0 and out.startswith("OK"), label, out[-200:])

def check_ntfscat(t, img, names, label):
    """libntfs-3g's reading of each file (data and named streams) vs. our extraction"""
    if not shutil.which("ntfscat"):
        return
    r, rows, out = t.extract(img)
    byname = {v[3]: k for k, v in rows.items()}
    bad = []
    for nm in names:
        args = ["ntfscat", "-q"]
        path = nm
        if ":" in nm:
            path, stream = nm.split(":", 1)
            args += ["-a", "0x80", "-n", stream]
        if path.startswith("[SYSTEM]/"):
            path = path[9:]
        rr = subprocess.run(args + [img, "/" + path], capture_output=True, timeout=120)
        i = byname.get(nm)
        mine = open(os.path.join(out, "%d.bin" % i), "rb").read() if i is not None else None
        if rr.returncode or mine != rr.stdout:
            bad.append("%s (rc %d, %s/%d)" % (nm, rr.returncode, None if mine is None else len(mine), len(rr.stdout)))
    t.record(not bad, label, "; ".join(bad[:4]) or "%d files" % len(names))

def vs_7z(t, img, label, skip=()):
    """our extraction vs 7-Zip's for every file 7-Zip extracts (names in skip are known 7-Zip
    failures, e.g. ntfs-3g sparse files with a compression unit)"""
    if not shutil.which("7z"):
        return None
    r, out = t.sevenzip_extract(img)
    exp = t.read_tree(out)
    for k in skip:
        exp.pop(k, None)
    if not exp or (r.returncode and not skip):
        return t.record(False, label, "7z reference failed: " + r.stdout.decode(errors="replace")[-300:])
    return t.check_extract(img, exp, allow_extra=True, label=label)

def ft(ns):
    return ns // 100 + FT_EPOCH * 10000000

def survive(drv, img, timeout=60):
    try:
        for cmd in (["l"], ["s", img, "4"]):
            r = subprocess.run([drv, cmd[0], img] + cmd[2:], capture_output=True, timeout=timeout)
            err = r.stderr.decode(errors="replace")
            if r.returncode not in (0, 1) or "Sanitizer" in err or "runtime error" in err:
                return "%s rc=%d %s" % (cmd, r.returncode, err[-400:])
    except subprocess.TimeoutExpired:
        return "timeout"
    return None

def hostile(t, drv, img, label):
    why = survive(drv, img)
    return t.record(why is None, label, why or "")

def fuzz(t, drv, img, label, regions, n, seed):
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
        why = survive(drv, tmp)
        if why:
            shutil.copy(tmp, t.path("fuzzfail_%s_%d.img" % (label, k)))
            bad.append("%d %s" % (k, why))
    os.remove(tmp)
    return t.record(not bad, "fuzz %s x%d" % (label, n), "; ".join(bad[:4]))

INNER = {"inner/a.txt": blob(3000, 51, True), "inner/b.bin": blob(20000, 52)}

def zip_bytes(files):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in files.items():
            z.writestr(k, v)
    return bio.getvalue()

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
    return t.record(ok, label, "" if ok else str((out[:3], len(got), len(want))))

# ---------------------------------------------------------------- basic (no mount)

def test_basic(t, drv):
    img = mkntfs(t, "basic.img", 16, label="BASIC")
    src = t.path("basic_src")
    os.makedirs(src, exist_ok=True)
    files = {"readme.txt": blob(5000, 1, True), "big.bin": blob(700000, 2), "empty.dat": b"",
             "한글 이름.txt": "고깃집 NTFS".encode(), "tiny": b"x", "inner.zip": zip_bytes(INNER)}
    for i, (k, v) in enumerate(files.items()):
        p = os.path.join(src, "f%d" % i)
        open(p, "wb").write(v)
        t.sh(["ntfscp", "-q", img, p, k], env=ENV)
    ads = blob(3000, 3, True)
    open(os.path.join(src, "ads"), "wb").write(ads)
    t.sh(["ntfscp", "-q", "-N", "zone.identifier", img, os.path.join(src, "ads"), "readme.txt"], env=ENV)
    exp = dict(files)
    exp["readme.txt:zone.identifier"] = ads
    t.check_extract(img, exp, allow_extra=True, label="basic files", expect_type="NTFS")
    vs_7z(t, img, "basic vs 7z")
    r, typ, comment, rows = dump(t, drv, img)
    sysok = all(v["aux"] == 1 for k, v in rows.items() if k.startswith("[SYSTEM]/"))
    ok = typ == "NTFS" and comment == "BASIC" and sysok and rows.get("readme.txt:zone.identifier", {}).get("aux") == 1 \
        and rows["readme.txt"]["aux"] == 0 and "[SYSTEM]/$MFT" in rows and "[SYSTEM]/$BadClus:$Bad" not in rows
    t.record(ok, "basic listing (label, [SYSTEM], aux)", "%s %s sys=%s" % (typ, comment, sysok))
    check_views(t, drv, img, "basic views")
    check_ntfscat(t, img, ["readme.txt", "big.bin", "readme.txt:zone.identifier", "한글 이름.txt"], "basic vs ntfscat")
    check_nested(t, drv, img, "inner.zip", INNER, "basic nested zip through the view")
    return img, exp

# ---------------------------------------------------------------- mounted fixtures

ATTR_MTIME_NS = 1600000000987654300

def tree_files():
    files = {
        "readme.txt": blob(5000, 1, True),
        "문서/보고서.txt": blob(120000, 2, True),
        "문서/사진/고기.jpg": blob(70000, 3),
        "empty.txt": b"",
        "deep/a/b/c/d/e/f/g/h.bin": blob(30000, 4),
        "A long file name with spaces, commas and more than 60 characters in it.dat": blob(2000, 5),
        "日本語/ファイル.txt": "テキスト".encode(),
        "big.bin": blob(1 << 20, 6),
        "Long File Name.txt": b"has a DOS name\n",
        "Case.txt": b"upper\n",
        "case.txt": b"lower\n",
        "links/original.txt": blob(9000, 7, True),
        "attr/hidden.txt": b"hidden + read-only\n",
    }
    for i in range(300):
        files["many/file number %04d.txt" % i] = ("content %d\n" % i).encode() * (1 + i % 7)
    return files

def make_tree(t, name, sector, cluster, size_mb=64):
    """mounted fixture: tree + ADS, hard links, DOS name, attributes, sparse file, symlink"""
    img = mkntfs(t, name, size_mb, sector, cluster, label="TREE")
    files = tree_files()
    extra = {
        "readme.txt:stream.one": b"alternate stream data\n",
        "big.bin:big stream": blob(200000, 8),
        "dir with ads:dirstream": b"stream on a directory\n",
        "links/hard.txt": files["links/original.txt"],
        "문서/hard2.txt": files["links/original.txt"],
    }
    sparse = bytearray(10 << 20)
    sparse[5000000:5000000 + 12] = b"middle bytes"
    sparse[-100:] = blob(100, 9)
    extra["sparse.bin"] = bytes(sparse)
    with mounted(t, img) as mnt:
        populate(t, mnt, files)
        os.makedirs(os.path.join(mnt, "dir with ads"))
        for k in ("readme.txt:stream.one", "big.bin:big stream", "dir with ads:dirstream"):
            with open(os.path.join(mnt, k), "wb") as f:
                f.write(extra[k])
        os.link(os.path.join(mnt, "links/original.txt"), os.path.join(mnt, "links/hard.txt"))
        os.link(os.path.join(mnt, "links/original.txt"), os.path.join(mnt, "문서/hard2.txt"))
        os.setxattr(os.path.join(mnt, "Long File Name.txt"), "system.ntfs_dos_name", b"LONGFI~1.TXT")
        hp = os.path.join(mnt, "attr/hidden.txt")
        os.utime(hp, ns=(ATTR_MTIME_NS, ATTR_MTIME_NS))
        os.setxattr(hp, "system.ntfs_attrib_be", struct.pack(">I", 0x23))
        with open(os.path.join(mnt, "sparse.bin"), "wb") as f:
            f.truncate(len(sparse))
            f.seek(5000000)
            f.write(sparse[5000000:5000012])
            f.seek(len(sparse) - 100)
            f.write(sparse[-100:])
        os.symlink("readme.txt", os.path.join(mnt, "sym.txt"))
    files.update(extra)
    return img, files

def test_tree(t, drv, sector, cluster):
    tag = "tree s%d c%d" % (sector, cluster)
    img, files = make_tree(t, "tree_%d_%d.img" % (sector, cluster), sector, cluster)
    t.check_extract(img, files, allow_extra=True, label=tag + " files")
    if sector == 512:                      # 7-Zip 23 does not open 4096-byte-sector volumes
        vs_7z(t, img, tag + " vs 7z", skip=("sparse.bin", "sym.txt"))
    check_ntfscat(t, img, ["readme.txt", "readme.txt:stream.one", "big.bin:big stream", "sparse.bin",
                           "문서/보고서.txt", "links/hard.txt", "[SYSTEM]/$LogFile", "[SYSTEM]/$UpCase"], tag + " vs ntfscat")
    r, typ, comment, rows = dump(t, drv, img)
    probs = []
    if "LONGFI~1.TXT" in rows or "Long File Name.txt" not in rows:
        probs.append("DOS name")
    h = rows.get("attr/hidden.txt", {})
    if h.get("attr", 0) & 0x23 != 0x23 or h.get("mtime") != ft(ATTR_MTIME_NS) or h.get("mk") != 1:
        probs.append("attr/mtime %s" % h)
    s = rows.get("sym.txt", {})
    if s.get("is_link") != 1 or s.get("link") != "readme.txt":
        probs.append("symlink %s" % s)
    if rows.get("dir with ads:dirstream", {}).get("aux") != 1 or rows.get("dir with ads", {}).get("is_dir") != 1:
        probs.append("dir stream")
    if rows.get("sparse.bin", {}).get("method") != "Sparse":
        probs.append("sparse method")
    if not rows.get("문서", {}).get("is_dir") or rows.get("[SYSTEM]/$Extend", {}).get("aux") != 1:
        probs.append("dirs")
    t.record(not probs and comment == "TREE", tag + " metadata", "; ".join(probs))
    check_views(t, drv, img, tag + " views")
    return img, files

def comp_files():
    return {
        "c/text.txt": blob(300000, 11, True),
        "c/random.bin": blob(150000, 12),
        "c/mixed.bin": blob(65536, 13, True) + blob(65536, 14) + blob(70000, 15, True),
        "c/zeros.bin": bytes(200000),
        "c/unit.bin": blob(65536, 16, True),
        "c/small.txt": b"tiny compressed file\n",
        "c/odd.txt": blob(4097, 17, True),
        "c/sub/inherit.txt": blob(100000, 18, True),
    }

def test_compressed(t, drv, cluster):
    tag = "lznt1 c%d" % cluster
    img = mkntfs(t, "comp_%d.img" % cluster, 32, 512, cluster, label="COMP")
    files = comp_files()
    sp = bytearray(3000000)
    sp[2500000:2500000 + 2400] = b"end of sparse compressed" * 100
    with mounted(t, img) as mnt:
        os.makedirs(os.path.join(mnt, "c"))
        os.setxattr(os.path.join(mnt, "c"), "system.ntfs_attrib_be", struct.pack(">I", 0x800))
        populate(t, mnt, files)
        with open(os.path.join(mnt, "c/sparse.bin"), "wb") as f:
            f.seek(2500000)
            f.write(sp[2500000:2502400])
            f.truncate(len(sp))
    files["c/sparse.bin"] = bytes(sp)
    t.check_extract(img, files, allow_extra=True, label=tag + " files")
    vs_7z(t, img, tag + " vs 7z")
    check_ntfscat(t, img, sorted(files), tag + " vs ntfscat")
    r, typ, comment, rows = dump(t, drv, img)
    meth = {k: rows.get(k, {}).get("method") for k in ("c/text.txt", "c/random.bin", "c/sub/inherit.txt")}
    t.record(all(m == "LZNT1" for m in meth.values()), tag + " method", str(meth))
    check_views(t, drv, img, tag + " views", no_view=("c/",))
    return img

# ---------------------------------------------------------------- WOF (system compression)

def wim_blob(t, data, comp, chunk):
    """compress data with wimlib; returns the resource (chunk table + chunks) or None if stored"""
    src = t.path("wofsrc", "f")
    shutil.rmtree(os.path.dirname(src), ignore_errors=True)
    os.makedirs(os.path.dirname(src))
    open(src, "wb").write(data)
    wim = t.path("wof_%s_%d.wim" % (comp, chunk))
    if os.path.exists(wim):
        os.remove(wim)
    t.sh(["wimlib-imagex", "capture", os.path.dirname(src), wim, "--compress=" + comp,
          "--chunk-size=%d" % chunk, "--no-acls"], env=ENV)
    d = open(wim, "rb").read()
    def reshdr(o):
        return int.from_bytes(d[o:o + 7], "little"), d[o + 7], u64(d, o + 8), u64(d, o + 16)
    sz, fl, off, us = reshdr(48)
    for i in range(off, off + sz, 50):
        bsz, bfl, boff, bus = reshdr(i)
        if bus == len(data):
            return d[boff:boff + bsz] if bfl & 4 else None
    raise RuntimeError("blob not found")

def wof_stream(t, data, comp, chunk):
    res = wim_blob(t, data, comp, chunk)
    if res is not None and len(data) > 0:
        return res
    # wimlib stored the blob: build a WOF stream of stored chunks
    n = (len(data) + chunk - 1) // chunk
    esz = 8 if len(data) > 0xFFFFFFFF else 4
    tab, pos = b"", 0
    for i in range(1, n):
        pos += min(chunk, len(data) - (i - 1) * chunk)
        tab += pos.to_bytes(esz, "little")
    return tab + data

WOF_ALGOS = (("XPRESS", 4096, 0), ("LZX", 32768, 1), ("XPRESS", 8192, 2), ("XPRESS", 16384, 3))

def x86ish(n, seed):
    rnd = random.Random(seed)
    out = bytearray()
    while len(out) < n:
        out += b"\x55\x8b\xec\xe8" + rnd.randrange(1 << 20).to_bytes(4, "little") + b"\x83\xc4\x08\xc3"
        out += rnd.choice([b"push ebp", b"call", b"\x90\x90", b"\xe8\xff\xff\xff\xff"])
    return bytes(out[:n])

def test_wof(t, drv):
    if not shutil.which("wimlib-imagex"):
        t.record(True, "wof skipped", "wimlib-imagex missing")
        return None
    img = mkntfs(t, "wof.img", 32, label="WOF")
    sources = {
        "text": blob(300000, 21, True),
        "random": blob(50000, 22),
        "mixed": blob(20000, 23, True) + blob(40000, 24) + blob(30001, 25, True),
        "x86": x86ish(200000, 26),
        "tiny": b"tiny wof file\n",
    }
    files, streams = {}, {}
    for comp, chunk, algo in WOF_ALGOS:
        srcs = dict(sources)
        srcs["exact"] = blob(chunk * 3, 27, True)
        for k, v in srcs.items():
            name = "wof/%s%d_%s.bin" % (comp.lower(), chunk // 1024, k)
            files[name] = v
            streams[name] = (wof_stream(t, v, comp, chunk), algo)
    with mounted(t, img) as mnt:
        os.makedirs(os.path.join(mnt, "wof"))
        for name, (st, algo) in streams.items():
            p = os.path.join(mnt, name)
            with open(p, "wb") as f:
                f.truncate(len(files[name]))
            with open(p + ":WofCompressedData", "wb") as f:
                f.write(st)
            os.setxattr(p, "system.ntfs_reparse_data", struct.pack("<IHHIIII", 0x80000017, 16, 0, 1, 2, 1, algo))
        # WIMBoot provider: listed, not extractable
        p = os.path.join(mnt, "wimboot.bin")
        with open(p, "wb") as f:
            f.truncate(5000)
        with open(p + ":WofCompressedData", "wb") as f:
            f.write(b"x" * 100)
        os.setxattr(p, "system.ntfs_reparse_data", struct.pack("<IHHIIII", 0x80000017, 16, 0, 1, 1, 1, 0))
    t.check_extract(img, files, allow_extra=True, label="wof files (XPRESS4K/8K/16K, LZX)")
    r, typ, comment, rows = dump(t, drv, img)
    names = {0: "XPRESS4K", 1: "LZX", 2: "XPRESS8K", 3: "XPRESS16K"}
    bad = [k for k, (st, algo) in streams.items() if rows.get(k, {}).get("method") != names[algo]]
    bad += [k for k in rows if k.endswith(":WofCompressedData") and not k.startswith("wimboot")]
    t.record(not bad, "wof listing", "; ".join(bad[:4]))
    st = stream_crc(drv, img, "wimboot.bin")
    t.record(st and st[0] == GZ_E_METHOD, "wof WIMBoot provider -> unsupported", str(st))
    return img

def test_wof_big(t, drv):
    """WOF file > 4 GiB: 8-byte chunk table entries (LZX chunks of zeros, a stored chunk at the end)"""
    if not shutil.which("wimlib-imagex"):
        return
    zero = wim_blob(t, bytes(32768), "LZX", 32768)
    if zero is None:
        t.record(False, "wof > 4 GiB fixture", "wimlib stored the zero chunk")
        return
    tail = blob(32768, 81)
    n = (4 << 30) // 32768 + 2
    size = n * 32768
    pos, tab = 0, bytearray()
    for i in range(1, n):
        pos += len(zero)
        tab += pos.to_bytes(8, "little")
    stream = bytes(tab) + zero * (n - 1) + tail
    img = mkntfs(t, "wofbig.img", 32, label="WOFBIG")
    with mounted(t, img) as mnt:
        p = os.path.join(mnt, "big.wof")
        with open(p, "wb") as f:
            f.truncate(size)
        with open(p + ":WofCompressedData", "wb") as f:
            f.write(stream)
        os.setxattr(p, "system.ntfs_reparse_data", struct.pack("<IHHIIII", 0x80000017, 16, 0, 1, 2, 1, 1))
    st = stream_crc(drv, img, "big.wof", timeout=900)
    t.record(st == (0, size, crc_sparse(size, {size - 32768: tail})), "wof > 4 GiB (8-byte chunk table)", str(st))

# ---------------------------------------------------------------- reparse points, EFS

def rp_symlink(sub, rel):
    s = sub.encode("utf-16le")
    body = struct.pack("<HHHHI", 0, len(s), len(s), len(s), 1 if rel else 0) + s + s
    return struct.pack("<IHH", 0xA000000C, len(body), 0) + body

def rp_junction(sub):
    s = sub.encode("utf-16le") + b"\0\0"
    body = struct.pack("<HHHH", 0, len(s) - 2, len(s), len(s) - 2) + s + s
    return struct.pack("<IHH", 0xA0000003, len(body), 0) + body

def test_links_efs(t, drv):
    img = mkntfs(t, "links.img", 16, label="LINKS")
    secret = blob(20000, 31, True)
    with mounted(t, img) as mnt:
        open(os.path.join(mnt, "target.txt"), "wb").write(b"target\n")
        for name, rp, isdir in (("rel.lnk", rp_symlink("..\\dir\\target.txt", True), 0),
                                ("abs.lnk", rp_symlink("\\??\\C:\\Windows\\notepad.exe", False), 0),
                                ("unc.lnk", rp_symlink("\\??\\UNC\\server\\share\\f.txt", False), 0),
                                ("junction", rp_junction("\\??\\C:\\Users"), 1)):
            p = os.path.join(mnt, name)
            if isdir:
                os.mkdir(p)
            else:
                open(p, "wb").close()
            os.setxattr(p, "system.ntfs_reparse_data", rp)
        os.symlink("../a/very/long/" + "x" * 300 + "/target", os.path.join(mnt, "interix.lnk"))
        open(os.path.join(mnt, "secret.txt"), "wb").write(secret)
        open(os.path.join(mnt, "plain.txt"), "wb").write(b"plain\n")
    v = Vol(img)
    n = v.find("secret.txt")
    rec = v.get(n)
    a = v.attr(rec, 0x80)
    struct.pack_into("<H", rec, a["off"] + 0x0C, u16(rec, a["off"] + 0x0C) | 0x4000)
    si = v.attr(rec, 0x10)
    so = si["off"] + u16(rec, si["off"] + 0x14)
    struct.pack_into("<I", rec, so + 0x20, u32(rec, so + 0x20) | 0x4000)
    v.put(n, rec)
    v.save()
    r, typ, comment, rows = dump(t, drv, img)
    want = {"rel.lnk": "../dir/target.txt", "abs.lnk": "C:/Windows/notepad.exe", "unc.lnk": "//server/share/f.txt",
            "junction": "C:/Users", "interix.lnk": "../a/very/long/" + "x" * 300 + "/target"}
    bad = ["%s=%s" % (k, rows.get(k, {}).get("link")) for k, w in want.items()
           if rows.get(k, {}).get("link") != w or rows[k]["is_link"] != 1 or rows[k]["is_dir"]]
    t.record(not bad, "reparse / Interix links", "; ".join(bad))
    st = stream_crc(drv, img, "secret.txt")
    ok = st and st[0] == GZ_E_METHOD and rows.get("secret.txt", {}).get("method") == "EFS"
    t.record(ok, "EFS -> unsupported method", str(st))
    t.check_extract(img, {"plain.txt": b"plain\n", "target.txt": b"target\n"}, allow_extra=True, label="links files")
    return img

# ---------------------------------------------------------------- attribute lists, fragmentation

def test_frag(t, drv):
    """fragmented files ($DATA extents in extension records), many hard links ($FILE_NAMEs in
    extension records), a fragmented compressed file"""
    img = mkntfs(t, "frag.img", 64, label="FRAG")
    data, ctext = blob(3 << 20, 41), blob(12 << 20, 42, True)
    linked = b"linked content\n" * 100
    files = {"data.bin": data, "c/text.txt": ctext, "linked.txt": linked}
    with mounted(t, img) as mnt:
        # a big compressed file: alternating data / sparse runs need extension records
        os.mkdir(os.path.join(mnt, "c"))
        os.setxattr(os.path.join(mnt, "c"), "system.ntfs_attrib_be", struct.pack(">I", 0x800))
        with open(os.path.join(mnt, "c/text.txt"), "wb") as f:
            f.write(ctext)
        # leave free space only in the holes of deleted one-cluster files
        fill = os.path.join(mnt, "fill")
        os.mkdir(fill)
        for i in range(2400):
            with open(os.path.join(fill, "%04d" % i), "wb") as f:
                f.write(b"f" * 4096)
        with open(os.path.join(mnt, "filler.bin"), "wb", buffering=0) as f:
            chunk = bytes(1 << 16)
            try:
                while True:
                    f.write(chunk)
            except OSError:
                pass
        filler = os.path.getsize(os.path.join(mnt, "filler.bin"))
        for i in range(0, 1600, 2):
            os.remove(os.path.join(fill, "%04d" % i))
        with open(os.path.join(mnt, "data.bin"), "wb") as f:
            f.write(data)
        for i in range(1600, 2400, 2):
            os.remove(os.path.join(fill, "%04d" % i))
        base = os.path.join(mnt, "linked.txt")
        with open(base, "wb") as f:
            f.write(linked)
        for i in range(40):
            nm = "hardlink_%02d_" % i + "x" * 200
            os.link(base, os.path.join(mnt, nm))
            files[nm] = linked
    for i in range(1, 2400, 2):
        files["fill/%04d" % i] = b"f" * 4096
    files["filler.bin"] = bytes(filler)
    v = Vol(img)
    al = {k: any(a["type"] == 0x20 for a in v.attrs(v.get(v.find(k.split("/")[-1])))) for k in
          ("data.bin", "text.txt", "linked.txt")}
    t.record(all(al.values()), "frag fixture has attribute lists", str(al))
    t.check_extract(img, files, allow_extra=True, label="frag files (attribute lists)")
    vs_7z(t, img, "frag vs 7z")
    check_ntfscat(t, img, ["data.bin", "c/text.txt", "linked.txt"], "frag vs ntfscat")
    check_views(t, drv, img, "frag views", no_view=("c/",))
    check_threads(t, drv, img, "frag threads")
    return img, files

def test_mft_frag(t, drv, tree_img, tree_files_):
    for al in (False, True):
        tag = "mft fragmented" + (" + attribute list" if al else "")
        img = t.path("mftfrag%d.img" % al)
        nruns = fragment_mft(tree_img, img, with_al=al)
        r, typ, comment, rows = dump(t, drv, img)
        t.record(nruns >= 10 and len(rows) > 330, tag + " fixture", "%d runs, %d entries" % (nruns, len(rows)))
        t.check_extract(img, tree_files_, allow_extra=True, label=tag + " files")
        if not al:                   # 7-Zip 23 does not read an attribute-listed $MFT
            vs_7z(t, img, tag + " vs 7z", skip=("sparse.bin", "sym.txt"))
        check_ntfscat(t, img, ["many/file number 0299.txt", "many/file number 0150.txt", "big.bin",
                               "문서/사진/고기.jpg", "[SYSTEM]/$LogFile"], tag + " vs ntfscat")
    # the extension record holding the tail of the runlist is unreadable: partial MFT, no crash
    v = Vol(t.path("mftfrag1.img"))
    raw = bytearray(v.rec_raw(16))
    raw[0:4] = b"BAAD"
    v.put_raw(16, raw)
    v.save(t.path("mftfrag_bad.img"))
    hostile(t, drv, t.path("mftfrag_bad.img"), "mft attribute list: lost extension record")

# ---------------------------------------------------------------- files > 4 GiB

def crc_sparse(size, pieces):
    crc, pos, z = 0, 0, bytes(1 << 20)
    for off, data in sorted(pieces.items()) + [(size, b"")]:
        while pos < off:
            n = min(len(z), off - pos)
            crc = zlib.crc32(z if n == len(z) else z[:n], crc)
            pos += n
        crc = zlib.crc32(data, crc)
        pos += len(data)
    return "%08x" % crc

def test_big(t, drv):
    img = mkntfs(t, "big.img", 32, label="BIG")
    huge, chuge = (5 << 30) + 12345, (4 << 30) + 4321
    m1, m2, m3 = b"past four GiB" * 10, blob(5000, 61), b"compressed marker" * 50
    with mounted(t, img) as mnt:
        with open(os.path.join(mnt, "huge.bin"), "wb") as f:
            f.truncate(huge)
            f.seek(4500 << 20)
            f.write(m1)
            f.seek(huge - len(m2))
            f.write(m2)
        os.mkdir(os.path.join(mnt, "c"))
        os.setxattr(os.path.join(mnt, "c"), "system.ntfs_attrib_be", struct.pack(">I", 0x800))
        with open(os.path.join(mnt, "c/huge.bin"), "wb") as f:
            f.truncate(chuge)
            f.seek(chuge - (1 << 20))
            f.write(m3)
    r, typ, comment, rows = dump(t, drv, img)
    t.record(rows.get("huge.bin", {}).get("usize") == huge and rows.get("c/huge.bin", {}).get("usize") == chuge,
             "big sizes > 4 GiB", "%s" % {k: rows.get(k, {}).get("usize") for k in ("huge.bin", "c/huge.bin")})
    rr = subprocess.run([drv, "r", img, "huge.bin", str(4500 << 20), str(len(m1)), str(huge - len(m2)), str(len(m2)),
                         str(huge - 1), "1"], capture_output=True, timeout=120)
    lines = rr.stdout.decode().split("\n")
    want = ["SIZE\t%d" % huge, "0\t%08x" % zlib.crc32(m1), "0\t%08x" % zlib.crc32(m2),
            "0\t%08x" % zlib.crc32(m2[-1:])]
    t.record(lines[:4] == want, "big view ranges past 4 GiB", str(lines[:4]))
    st = stream_crc(drv, img, "huge.bin")
    t.record(st == (0, huge, crc_sparse(huge, {4500 << 20: m1, huge - len(m2): m2})), "big sparse 5 GiB stream", str(st))
    st = stream_crc(drv, img, "c/huge.bin")
    t.record(st == (0, chuge, crc_sparse(chuge, {chuge - (1 << 20): m3})), "big compressed 4 GiB stream", str(st))

# ---------------------------------------------------------------- container

def test_container(t, drv, img, files):
    """NTFS partition in an MBR disk: opened automatically ("NTFS (MBR)"), nested zip via views"""
    data = open(img, "rb").read()
    disk = t.path("mbr_ntfs.img")
    start = 2048
    with open(disk, "wb") as f:
        mbr = bytearray(512)
        struct.pack_into("<B3sB3sII", mbr, 446, 0, b"\xfe\xff\xff", 7, b"\xfe\xff\xff", start, len(data) // 512)
        mbr[510:512] = b"\x55\xaa"
        f.write(mbr)
        f.seek(start * 512)
        f.write(data)
        f.truncate(start * 512 + len(data) + (1 << 20))
    t.check_extract(disk, files, allow_extra=True, label="MBR container", expect_type="NTFS (MBR)")
    check_nested(t, drv, disk, "inner.zip", INNER, "MBR -> NTFS -> zip through views")

# ---------------------------------------------------------------- hostile images

def set_attr_mp(vol, rec, a, mp, sizes=None):
    """raw mapping pairs (and optionally alloc/data/init sizes) for attribute a"""
    o, mo = a["off"], u16(rec, a["off"] + 0x20)
    newlen = (mo + len(mp) + 7) & ~7
    splice_attr(vol, rec, o, a["len"], bytes(rec[o:o + mo]) + mp + bytes(newlen - mo - len(mp)))
    struct.pack_into("<I", rec, o + 4, newlen)
    if sizes:
        struct.pack_into("<QQQ", rec, o + 0x28, *sizes)
    return rec

def patched(t, src, name, fn):
    """copy src to name, apply fn(Vol), save; returns the path"""
    dst = t.path(name)
    shutil.copy(src, dst)
    v = Vol(dst)
    fn(v)
    v.save()
    return dst

def file_patch(fname, fn):
    def go(v):
        n = v.find(fname)
        rec = v.get(n)
        fn(v, rec)
        v.put(n, rec)
    return go

def raw_patch(fname, fn):
    def go(v):
        n = v.find(fname) if isinstance(fname, str) else fname
        raw = bytearray(v.rec_raw(n))
        fn(raw)
        v.put_raw(n, raw)
    return go

def boot_patch(fn):
    def go(v):
        fn(v.d)
    return go

def flip(i, x=0xFF):
    def f(r):
        r[i] ^= x
    return f

def test_hostile_basic(t, drv, img, files):
    others = {k: v for k, v in files.items() if not k.startswith("readme")}
    # torn write: the record of readme.txt fails its update sequence check and is skipped
    h = patched(t, img, "h_fixup.img", raw_patch("readme.txt", flip(510)))
    r, typ, comment, rows = dump(t, drv, h)
    t.record("readme.txt" not in rows and "big.bin" in rows, "hostile fixup error: record skipped")
    t.check_extract(h, others, allow_extra=True, label="hostile fixup error: other files")
    # record 0 torn: $MFTMirr is used
    h = patched(t, img, "h_fixup0.img", raw_patch(0, flip(1022, 0x55)))
    t.check_extract(h, files, allow_extra=True, label="hostile $MFT record 0 torn -> $MFTMirr")
    # runs outside the volume, overflowing lengths, overlapping runs
    nclus = len(open(img, "rb").read()) // 4096
    cases = {
        "run beyond the volume": lambda v, rec: set_attr_runs(v, rec, v.attr(rec, 0x80), [(0, nclus + 5, 171)]),
        "run length overflow": lambda v, rec: set_attr_mp(v, rec, v.attr(rec, 0x80), b"\x18" + b"\xff" * 7 + b"\x7f\x10\x00"),
        "negative LCN": lambda v, rec: set_attr_mp(v, rec, v.attr(rec, 0x80), b"\x11\x10\x10\x11\x10\x80\x00"),
        "zero-length run": lambda v, rec: set_attr_mp(v, rec, v.attr(rec, 0x80), b"\x11\x00\x10\x00"),
        "truncated mapping pairs": lambda v, rec: set_attr_mp(v, rec, v.attr(rec, 0x80), b"\x48\x01"),
        "data size > allocated": lambda v, rec: struct.pack_into("<Q", rec, v.attr(rec, 0x80)["off"] + 0x30, 1 << 40),
        "initialized > data size": lambda v, rec: struct.pack_into("<Q", rec, v.attr(rec, 0x80)["off"] + 0x38, 1 << 40),
    }
    for label, fn in cases.items():
        h = patched(t, img, "h_%s.img" % label.replace(" ", "_"), file_patch("big.bin", fn))
        st = stream_crc(drv, h, "big.bin")
        ok = st is not None and st[0] not in (0, -1) and survive(drv, h) is None
        t.record(ok, "hostile " + label, str(st))
    # the same 10 clusters 200 times (allowed, bounded by the volume) and 500 times (more than
    # the volume holds): no crash, no runaway output
    for reps, ln in ((100, 10), (150, 40)):
        def loop(v, rec, reps=reps, ln=ln):
            a = v.attr(rec, 0x80)
            lcn = v.runs_of(rec, a)[0][1]
            mp = encode_runs([(0, lcn, ln)])[:-1] + bytes([0x11, ln, 0]) * (reps - 1) + b"\x00"
            set_attr_mp(v, rec, a, mp, ((ln * reps) * 4096,) * 3)
        h = patched(t, img, "h_loop%d.img" % reps, file_patch("big.bin", loop))
        st = stream_crc(drv, h, "big.bin")
        want_ok = reps * ln < nclus
        t.record(st is not None and (st[0] == 0) == want_ok and survive(drv, h) is None,
                 "hostile overlapping runs %dx%d" % (reps, ln), str(st))
    # $MFT claims a huge data size: clipped to its runs
    def mft_huge(v, rec):
        struct.pack_into("<Q", rec, v.attr(rec, 0x80)["off"] + 0x30, 1 << 50)
    h = patched(t, img, "h_mfthuge.img", file_patch("$MFT", mft_huge))
    t.check_extract(h, others, allow_extra=True, label="hostile $MFT data size 2^50")
    # boot sector variants: rejected or harmless
    for label, fn in (("record size 0", lambda d: d.__setitem__(0x40, 0)),
                      ("cluster 2^32 sectors", lambda d: d.__setitem__(13, 0xE0)),
                      ("no sectors", lambda d: d.__setitem__(slice(0x28, 0x30), bytes(8))),
                      ("MFT past the end", lambda d: d.__setitem__(slice(0x30, 0x38), struct.pack("<Q", 1 << 40))),
                      ("huge volume", lambda d: d.__setitem__(slice(0x28, 0x30), struct.pack("<Q", 1 << 50))),
                      ("record = 64 clusters", lambda d: d.__setitem__(0x40, 64))):
        hostile(t, drv, patched(t, img, "h_boot_%s.img" % label.replace(" ", "_"), boot_patch(fn)), "hostile boot " + label)
    data = open(img, "rb").read()
    for n in (512, 4096, 3 << 20, len(data) // 2, len(data) - 4096):
        p = t.path("h_trunc_%d.img" % n)
        open(p, "wb").write(data[:n])
        hostile(t, drv, p, "hostile truncated to %d" % n)

def set_parent(v, rec, ref):
    for a in v.attrs(rec):
        if a["type"] == 0x30:
            vo = a["off"] + u16(rec, a["off"] + 0x14)
            struct.pack_into("<Q", rec, vo, ref)

def ref_of(v, name):
    n = v.find(name)
    return n | u16(v.get(n), 0x10) << 48

def test_hostile_tree(t, drv, img, files):
    """broken parent references: the subtree lands below [LOST] exactly once"""
    want = files["deep/a/b/c/d/e/f/g/h.bin"]
    def parent_of(fname, target):
        return lambda v: file_patch(fname, lambda v, rec: set_parent(v, rec, target(v)))(v)
    cases = (
        ("cycle a -> g", parent_of("a", lambda v: ref_of(v, "g"))),
        ("directory is its own parent", parent_of("a", lambda v: ref_of(v, "a"))),
        ("parent is a file", parent_of("a", lambda v: ref_of(v, "readme.txt"))),
        ("parent sequence mismatch", parent_of("h.bin", lambda v: ref_of(v, "g") ^ (7 << 48))),
        ("parent record out of range", parent_of("h.bin", lambda v: (1 << 40) | 1 << 48)),
    )
    for label, fn in cases:
        h = patched(t, img, "ht_%s.img" % label.replace(" ", "_").replace(">", ""), fn)
        r, rows, out = t.extract(h, timeout=120)
        hits = [v[3] for k, v in rows.items() if v[3].startswith("[LOST]/") and v[3].endswith("/h.bin") and
                v[0] == 0 and open(os.path.join(out, "%d.bin" % k), "rb").read() == want]
        rd = [k for k, v in rows.items() if v[3] == "readme.txt" and v[0] == 0]
        t.record(len(hits) == 1 and rd and survive(drv, h) is None, "hostile tree " + label, str(hits))

def write_attr_data(v, rec, a, data):
    """overwrite the value of attribute a in place (same length)"""
    o = a["off"]
    if not a["nonres"]:
        vo = o + u16(rec, o + 0x14)
        rec[vo:vo + len(data)] = data
        return
    pos = 0
    for off, ln in v.phys(v.runs_of(rec, a), 0, len(data)):
        v.d[off:off + ln] = data[pos:pos + ln]
        pos += ln

def al_edit(fname, fn):
    def go(v):
        n = v.find(fname)
        rec = v.get(n)
        a = v.attr(rec, 0x20)
        al = bytearray(v.data_of(rec, a))
        ents, p = [], 0
        while p + 0x1A <= len(al) and u16(al, p + 4) >= 0x1A:
            ents.append(p)
            p += u16(al, p + 4)
        fn(v, n, al, ents)
        write_attr_data(v, rec, a, bytes(al))
        v.put(n, rec)
    return go

def test_hostile_al(t, drv, img, files):
    base = {k: files[k] for k in ("data.bin", "c/text.txt", "linked.txt")}
    def all_refs(val):
        def f(v, n, al, ents):
            for p in ents:
                struct.pack_into("<Q", al, p + 0x10, val(n))
        return f
    def data_ents(al, ents):
        return [p for p in ents if u32(al, p) == 0x80]
    def swap_data(v, n, al, ents):
        d = data_ents(al, ents)
        a, b = d[1], d[2]
        ea, eb = bytes(al[a:a + 0x20]), bytes(al[b:b + 0x20])
        al[a:a + 0x20], al[b:b + 0x20] = eb, ea
    def dup_data(v, n, al, ents):
        d = data_ents(al, ents)
        al[d[2]:d[2] + 0x20] = al[d[1]:d[1] + 0x20]
    def bad_len(v, n, al, ents):
        struct.pack_into("<H", al, ents[3] + 4, 0xFFF0)
    cases = (("refs to the base record", "linked.txt", all_refs(lambda n: n)),
             ("refs to $MFT", "linked.txt", all_refs(lambda n: 1 << 48)),
             ("refs out of range", "linked.txt", all_refs(lambda n: 1 << 40)),
             ("entry length overflow", "linked.txt", bad_len),
             ("extents out of order", "data.bin", swap_data),
             ("duplicate extent", "data.bin", dup_data))
    for label, fname, fn in cases:
        h = patched(t, img, "ha_%s.img" % label.replace(" ", "_").replace("$", ""), al_edit(fname, fn))
        why = survive(drv, h)
        t.record(why is None, "hostile attribute list " + label, why or "")
        exp = {k: v for k, v in base.items() if k != fname}
        t.check_extract(h, exp, allow_extra=True, label="hostile attribute list %s: others" % label)
        st = stream_crc(drv, h, fname)
        if fname == "data.bin":
            t.record(st and st[0] != 0, "hostile attribute list %s: error" % label, str(st))
        else:
            t.record(st and st[0] == 0 and st[2] == "%08x" % zlib.crc32(files[fname]),
                     "hostile attribute list %s: base record still read" % label, str(st))

def test_deep(t, drv):
    """301 nested directories (deeper than the tree limit) and the same chain made a cycle"""
    img = mkntfs(t, "deep.img", 16, label="DEEP")
    leaf = b"bottom of a deep tree\n"
    with mounted(t, img) as mnt:
        p = os.path.join(mnt, *["d%03d" % i for i in range(301)])
        os.makedirs(p)
        with open(os.path.join(p, "leaf.txt"), "wb") as f:
            f.write(leaf)
    def ok_leaf(h, label):
        r, rows, out = t.extract(h, timeout=120)
        hits = [k for k, v in rows.items() if v[3].endswith("/leaf.txt") and v[0] == 0 and
                open(os.path.join(out, "%d.bin" % k), "rb").read() == leaf]
        t.record(r.returncode == 0 and len(hits) == 1, label, "%d hits, %d entries" % (len(hits), len(rows)))
    ok_leaf(img, "deep 301 levels")
    h = patched(t, img, "deep_cycle.img", file_patch("d000", lambda v, rec: set_parent(v, rec, ref_of(v, "d300"))))
    ok_leaf(h, "deep cycle of 301 directories")
    hostile(t, drv, h, "hostile deep cycle")

def wof_stored(data, chunk=4096):
    n = (len(data) + chunk - 1) // chunk
    return b"".join(min(len(data), i * chunk).to_bytes(4, "little") for i in range(1, n)) + data

def make_fuzz_img(t, name="fuzz.img", sector=512, cluster=4096):
    """small image with most features for fuzzing"""
    img = mkntfs(t, name, 8, sector, cluster, label="FUZZ")
    wdata = blob(9000, 76, True)
    fdata = blob(300 * cluster, 77)
    with mounted(t, img) as mnt:
        populate(t, mnt, {"a.txt": blob(3000, 71, True), "d/b.bin": blob(20000, 72), "d/e/f.txt": b"deep\n"})
        os.makedirs(os.path.join(mnt, "c"))
        os.setxattr(os.path.join(mnt, "c"), "system.ntfs_attrib_be", struct.pack(">I", 0x800))
        populate(t, mnt, {"c/t.txt": blob(150000, 73, True), "c/r.bin": blob(70000, 74)})
        with open(os.path.join(mnt, "a.txt:ads"), "wb") as f:
            f.write(blob(9000, 75))
        with open(os.path.join(mnt, "sparse.bin"), "wb") as f:
            f.truncate(1 << 20)
            f.seek(500000)
            f.write(b"x" * 5000)
        base = os.path.join(mnt, "linked.txt")
        with open(base, "wb") as f:
            f.write(b"linked\n")
        for i in range(12):
            os.link(base, os.path.join(mnt, "link%02d_" % i + "y" * 150))
        os.symlink("a.txt", os.path.join(mnt, "sym"))
        p = os.path.join(mnt, "w.txt")
        with open(p, "wb") as f:
            f.truncate(len(wdata))
        with open(p + ":WofCompressedData", "wb") as f:
            f.write(wof_stored(wdata))
        os.setxattr(p, "system.ntfs_reparse_data", struct.pack("<IHHIIII", 0x80000017, 16, 0, 1, 2, 1, 0))
        # a file in 300 fragments: $DATA extents in extension records
        os.mkdir(os.path.join(mnt, "fill"))
        for i in range(600):
            with open(os.path.join(mnt, "fill", "%03d" % i), "wb") as f:
                f.write(b"z" * cluster)
        with open(os.path.join(mnt, "filler.bin"), "wb", buffering=0) as f:
            try:
                while True:
                    f.write(bytes(cluster))
            except OSError:
                pass
        for i in range(0, 600, 2):
            os.remove(os.path.join(mnt, "fill", "%03d" % i))
        with open(os.path.join(mnt, "frag.bin"), "wb") as f:
            f.write(fdata)
    v = Vol(img)
    has_al = all(any(a["type"] == 0x20 for a in v.attrs(v.get(v.find(n)))) for n in ("linked.txt",))
    nruns = len(v.runs_of(v.get(v.find("frag.bin")), v.attr(v.get(v.find("frag.bin")), 0x80)))
    t.check_extract(img, {"w.txt": wdata, "c/t.txt": blob(150000, 73, True), "frag.bin": fdata}, allow_extra=True,
                    label="fuzz base image s%d" % sector)
    t.record(has_al and nruns > 50, "fuzz base image s%d: attribute list, fragmented file" % sector, "%d runs" % nruns)
    return img

def run(t):
    t.need("mkntfs", "ntfscp")
    drv = t.build_driver("tests/drivers/ntfs_dump.c")
    basic, bfiles = test_basic(t, drv)
    test_container(t, drv, basic, bfiles)
    test_hostile_basic(t, drv, basic, bfiles)
    n = int(os.environ.get("GZ_NTFS_FUZZ", "200"))
    if not fuse_ok(t):
        t.record(True, "mounted fixtures skipped", "ntfs-3g FUSE mount not available")
        v = Vol(basic)
        mft = v.mft_lcn * v.cs
        fuzz(t, drv, basic, "basic", [(0, 512), (mft, 40 * v.rs), (mft, v.nrec * v.rs)], n // 2, 5)
        return
    tree, tfiles = test_tree(t, drv, 512, 4096)
    check_threads(t, drv, tree, "tree threads")
    test_mft_frag(t, drv, tree, tfiles)
    for s, c in ((4096, 4096), (512, 512), (512, 65536)):
        test_tree(t, drv, s, c)
    for c in (512, 1024, 2048, 4096):
        test_compressed(t, drv, c)
    test_wof(t, drv)
    test_links_efs(t, drv)
    frag, ffiles = test_frag(t, drv)
    test_big(t, drv)
    if "sanitize" not in os.environ.get("HOST_CFLAGS", ""):       # 4 GiB through LZX: too slow there
        test_wof_big(t, drv)
    test_hostile_tree(t, drv, tree, tfiles)
    test_hostile_al(t, drv, frag, ffiles)
    test_deep(t, drv)
    for k, (sector, cluster) in enumerate(((512, 4096), (4096, 4096))):
        fz = make_fuzz_img(t, "fuzz%d.img" % sector, sector, cluster)
        v = Vol(fz)
        mft = v.mft_lcn * v.cs
        fuzz(t, drv, fz, "s%d" % sector, [(0, 512), (mft, 40 * v.rs), (mft + 64 * v.rs, 32 * v.rs),
                                          (mft, v.nrec * v.rs)], n if k == 0 else n // 2, 7 + k)
