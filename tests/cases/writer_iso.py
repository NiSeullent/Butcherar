"""ISO 9660 writer (src/fmt/iso_write.c): Level 3 + Joliet + Rock Ridge.

Images are made with `gzt c iso` and with the iso_wdrv driver (symlinks, failing
items, cancel, labels, weird names, sparse multi-extent files), then checked by a
structural validator written here (volume descriptors, path tables, record
placement and order, identifiers, Joliet case-insensitive uniqueness, SUSP/CE,
extents) and by the reference tools: xorriso (RR listing), isoinfo -R / -J / -l,
isovfy, 7z x / l (Joliet names), bsdtar -x / -t (Rock Ridge names, modes, symlinks,
mtimes), pycdlib when installed, and 고깃ZIP's own ISO reader. Contents are compared
byte for byte.

When qemu-system-x86_64, busybox, cpio and a distro kernel (/boot/vmlinuz-*, isofs and
nls_utf8 modules) are installed, the images are also mounted by the real Linux isofs
driver (Rock Ridge, Joliet and plain primary tree) in a throw-away VM; GZ_ISO_KERNEL=0
turns that off.

GZ_TEST_BIG=1 adds a 4.1 GiB multi-extent image (sparse, a few MB on disk).
GZ_ISO_FUZZ=<n> sets the number of random item lists (default 30).
"""
import os, re, sys, mmap, stat, time, struct, random, shutil, hashlib, subprocess
from gztest import normalize

SECT = 2048
JMAX = 103
EXT = 0xFFFFF800
RRMAX = 253         # Linux isofs drops Rock Ridge names of 254 bytes and more
JBAD = set('*/:;?\\')

# ---------------------------------------------------------------- helpers

def blob(n, seed=1):
    rnd = random.Random(seed * 7919 + n)
    return bytes(rnd.getrandbits(8) for _ in range(n)) if n < 200000 else \
        (bytes(rnd.getrandbits(8) for _ in range(65536)) * (n // 65536 + 1))[:n]

def pat_byte(o):
    return (o * 7 + (o >> 11) * 13 + 1) & 0xFF

def pat_windows(size):
    w = [((k << 30), (k << 30) + 65536) for k in range(size // (1 << 30) + 1)]
    w += [(EXT - 65536, EXT + 65536), (max(0, size - 65536), size)]
    return [(max(0, a), min(b, size)) for a, b in w if a < size and b > 0]

def pat_chunk(a, b, size):
    """expected bytes [a, b) of a driver 'v' file of the given size"""
    out = bytearray(b - a)
    for ws, we in pat_windows(size):
        s, e = max(a, ws), min(b, we)
        if s < e:
            out[s - a:e - a] = bytes(pat_byte(o) for o in range(s, e))
    return bytes(out)

def pat_data(size):
    return pat_chunk(0, size, size)

def jname(name, is_dir):
    """Joliet name the writer produces when no uniquification is needed"""
    s = "".join("_" if (ord(c) < 0x20 or c in JBAD) else c for c in name)
    if len(s.encode("utf-16-le")) // 2 <= JMAX:
        return s
    dot = -1
    if not is_dir:
        i = s.rfind(".")
        if i > 0 and len(s) - i - 1 <= 16:
            dot = i
    ext = s[dot:] if dot > 0 else ""
    return s[:JMAX - len(ext)] + ext

def rrname(name, is_dir):
    b = name.encode("utf-8", "surrogatepass")
    if len(b) <= RRMAX:
        return name
    ext = ""
    if not is_dir:
        i = name.rfind(".")
        if i > 0 and len(name) - i <= 32:
            ext = name[i:]
    base = name[:len(name) - len(ext)] if ext else name
    eb = ext.encode()
    out = ""
    for ch in base:
        if len((out + ch).encode()) + len(eb) > RRMAX:
            break
        out += ch
    return out + ext

def jfold_key(name):
    """Joliet clash key: ASCII + Latin-1 case folded, trailing dots/spaces dropped
    (a subset of the writer's folding, so every clash found here is a writer bug)"""
    s = name.rstrip(". ")
    return "".join(chr(ord(c) - 32) if "a" <= c <= "z" or ("\xe0" <= c <= "\xfe" and c != "\xf7") else c for c in s)

def norm_link(t):
    """symlink target as stored: repeated '/' collapse, a trailing '/' stays"""
    parts = [p for p in t.split("/") if p]
    s = ("/" if t.startswith("/") else "") + "/".join(parts)
    return s + "/" if parts and t.endswith("/") else s

def view(files, joliet):
    """files: {rel: bytes | None | ('link', target)} -> expected {path: same} in one name space"""
    out = {}
    for rel, v in files.items():
        parts = [p for p in rel.split("/") if p not in ("", ".", "..")]
        if not parts:
            continue
        if joliet and isinstance(v, tuple):
            continue
        names = []
        for i, p in enumerate(parts):
            d = i < len(parts) - 1 or v is None
            names.append(jname(p, d) if joliet else rrname(p, d))
        out["/".join(names)] = v
    return out

# ---------------------------------------------------------------- structural checker

class Iso:
    """Minimal independent ISO 9660 / Joliet / RRIP reader that checks every rule the
    writer is supposed to follow and returns the RR and Joliet trees."""

    def __init__(self, path):
        self.f = open(path, "rb")
        self.m = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        self.n = len(self.m) // SECT
        self.p = []
        self.rr = {}        # path -> dict
        self.jol = {}
        self.ce = []        # (byte offset, dir end) of CE areas
        self.data = []      # (lba, sectors, path)
        self.multi = 0
        self.hidden = []

    def close(self):
        self.m.close()
        self.f.close()

    def bad(self, msg):
        if len(self.p) < 40:
            self.p.append(msg)

    def b16(self, b, o):
        le, be = struct.unpack_from("<H", b, o)[0], struct.unpack_from(">H", b, o + 2)[0]
        if le != be:
            self.bad("both-endian u16 differs @%d" % o)
        return le

    def b32(self, b, o):
        le, be = struct.unpack_from("<I", b, o)[0], struct.unpack_from(">I", b, o + 4)[0]
        if le != be:
            self.bad("both-endian u32 differs @%d" % o)
        return le

    def sec(self, lba, cnt=1):
        return self.m[lba * SECT:(lba + cnt) * SECT]

    def check(self):
        if len(self.m) % SECT:
            self.bad("size not a multiple of 2048")
        if self.m[:16 * SECT].count(0) != 16 * SECT:
            self.bad("system area not zero")
        vd = [self.sec(16 + i) for i in range(3)]
        for i, (t, v) in enumerate(zip((1, 2, 255), vd)):
            if v[0] != t or v[1:6] != b"CD001" or v[6] != 1:
                self.bad("volume descriptor %d: type %d" % (16 + i, v[0]))
                return self
        if vd[1][88:91] != b"%/E":
            self.bad("Joliet escape sequence")
        self.label_p = vd[0][40:72].decode("ascii", "replace").rstrip()
        self.label_j = vd[1][40:72].decode("utf-16-be", "replace").rstrip()
        if not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for c in self.label_p):
            self.bad("primary volume id not d-characters: %r" % self.label_p)
        for v, jol in ((vd[0], False), (vd[1], True)):
            if self.b32(v, 80) != self.n:
                self.bad("volume space size %d != %d" % (self.b32(v, 80), self.n))
            if self.b16(v, 120) != 1 or self.b16(v, 124) != 1 or self.b16(v, 128) != SECT:
                self.bad("set size / sequence / block size")
            if v[881] != 1:
                self.bad("file structure version")
            for o in (813, 830):
                d = v[o:o + 16]
                if not d.isdigit():
                    self.bad("volume date %r" % d)
            root = v[156:190]
            if root[0] != 34 or root[32] != 1 or root[33] != 0 or not root[25] & 2:
                self.bad("root record in VD")
            self.walk(self.b32(root, 2), self.b32(root, 10), jol, v)
        self.finish()
        return self

    # -- directories
    def records(self, lba, size):
        out = []
        if (lba + size // SECT) > self.n or size % SECT or not size:
            self.bad("directory extent %d+%d outside volume" % (lba, size))
            return out
        pos, end = lba * SECT, lba * SECT + size
        while pos < end:
            l = self.m[pos]
            if l == 0:
                nxt = (pos // SECT + 1) * SECT
                if self.m[pos:nxt].count(0) != nxt - pos:
                    self.bad("garbage after last record in sector @%d" % pos)
                pos = nxt
                continue
            if pos % SECT + l > SECT:
                self.bad("record crosses a sector boundary @%d" % pos)
            r = self.m[pos:pos + l]
            pos += l
            if l < 34 or l & 1 or 33 + r[32] > l:
                self.bad("bad record length %d" % l)
                continue
            if self.b16(r, 28) != 1 or r[1] != 0 or r[26] or r[27]:
                self.bad("record vol seq / ext attr / interleave")
            dt = r[18:25]
            if any(dt[:6]) and not (1 <= dt[1] <= 12 and 1 <= dt[2] <= 31 and dt[3] < 24 and dt[4] < 60 and dt[5] < 60):
                self.bad("record date %r" % bytes(dt))
            idl = r[32]
            out.append(dict(lba=self.b32(r, 2), size=self.b32(r, 10), flags=r[25], id=bytes(r[33:33 + idl]),
                            sua=bytes(r[33 + idl + (1 - idl % 2):l]), date=bytes(dt)))
        return out

    def walk(self, rlba, rsize, jol, vd):
        tree = self.jol if jol else self.rr
        queue = [(rlba, rsize, rlba, rsize, "", 1, b"\0")]
        bfs = []                                  # path table expectation
        seen = set()
        depth = 0
        while queue:
            nq = []
            for lba, size, plba, psize, path, pnum, ident in queue:
                if lba in seen:
                    self.bad("directory loop")
                    continue
                seen.add(lba)
                bfs.append((lba, pnum, ident))
                me = len(bfs)
                recs = self.records(lba, size)
                if len(recs) < 2 or recs[0]["id"] != b"\0" or recs[1]["id"] != b"\1":
                    self.bad("'.'/'..' missing in %r" % path)
                    continue
                if (recs[0]["lba"], recs[0]["size"]) != (lba, size) or (recs[1]["lba"], recs[1]["size"]) != (plba, psize):
                    self.bad("'.'/'..' extents in %r" % path)
                if not jol:
                    sus = self.susp(recs[0]["sua"], lba * SECT + size)
                    if path == "":
                        if not recs[0]["sua"].startswith(b"SP\x07\x01\xbe\xef"):
                            self.bad("SP not first in root '.'")
                        if not any(s == b"ER" and b[8:18] == b"RRIP_1991A" for s, b in sus):
                            self.bad("no ER RRIP_1991A")
                    self.susp(recs[1]["sua"], lba * SECT + size)
                prev = None
                names = {}
                kids = recs[2:]
                i = 0
                while i < len(kids):
                    r = kids[i]
                    group = [r]
                    while group[-1]["flags"] & 0x80 and i + 1 < len(kids):
                        i += 1
                        group.append(kids[i])
                    i += 1
                    if group[-1]["flags"] & 0x80:
                        self.bad("multi-extent chain not terminated")
                    if any(g["id"] != r["id"] for g in group):
                        self.bad("multi-extent records with different names")
                    key = self.sort_key(r["id"], jol, r["flags"] & 2)
                    if key is None:
                        continue
                    if prev is not None and not self.less(prev, key):
                        self.bad("records not sorted in %r: %r !< %r" % (path, prev, key))
                    prev = key
                    uk = (tuple(key[0]), tuple(key[1]))
                    if jol:                       # what Windows / Linux Joliet lookups compare
                        uk = jfold_key(r["id"].decode("utf-16-be", "surrogatepass"))
                    if uk in names:
                        self.bad("duplicate identifier %r in %r" % (r["id"], path))
                    names[uk] = 1
                    if jol:
                        nm = r["id"].decode("utf-16-be", "surrogatepass")
                        if r["flags"] & 1:
                            self.hidden.append(path + nm)
                    else:
                        nm, info = self.rr_info(group, lba * SECT + size)
                        if nm is None:
                            continue
                    full = path + nm
                    if full in tree:
                        self.bad("duplicate path %r" % full)
                    if r["flags"] & 2:
                        if len(group) > 1:
                            self.bad("multi-extent directory")
                        ent = dict(dir=True, lba=r["lba"])
                        if not jol:
                            ent.update(info)
                        tree[full] = ent
                        nq.append((r["lba"], r["size"], lba, size, full + "/", me, r["id"]))
                    else:
                        ent = dict(dir=False, size=sum(g["size"] for g in group), lba=r["lba"], n=len(group),
                                   date=r["date"])
                        if not jol:
                            ent.update(info)
                        self.extents(group, full, jol)
                        tree[full] = ent
            queue = nq
            depth += 1
        self.path_table(vd, bfs, jol)

    def sort_key(self, ident, jol, is_dir):
        if jol:
            if len(ident) % 2 or len(ident) > 2 * JMAX:
                self.bad("Joliet identifier length %d" % len(ident))
            s = ident.decode("utf-16-be", "surrogatepass")
            if any(ord(c) < 0x20 or c in JBAD for c in s):
                self.bad("Joliet name with forbidden character %r" % s)
            u = list(struct.unpack(">%dH" % (len(ident) // 2), ident))   # order is by UTF-16 units
            if is_dir:
                return (u, [])
            d = len(u) - 1 - u[::-1].index(0x2E) if 0x2E in u else -1
            return (u[:d], u[d + 1:]) if d > 0 else (u, [])
        s = ident.decode("ascii", "replace")
        if is_dir:
            if not s or len(s) > 31 or not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for c in s):
                self.bad("primary directory identifier %r" % s)
            return (list(ident), [])
        if not s.endswith(";1") or s.count(".") != 1:
            self.bad("primary file identifier %r" % s)
            return None
        nm, ex = s[:-2].split(".")
        if len(nm) + len(ex) > 30 or not nm + ex or \
                not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for c in nm + ex):
            self.bad("primary file identifier %r" % s)
        return (list(nm.encode()), list(ex.encode()))

    @staticmethod
    def less(a, b):
        def pad(x, y):
            n = max(len(x), len(y))
            return x + [0x20] * (n - len(x)), y + [0x20] * (n - len(y))
        x, y = pad(a[0], b[0])
        if x != y:
            return x < y
        x, y = pad(a[1], b[1])
        return x < y

    def extents(self, group, path, jol):
        for k, g in enumerate(group):
            if k + 1 < len(group) and (g["size"] % SECT or not g["flags"] & 0x80):
                self.bad("multi-extent part %d of %r: size %d" % (k, path, g["size"]))
            if k and g["lba"] != group[k - 1]["lba"] + group[k - 1]["size"] // SECT:
                self.bad("multi-extent parts of %r not contiguous" % path)
            ns = (g["size"] + SECT - 1) // SECT
            if g["lba"] + ns > self.n or (g["size"] and g["lba"] < 19):
                self.bad("extent of %r outside volume" % path)
            if not jol and g["size"]:
                self.data.append((g["lba"], ns, path))
        if len(group) > 1:
            self.multi += 1

    # -- SUSP / RRIP
    def susp(self, sua, dir_end):
        ents, area, hops = [], sua, 0
        while True:
            i, ce = 0, None
            while i + 4 <= len(area):
                sig, ln = area[i:i + 2], area[i + 2]
                if sig == b"\0\0" or ln == 0:
                    break
                if ln < 4 or i + ln > len(area) or area[i + 3] != 1:
                    self.bad("bad SUSP entry %r" % sig)
                    break
                body = area[i + 4:i + ln]
                if sig == b"CE":
                    ce = (self.b32(body, 0), self.b32(body, 8), self.b32(body, 16))
                elif sig == b"ST":
                    break
                else:
                    ents.append((sig, area[i:i + ln]))
                i += ln
            if not ce:
                return ents
            loc, off, ln = ce
            hops += 1
            if hops > 32:
                self.bad("CE loop")
                return ents
            if off + ln > SECT or loc >= self.n:
                self.bad("CE area crosses a sector / outside volume")
                return ents
            self.ce.append((loc * SECT + off, dir_end))
            area = self.m[loc * SECT + off:loc * SECT + off + ln]

    def rr_info(self, group, dir_end):
        name, info, sl = b"", {}, []
        for k, g in enumerate(group):
            ents = self.susp(g["sua"], dir_end)
            if k:
                continue
            for sig, e in ents:
                if sig == b"NM":
                    if e[4] & ~1:
                        self.bad("NM flags")
                    name += e[5:]
                elif sig == b"PX":
                    if e[2] not in (36, 44):
                        self.bad("PX length")
                    info["mode"] = self.b32(e, 4)
                    info["nlink"] = self.b32(e, 12)
                elif sig == b"TF":
                    info["tf"] = e[4]
                elif sig == b"SL":
                    sl.append(e)
        if not name:
            self.bad("record without NM: %r" % group[0]["id"])
            return None, None
        try:
            nm = name.decode("utf-8")
        except UnicodeDecodeError:
            self.bad("NM is not UTF-8: %r" % name)
            nm = name.decode("utf-8", "replace")
        if len(name) > RRMAX or "/" in nm or nm in (".", ".."):
            self.bad("bad RR name %r" % nm)
        if sl:
            info["target"] = self.sl_decode(sl)
        if "mode" not in info:
            self.bad("no PX for %r" % nm)
        return nm, info

    def sl_decode(self, sl):
        out, comp = "", b""
        for k, e in enumerate(sl):
            body, i = e[5:], 0
            while i + 2 <= len(body):
                fl, ln = body[i], body[i + 1]
                txt = body[i + 2:i + 2 + ln]
                i += 2 + ln
                if fl & 8:
                    out = "/"
                    continue
                comp += b"." if fl & 2 else b".." if fl & 4 else txt
                if not fl & 1:
                    if out and not out.endswith("/"):
                        out += "/"
                    out += comp.decode("utf-8", "replace")
                    comp = b""
            if k + 1 < len(sl) and not e[4] & 1:
                self.bad("SL continuation flag")
            if k + 1 < len(sl) and body and not body[i - 2 - ln] & 1:
                self.bad("SL entry ends after a complete component (Linux and libarchive disagree)")
        return out

    # -- path tables and data placement
    def path_table(self, vd, bfs, jol):
        size = self.b32(vd, 132)
        exp_ids = [(lba, min(pnum, 0xFFFF), ident) for lba, pnum, ident in bfs]
        for be, o in ((False, 140), (True, 148)):
            loc = struct.unpack_from(">I" if be else "<I", vd, o)[0]
            b = self.m[loc * SECT:loc * SECT + size]
            ents, i = [], 0
            while i < size:
                l = b[i]
                if l == 0 or i + 8 + l > size:
                    self.bad("bad path table record")
                    break
                lba = struct.unpack_from(">I" if be else "<I", b, i + 2)[0]
                par = struct.unpack_from(">H" if be else "<H", b, i + 6)[0]
                ents.append((lba, par, bytes(b[i + 8:i + 8 + l])))
                i += 8 + l + (l & 1)
            if len(ents) != len(exp_ids):
                self.bad("path table has %d entries, tree %d dirs" % (len(ents), len(exp_ids)))
                continue
            for (lba, par, ident), (elba, epar, eid) in zip(ents, exp_ids):
                if lba != elba or par != epar or ident != eid:
                    self.bad("path table entry %r/%d/%d != %r/%d/%d" % (ident, lba, par, eid, elba, epar))
                    break

    def finish(self):
        self.data.sort()
        for a, b in zip(self.data, self.data[1:]):
            if a[0] + a[1] > b[0]:
                self.bad("file extents overlap: %r %r" % (a[2], b[2]))
        # libarchive reads CE areas only as the sectors right after their directory
        runs = {}
        for off, dend in self.ce:
            runs.setdefault(dend, set()).add(off // SECT)
        for dend, secs in runs.items():
            if secs != set(range(dend // SECT, dend // SECT + len(secs))):
                self.bad("CE areas of the directory ending at %d are not right after it: %r" % (dend, sorted(secs)[:4]))
        jf = sorted((v["lba"], v["size"]) for v in self.jol.values() if not v["dir"] and v["size"])
        rf = sorted((v["lba"], v["size"]) for v in self.rr.values() if not v["dir"] and v["size"])
        if jf != rf:
            self.bad("Joliet and primary trees point at different file data")
        if sum(v["dir"] for v in self.jol.values()) != sum(v["dir"] for v in self.rr.values()):
            self.bad("Joliet and primary trees have different directories")

def iso_check(t, arc, label):
    try:
        iso = Iso(arc).check()
    except Exception as e:
        t.record(False, label + " structure", "exception %r" % e)
        return None
    t.record(not iso.p, label + " structure", "; ".join(iso.p[:6]) or
             "%d sectors, %d RR + %d Joliet entries, %d CE, %d multi-extent" %
             (iso.n, len(iso.rr), len(iso.jol), len(iso.ce), iso.multi))
    return iso

# ---------------------------------------------------------------- reference tools

LSDL = re.compile(r"^([-dlcbps][-rwxsStT]{9})\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\w+\s+\d+\s+[\d:]+\s+'(.*?)'(?: -> '(.*)')?$")

def check_xorriso(t, arc, rr, label):
    r = t.sh(["xorriso", "-indev", arc, "-find", "/", "-exec", "lsdl"], check=False)
    out = r.stdout.decode("utf-8", "replace")
    err = r.stderr.decode("utf-8", "replace")
    got = {}
    for line in out.splitlines():
        m = LSDL.match(line)
        if m and m.group(6) != "/":
            got[m.group(6).lstrip("/")] = (m.group(1), int(m.group(5)), m.group(7))
    probs = []
    if r.returncode or re.search(r"WARNING|FAILURE|SORRY|MISHAP|FATAL", err):
        probs.append("xorriso rc=%d %s" % (r.returncode, err[-300:]))
    for p, v in rr.items():
        g = got.get(p)
        if g is None:
            probs.append("missing " + p)
            continue
        if isinstance(v, tuple):
            if g[0][0] != "l" or g[2] != norm_link(v[1]):
                probs.append("link %s: %r" % (p, g))
        elif v is None:
            if g[0][0] != "d":
                probs.append("not a dir: " + p)
        elif g[0][0] != "-" or g[1] != len(v):
            probs.append("file %s: %r" % (p, g))
    extra = set(got) - set(rr)
    if extra:
        probs.append("extra %r" % sorted(extra)[:3])
    return t.record(not probs, label + " xorriso", "; ".join(probs[:5]) or "%d entries" % len(got))

ISOINFO = re.compile(r"^([-dl][-rwxsStT]{9})\s+\d+\s+\d+\s+\d+\s+(\d+)\s+\w+\s+\d+\s+\d+\s+\[\s*(\d+)\s+(\d+)\]\s\s(.*?) ?$")

def isoinfo_tree(t, arc, opt):
    r = t.sh(["isoinfo"] + opt + ["-l", "-i", arc], check=False)
    cur, got, n = "/", {}, 0
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("Directory listing of "):
            cur = line[len("Directory listing of "):]
            continue
        m = ISOINFO.match(line)
        if not m or m.group(5) in (".", ".."):
            continue
        nm, tgt = m.group(5), None
        if m.group(1)[0] == "l" and " -> " in nm:
            nm, tgt = nm.split(" -> ", 1)
        elif m.group(1)[0] == "l" and nm.endswith(" ->"):     # isoinfo prints "/" as ""
            nm, tgt = nm[:-3], ""
        got[(cur + nm).strip("/")] = (m.group(1), int(m.group(2)), tgt)
        n += 1
    return r, got, n

def check_isoinfo(t, arc, rr, files_rel, label, modes=None):
    probs = []
    r, got, _ = isoinfo_tree(t, arc, ["-R"])
    if r.returncode:
        probs.append("isoinfo -R rc=%d" % r.returncode)
    for p, v in rr.items():
        g = got.get(p)
        if g is None:
            probs.append("-R missing " + p)
            continue
        if isinstance(v, tuple):
            if g[0][0] != "l" or (len(v[1]) < 200 and g[2].rstrip("/") != norm_link(v[1]).rstrip("/")):
                probs.append("-R link %s %r" % (p, g))
        elif v is None:
            if g[0][0] != "d":
                probs.append("-R not dir " + p)
        elif g[1] != len(v):
            probs.append("-R size %s" % p)
        if modes and p in modes and g[0] != stat.filemode(modes[p]):
            probs.append("-R mode %s %s != %s" % (p, g[0], stat.filemode(modes[p])))
    r2, _, n2 = isoinfo_tree(t, arc, ["-J"])
    if r2.returncode or n2 != len(view(files_rel, True)):
        probs.append("isoinfo -J rc=%d %d entries (want %d)" % (r2.returncode, n2, len(view(files_rel, True))))
    r3, _, n3 = isoinfo_tree(t, arc, [])
    if r3.returncode or n3 != len(view(files_rel, False)):
        probs.append("isoinfo (primary) rc=%d %d entries" % (r3.returncode, n3))
    return t.record(not probs, label + " isoinfo", "; ".join(probs[:5]) or "%d/%d/%d entries" % (len(got), n2, n3))

def read_full_tree(root):
    out = {}
    for dp, dns, fns in os.walk(root):
        for d in dns:
            fp = os.path.join(dp, d)
            rel = os.path.relpath(fp, root)
            out[rel] = ("link", os.readlink(fp)) if os.path.islink(fp) else None
        for f in fns:
            fp = os.path.join(dp, f)
            rel = os.path.relpath(fp, root)
            out[rel] = ("link", os.readlink(fp)) if os.path.islink(fp) else open(fp, "rb").read()
    return out

def cmp_tree(got, exp):
    probs = []
    for p, v in exp.items():
        if p not in got:
            probs.append("missing %r" % p[:80])
            continue
        g = got[p]
        if isinstance(v, tuple):
            if g != ("link", norm_link(v[1])):
                probs.append("link %r: %r" % (p[:60], g))
        elif v is None:
            if g is not None:
                probs.append("not a dir %r" % p)
        elif g != v:
            probs.append("data %r (%s vs %d bytes)" % (p[:60], len(g) if isinstance(g, bytes) else g, len(v)))
    extra = set(got) - set(exp)
    if extra:
        probs.append("extra %r" % sorted(extra)[:3])
    return probs

def check_7z(t, arc, jol, label):
    out = t.path("x7_" + label.replace(" ", "_"))
    shutil.rmtree(out, ignore_errors=True)
    r = t.sh(["7z", "x", "-y", "-o" + out, arc], check=False)
    rt = t.sh(["7z", "t", arc], check=False)
    probs = []
    if r.returncode or rt.returncode or b"Warnings" in r.stdout:
        probs.append("7z rc=%d/%d %s" % (r.returncode, rt.returncode, r.stdout.decode(errors="replace")[-300:]))
    probs += cmp_tree(read_full_tree(out) if os.path.isdir(out) else {}, jol)
    shutil.rmtree(out, ignore_errors=True)
    # 7z l -slt: same names, folder flags and sizes
    rl = t.sh(["7z", "l", "-slt", "-sccUTF-8", arc], check=False)
    got, cur = {}, {}
    for line in rl.stdout.decode("utf-8", "replace").split("----------", 1)[-1].splitlines() + [""]:
        if not line.strip():
            if "Path" in cur:
                got[cur["Path"]] = (cur.get("Folder") == "+", int(cur.get("Size") or 0))
            cur = {}
        elif " = " in line:
            k, v = line.split(" = ", 1)
            cur[k] = v
    want = {p: (v is None, len(v) if isinstance(v, bytes) else 0) for p, v in jol.items()}
    if rl.returncode or got != want:
        probs.append("7z l: rc=%d missing %r extra %r" % (rl.returncode, sorted(set(want) - set(got))[:2],
                                                         sorted(set(got) - set(want))[:2]))
    return t.record(not probs, label + " 7z (Joliet)", "; ".join(probs[:5]) or "%d entries" % len(jol))

def check_bsdtar(t, arc, rr, label, modes=None, mtimes=None):
    out = t.path("xb_" + label.replace(" ", "_"))
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    r = t.sh(["bsdtar", "-xpf", arc, "-C", out], check=False)
    probs = []
    if r.returncode:
        probs.append("bsdtar rc=%d %s" % (r.returncode, r.stderr.decode(errors="replace")[-300:]))
    probs += cmp_tree(read_full_tree(out), rr)
    rl = t.sh(["bsdtar", "-tf", arc], check=False, env=dict(os.environ, LC_ALL="C.UTF-8"))   # listing: same names
    unesc = lambda m: b"\\" if m.group(1) == b"\\" else bytes([int(m.group(1), 8)])   # bsdtar escapes \ and \ooo
    names = {re.sub(rb"\\(\\|[0-7]{3})", unesc, l).decode("utf-8", "surrogateescape")
             for l in rl.stdout.splitlines()} - {"."}
    if rl.returncode or names != set(rr):
        probs.append("bsdtar -t: missing %r extra %r" % (sorted(set(rr) - names)[:2], sorted(names - set(rr))[:2]))
    for p, m in (modes or {}).items():
        fp = os.path.join(out, p)
        if os.path.lexists(fp) and not os.path.islink(fp) and (os.lstat(fp).st_mode & 0o7777) != (m & 0o7777):
            probs.append("mode %s %o != %o" % (p, os.lstat(fp).st_mode & 0o7777, m & 0o7777))
    for p, mt in (mtimes or {}).items():
        fp = os.path.join(out, p)
        if os.path.lexists(fp) and not os.path.isdir(fp) and int(os.lstat(fp).st_mtime) != mt:
            probs.append("mtime %s %d != %d" % (p, os.lstat(fp).st_mtime, mt))
    shutil.rmtree(out, ignore_errors=True)
    return t.record(not probs, label + " bsdtar (RR)", "; ".join(probs[:5]) or "%d entries" % len(rr))

def check_all(t, arc, files, label, modes=None, mtimes=None, rr=None, jol=None, tools=True, isovfy=True):
    rr = view(files, False) if rr is None else rr
    jol = view(files, True) if jol is None else jol
    iso = iso_check(t, arc, label)
    if iso and tools:
        check_xorriso(t, arc, rr, label)
        check_isoinfo(t, arc, rr, files, label, modes)
        check_7z(t, arc, jol, label)
        check_bsdtar(t, arc, rr, label, modes, mtimes)
        if isovfy:                                  # isovfy overflows on targets > ~600 bytes
            check_isovfy(t, arc, label)
        check_pycdlib(t, arc, rr, jol, label)
        KERNEL.append((label, arc, rr, jol, modes, mtimes))
    own_reader(t, arc, rr, label)
    return iso

# ---------------------------------------------------------------- Linux kernel (isofs)

KERNEL = []         # images checked with the real Linux driver: (label, arc, rr, jol, modes, mtimes)

class Digest(str):
    """expected file content as "size:md5" (for files too big to hold)"""

KINIT = r"""#!/bin/busybox sh
/bin/busybox mkdir -p /proc /dev /mnt
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t devtmpfs dev /dev
insmod /isofs.ko
insmod /nls_utf8.ko
dump() {
  cd /mnt
  find . -exec stat -c 'S|%f|%Y|%s|%n' {} +
  find . -type f -exec md5sum {} + | sed 's/^/M|/'
  find . -type l | while IFS= read -r f; do echo "L|$(readlink "$f")|$f"; done
  cd /
}
for d in /dev/vd?; do
  for m in rr:ro joliet:ro,norock,iocharset=utf8 plain:ro,norock,nojoliet; do
    echo "@@BEGIN ${d#/dev/} ${m%%:*}"
    if mount -t iso9660 -o ${m#*:} $d /mnt; then dump; umount /mnt; else echo "@@MOUNTFAIL"; fi
    echo "@@END"
  done
done
dmesg | grep -i -E "isofs|rock|iso9660|joliet" | sed 's/^/@@DMESG /'
echo "@@DONE"
poweroff -f
"""

def kernel_env(t):
    """(vmlinuz, isofs.ko.*, nls_utf8.ko.*) of an installed x86-64 distro kernel, or None"""
    if not sys.platform.startswith("linux") or os.uname().machine != "x86_64":
        return None
    if not (shutil.which("qemu-system-x86_64") and shutil.which("busybox") and shutil.which("cpio")):
        return None
    for ver in sorted(os.listdir("/lib/modules"), reverse=True) if os.path.isdir("/lib/modules") else []:
        kern = "/boot/vmlinuz-" + ver
        mods = []
        for sub, name in (("fs/isofs", "isofs.ko"), ("fs/nls", "nls_utf8.ko")):
            d = os.path.join("/lib/modules", ver, "kernel", sub)
            hit = [os.path.join(d, f) for f in (os.listdir(d) if os.path.isdir(d) else []) if f.startswith(name)]
            mods += hit[:1]
        if os.access(kern, os.R_OK) and len(mods) == 2:
            return kern, mods[0], mods[1]
    return None

def kernel_mount(t, env, isos):
    """Boot the kernel under QEMU with each image as a virtio disk; parse the dumps
    {(disk index, mode): {path: (kind, perm, mtime, info)}} (None: mount failed)."""
    kern, isofs, nls = env
    root = t.path("kinit")
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(os.path.join(root, "bin"))
    shutil.copy(shutil.which("busybox"), os.path.join(root, "bin", "busybox"))
    for src, dst in ((isofs, "isofs.ko"), (nls, "nls_utf8.ko")):
        data = open(src, "rb").read()
        if src.endswith(".zst"):
            data = t.sh(["zstd", "-dc", src]).stdout
        elif src.endswith(".xz"):
            data = t.sh(["xz", "-dc", src]).stdout
        open(os.path.join(root, dst), "wb").write(data)
    with open(os.path.join(root, "init"), "w") as f:
        f.write(KINIT)
    os.chmod(os.path.join(root, "init"), 0o755)
    names = subprocess.run(["find", "."], cwd=root, capture_output=True).stdout
    initrd = t.path("kinit.cpio")
    with open(initrd, "wb") as f:
        subprocess.run(["cpio", "-o", "-H", "newc", "--quiet"], cwd=root, input=names, stdout=f, check=True)
    cmd = ["qemu-system-x86_64", "-m", "768", "-nographic", "-no-reboot", "-net", "none", "-kernel", kern, "-initrd", initrd,
           "-append", "console=ttyS0 quiet loglevel=1 panic=-1 rdinit=/init"]
    for arc in isos:
        cmd += ["-drive", "file=%s,format=raw,if=virtio,readonly=on" % arc]
    r = subprocess.run(cmd, capture_output=True, timeout=900, stdin=subprocess.DEVNULL)
    out, cur, res, dm = r.stdout.decode("utf-8", "surrogateescape").replace("\r", ""), None, {}, []
    for line in out.split("\n"):
        if line[:2] not in ("S|", "M|", "L|") and "@@" in line:
            line = line[line.index("@@"):]          # console reset sequences before the first line
        if line.startswith("@@BEGIN "):
            _, disk, mode = line.split()
            cur = res.setdefault((ord(disk[2]) - ord("a"), mode), {})
        elif line == "@@MOUNTFAIL" and cur is not None:
            res[[k for k, v in res.items() if v is cur][0]] = None
            cur = None
        elif line == "@@END":
            cur = None
        elif line.startswith("@@DMESG "):
            dm.append(line[8:])
        elif cur is not None and line.startswith("S|"):
            _, mode, mt, size, path = line.split("|", 4)
            m = int(mode, 16)
            kind = "D" if stat.S_ISDIR(m) else "L" if stat.S_ISLNK(m) else "F"
            if path != ".":
                cur[path[2:]] = [kind, stat.S_IMODE(m), int(mt), size + ":" if kind == "F" else ""]
        elif cur is not None and line.startswith("M|") and line[34:38] == "  ./" and line[38:] in cur:
            cur[line[38:]][3] += line[2:34]
        elif cur is not None and line.startswith("L|"):
            tgt, path = line[2:].rsplit("|./", 1)
            if path in cur:
                cur[path][3] = tgt
    return res, "@@DONE" in out, dm

def case_kernel(t):
    """Mount every image checked above with the Linux isofs driver: Rock Ridge (names,
    modes, mtimes, symlinks, contents), Joliet (norock) and the plain primary tree."""
    env = kernel_env(t) if os.environ.get("GZ_ISO_KERNEL", "1") != "0" else None
    if not env:
        return t.record(True, "linux isofs", "skipped: qemu-system-x86_64 / busybox / cpio / kernel modules "
                        "not available (or GZ_ISO_KERNEL=0)")
    imgs = list(KERNEL)
    t0 = time.time()
    try:
        res, done, dm = kernel_mount(t, env, [arc for _, arc, *_ in imgs])
    except subprocess.TimeoutExpired:
        return t.record(False, "linux isofs", "QEMU timed out")
    if not res:                     # no virtio disk seen (e.g. virtio_blk is a module there): no verdict
        return t.record(True, "linux isofs", "skipped: %s did not reach the disks" % os.path.basename(env[0]))
    if not t.record(done, "linux isofs boot", "%s, %d images, %.0fs" % (os.path.basename(env[0]), len(imgs), time.time() - t0)):
        return
    md5 = lambda b: b if isinstance(b, Digest) else "%d:%s" % (len(b), hashlib.md5(b).hexdigest())
    for i, (label, arc, rr, jol, modes, mtimes) in enumerate(imgs):
        for mode, exp in (("rr", rr), ("joliet", jol)):
            if exp is None:
                continue
            got, probs = res.get((i, mode)), []
            if got is None:
                t.record(False, "%s linux %s" % (label, mode), "mount failed")
                continue
            if mode == "joliet":         # Linux drops trailing dots of Joliet names
                exp = {"/".join(c.rstrip(".") or c for c in p.split("/")): v for p, v in exp.items()}
            for p, v in exp.items():
                g = got.get(p)
                if g is None:
                    probs.append("missing %r" % p[:50])
                elif v is None:
                    if g[0] != "D":
                        probs.append("not a dir %r" % p[:50])
                elif isinstance(v, tuple):
                    if g[0] != "L" or g[3] != norm_link(v[1]):
                        probs.append("link %r -> %r" % (p[:40], g[3][:40]))
                elif g[0] != "F" or g[3] != md5(v):
                    probs.append("data %r" % p[:50])
                if g and mode == "rr" and modes and p in modes and not isinstance(v, tuple) and \
                        g[1] != stat.S_IMODE(modes[p]):
                    probs.append("mode %r %o" % (p[:40], g[1]))
                if g and mtimes and p in mtimes and g[2] != mtimes[p]:
                    probs.append("mtime %r %d != %d" % (p[:40], g[2], mtimes[p]))
            extra = set(got) - set(exp)
            if extra:
                probs.append("extra %r" % sorted(extra)[:3])
            t.record(not probs, "%s linux %s" % (label, mode), "; ".join(probs[:4]) or "%d entries" % len(got))
        plain = res.get((i, "plain"))          # 8.3-ish names: same entries and file contents
        want = sorted(md5(v) for v in rr.values() if isinstance(v, (bytes, Digest)) and not md5(v).startswith("0:"))
        have = sorted(g[3] for g in (plain or {}).values() if g[0] == "F" and not g[3].startswith("0:"))
        t.record(plain is not None and len(plain) == len(rr) and have == want, "%s linux primary" % label,
                 "%d entries (want %d)" % (len(plain or {}), len(rr)))
    t.record(not [l for l in dm if re.search(r"(?i)corrupt|error|bad|warn", l)], "linux isofs dmesg", "; ".join(dm[:3]))

def own_reader(t, arc, rr, label):
    """고깃ZIP's own ISO reader (src/fmt/iso.c) must show the Rock Ridge tree (names as
    the core normalizes them: '\\' is a separator there), link targets, and the same bytes."""
    r, typ, rows = t.listing(arc)
    if r.returncode or not typ or "ISO" not in typ.upper():
        return t.record(False, label + " own reader", "not opened as ISO: rc=%d type=%r" % (r.returncode, typ))
    lst = {}
    for row in rows:
        nm, tgt = row["name"], None
        if stat.S_ISLNK(row["mode"]) and " -> " in nm:
            nm, tgt = nm.split(" -> ", 1)
        lst[nm] = (row, tgt)
    r2, rows2, out = t.extract(arc)
    data = {}
    for i, (st, isdir, size, name) in rows2.items():
        fp = os.path.join(out, "%d.bin" % i)
        if not isdir and st == 0 and os.path.exists(fp):
            data[name] = open(fp, "rb").read()
    probs = [] if r2.returncode == 0 else ["gzt x rc=%d" % r2.returncode]
    exp = {normalize(p): v for p, v in rr.items()}
    for p, v in exp.items():
        if p not in lst:
            probs.append("missing %r" % p[:60])
            continue
        row, tgt = lst[p]
        if v is None:
            if not row["is_dir"]:
                probs.append("not a dir %r" % p[:60])
        elif isinstance(v, tuple):
            if tgt != norm_link(v[1]):
                probs.append("link %r -> %r" % (p[:40], (tgt or "")[:40]))
        elif data.get(p) != v:
            probs.append("data %r" % p[:60])
    extra = set(lst) - set(exp)
    if extra:
        probs.append("extra %r" % sorted(extra)[:3])
    shutil.rmtree(out, ignore_errors=True)
    return t.record(not probs, label + " own reader", "; ".join(probs[:4]) or "%d entries" % len(lst))

def check_isovfy(t, arc, label):
    """isovfy (genisoimage): path tables, directory records, RR fields of the primary tree"""
    r = t.sh(["isovfy", "-i", arc], check=False)
    out = (r.stdout + r.stderr).decode("utf-8", "replace").strip()
    ok = r.returncode == 0 and out.endswith("No errors found")
    return t.record(ok, label + " isovfy", "" if ok else out[-300:])

def check_pycdlib(t, arc, rr, jol, label):
    """pycdlib (strict pure-Python ISO parser) when installed: all three trees load and
    hold the expected names."""
    try:
        import pycdlib
    except ImportError:
        return True
    probs = []
    iso = pycdlib.PyCdlib()
    try:
        iso.open(arc)
        for facade, exp in (("rr_path", rr), ("joliet_path", jol)):
            got = set()
            for root, dirs, files in iso.walk(**{facade: "/"}):
                for nm in dirs + files:
                    got.add((root.rstrip("/") + "/" + nm).lstrip("/"))
            if got != set(exp):
                probs.append("%s: missing %r extra %r" % (facade, sorted(set(exp) - got)[:2], sorted(got - set(exp))[:2]))
        n = sum(len(d) + len(f) for _, d, f in iso.walk(iso_path="/"))
        if n != len(rr):
            probs.append("iso9660 tree has %d entries, want %d" % (n, len(rr)))
        iso.close()
    except Exception as e:
        probs.append("exception %r" % e)
    return t.record(not probs, label + " pycdlib", "; ".join(probs[:3]))

# tests/gzt.c does not free its item list: keep LeakSanitizer for the driver runs only
NOLEAK = {"ASAN_OPTIONS": (os.environ.get("ASAN_OPTIONS", "") + ":detect_leaks=0").lstrip(":")}

def gzt_create(t, arc, src, rels, label):
    if os.path.exists(arc):
        os.remove(arc)
    r = t.run_gzt(["c", "iso", arc, "0", "-", src] + rels, NOLEAK, timeout=600)
    ok = r.returncode == 0 and b"CREATE 0" in r.stdout and b"Sanitizer" not in r.stderr
    t.record(ok, label + " create", "" if ok else (r.stdout + r.stderr).decode(errors="replace")[-300:])
    return ok

def drv_run(t, drv, arc, lines, timeout=900):
    spec = arc + ".spec"
    with open(spec, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write("\n".join(lines) + "\n")
    if os.path.exists(arc):
        os.remove(arc)
    r = subprocess.run([drv, arc, spec], capture_output=True, timeout=timeout)
    out = r.stdout.decode("utf-8", "replace")
    errs = [tuple(map(int, l.split()[1:3])) for l in out.splitlines() if l.startswith("ERR ")]
    m = re.search(r"CREATE (-?\d+) (\d+)", out)
    pm = re.search(r"PROG (\d+) (\d+) (\d+) (\d)", out)
    om = re.search(r"OPENS (\d+) CLOSES (\d+)", out)
    san = b"Sanitizer" in r.stderr or b"runtime error" in r.stderr
    res = dict(rc=(int(m.group(1)) if m else None) if not san else "sanitizer", written=int(m.group(2)) if m else 0, errs=errs,
               prog=tuple(map(int, pm.groups())) if pm else None, out=out, stderr=r.stderr.decode(errors="replace"),
               opens=tuple(map(int, om.groups())) if om else None)
    return res

def vline(name, size, mode="0644", mtime=1600000000, attr=0):
    return "v\t%s\t%d\t%d\t%d\t%s" % (mode, mtime, attr, size, name)

def dline(name, mode="0755", mtime=1600000000, attr=0x10):
    return "d\t%s\t%d\t%d\t%s" % (mode, mtime, attr, name)

def lline(name, target, mtime=1600000000):
    return "l\t0777\t%d\t0\t%s\t%s" % (mtime, target, name)

# ---------------------------------------------------------------- cases

def case_main_tree(t):
    deep = "/".join("깊이%02d" % i for i in range(1, 13))
    files = {
        "readme.txt": b"hello iso\n",
        "문서": None,
        "문서/보고서.txt": blob(120000, 1),
        "문서/사진": None,
        "문서/사진/고기.jpg": blob(70001, 2),
        "empty.txt": b"",
        "empty_dir": None,
        "UPPER.TXT": b"upper",
        "upper.txt": b"lower",
        "Upper.txt": b"mixed",
        "archive.tar.gz": blob(3000, 3),
        "noext": b"x",
        ".hidden": b"h",
        ".hidden.txt": b"h2",
        "name with spaces.doc": b"sp",
        "odd;name?*.txt": b"joliet forbidden chars",
        "back\\slash:colon": b"bs",
        "dots.in.the.middle.of.name.c": b"dots",
        "verylongextension.abcdefghijklmnopqrstuvwxyz": b"ext",
        "sizes": None,
        "sizes/s1": b"1",
        "sizes/s2047": blob(2047, 4),
        "sizes/s2048": blob(2048, 5),
        "sizes/s2049": blob(2049, 6),
        "sizes/s1M+1": blob((1 << 20) + 1, 7),
        "sizes/s3M": blob(3 << 20, 8),
        ("L" * 200) + ".txt": blob(500, 9),
        ("M" * 120): b"no extension, long",
        ("D" * 200) + "/inner.txt": b"inside long dir",
        ("가" * 70) + ".hwp": b"korean 70",
        ("나" * 80) + ".txt": b"korean 80 (244 bytes)",
        deep + "/leaf.txt": b"twelve levels down",
        deep + "/빈폴더": None,
        "Ünïcödé €uro.txt": b"latin + euro",
        "emoji 😀 name.txt": b"astral plane",
    }
    src = t.write_tree(t.path("main_src"), files)
    os.chmod(os.path.join(src, "readme.txt"), 0o600)
    os.chmod(os.path.join(src, "noext"), 0o755)
    mt = 1500000000
    for i, rel in enumerate(sorted(files)):
        os.utime(os.path.join(src, rel), (mt + i * 3600, mt + i * 3600))
    rels = sorted(files)
    arc = t.path("main.iso")
    t0 = time.time()
    if not gzt_create(t, arc, src, rels, "main"):
        return
    dt = time.time() - t0
    full = dict(files)
    for i in range(1, 13):                                     # implicit directories
        full["/".join(deep.split("/")[:i])] = None
    full["D" * 200] = None
    modes = {rel: os.lstat(os.path.join(src, rel)).st_mode for rel in files}
    mtimes = {rel: int(os.lstat(os.path.join(src, rel)).st_mtime) for rel in files if files[rel] is not None}
    # Joliet lookups ignore case: items come sorted, so UPPER.TXT keeps its name
    jol = {{"Upper.txt": "Upper~1.txt", "upper.txt": "upper~2.txt"}.get(k, k): v for k, v in view(full, True).items()}
    iso = check_all(t, arc, full, "main", modes={view({k: 1}, False).popitem()[0]: m for k, m in modes.items()},
                    mtimes={view({k: 1}, False).popitem()[0]: m for k, m in mtimes.items()}, jol=jol)
    if iso:
        t.record(iso.label_p == "GOGITZIP" and iso.label_j == "GOGITZIP", "main default label",
                 "%r %r" % (iso.label_p, iso.label_j))
        iso.close()
    arc2 = t.path("main2.iso")
    if gzt_create(t, arc2, src, rels, "main again"):
        t.record(open(arc, "rb").read() == open(arc2, "rb").read(), "main deterministic output")
    t.record(True, "main timing", "%.2fs for %d items, %d bytes" % (dt, len(rels), os.path.getsize(arc)))

def case_label(t, drv):
    for lab, want_p, want_j in (("My Disc 2024", "MY_DISC_2024", "My Disc 2024"),
                                ("사진 모음", "GOGITZIP", "사진 모음"),
                                ("A very long volume label exceeding", "A_VERY_LONG_VOLUME_LABEL_EXCEEDI",
                                 "A very long volu")):
        arc = t.path("label_%d.iso" % len(want_p))
        res = drv_run(t, drv, arc, ["opt\tlabel\t" + lab, vline("a.txt", 10)])
        iso = Iso(arc).check() if res["rc"] == 0 else None
        ok = iso is not None and not iso.p and iso.label_p == want_p and iso.label_j == want_j
        t.record(ok, "label %r" % lab, "" if ok else "%r %r %r" % (res["rc"], iso and iso.label_p, iso and iso.label_j))
        r = t.sh(["isoinfo", "-d", "-i", arc], check=False)
        t.record(("Volume id: " + want_p).encode() in r.stdout, "label %r isoinfo -d" % lab)
        if iso:
            iso.close()
    # derived from a single top-level folder
    src = t.write_tree(t.path("label_src"), {"Photos": None, "Photos/a.jpg": b"jpg", "Photos/b.jpg": b"jpg2"})
    arc = t.path("label_derived.iso")
    if gzt_create(t, arc, src, ["Photos", "Photos/a.jpg", "Photos/b.jpg"], "label derived"):
        iso = Iso(arc).check()
        t.record(iso.label_p == "PHOTOS" and iso.label_j == "Photos", "label derived from folder",
                 "%r %r" % (iso.label_p, iso.label_j))
        iso.close()

def case_symlinks(t, drv):
    src = t.path("sym_src")
    shutil.rmtree(src, ignore_errors=True)
    os.makedirs(os.path.join(src, "links/sub"))
    open(os.path.join(src, "links/target.txt"), "wb").write(b"target data")
    open(os.path.join(src, "links/sub/f.txt"), "wb").write(b"in sub")
    links = {
        "to_file": "target.txt",
        "to_dir": "sub",
        "abs": "/etc/hostname",
        "dangling": "does/not/exist",
        "up": "../links/target.txt",
        "dot": "./target.txt",
        "root": "/",
        "trailing": "sub/",
        "double": "sub//f.txt",
        "한글링크": "대상/파일.txt",
        "long": "c" * 300 + "/" + "d" * 10,
        "many": "/".join("p%d" % i for i in range(200)),   # 889 bytes: 4 SL entries
        "big4k": "/".join(["y" * 250] * 16),            # 4015 bytes: cut to 1023 by the writer
    }
    for k, v in links.items():
        os.symlink(v, os.path.join(src, "links", k))
    rels = ["links", "links/sub", "links/target.txt", "links/sub/f.txt"] + ["links/" + k for k in links]
    files = {"links": None, "links/sub": None, "links/target.txt": b"target data", "links/sub/f.txt": b"in sub"}
    for k, v in links.items():
        files["links/" + k] = ("link", v)
    arc = t.path("symlinks.iso")
    long_t = "/".join(["x" * 255] * 17)                  # > 4095 bytes: cut to 1023
    files["links/verylong"] = ("link", long_t)
    res = drv_run(t, drv, arc, ["t\t%s\t%s" % (src, r) for r in rels] + [lline("links/verylong", long_t)])
    if not t.record(res["rc"] == 0, "symlinks create", "" if res["rc"] == 0 else res["out"][-300:] + res["stderr"][-300:]):
        return
    rr = view(files, False)
    rr["links/verylong"] = ("link", long_t[:1023])       # libisofs refuses >= 1024
    rr["links/big4k"] = ("link", links["big4k"][:1023])
    iso = check_all(t, arc, files, "symlinks", rr=rr, isovfy=False)
    if iso:
        bad = [p for p, v in rr.items() if isinstance(v, tuple) and iso.rr.get(p, {}).get("target") != norm_link(v[1])]
        t.record(not bad, "symlinks SL decode", "%r" % bad[:3])
        modes = [p for p, v in iso.rr.items() if p in rr and isinstance(rr[p], tuple) and not stat.S_ISLNK(v["mode"])]
        t.record(not modes, "symlinks PX mode", "%r" % modes[:3])
        t.record(not any(isinstance(v, tuple) for v in iso.jol.values()) and
                 "links/to_file" not in iso.jol, "symlinks absent from Joliet")
        iso.close()
    # gzt c gives no link targets (no is_link): the writer must fall back to empty files
    arc = t.path("symlinks_gzt.iso")
    if gzt_create(t, arc, src, rels, "symlinks via gzt"):
        iso = Iso(arc).check()
        ok = not iso.p and iso.rr["links/dangling"]["size"] == 0 and stat.S_ISREG(iso.rr["links/dangling"]["mode"])
        t.record(ok, "symlinks via gzt become empty files", "; ".join(iso.p[:3]))
        iso.close()

def case_names(t, drv):
    lines, sizes = [], []
    def add(name, size, **kw):
        lines.append(vline(name, size, **kw))
        sizes.append(size)
    # many names mapping to one primary name ("___.TXT"), directory spans sectors
    lines.append(dline("모음"))
    hangul = [chr(0xAC00 + i * 37 % 11172) for i in range(400)]
    for i in range(1500):
        add("모음/%s%s%s.txt" % (hangul[i % 400], hangul[(i // 400) * 7 % 400], hangul[i * 13 % 400]), 100 + i)
    # names colliding in Joliet after truncation to 103 units
    for i in range(6):
        add("jol/" + "A" * 110 + "%d.txt" % i, 200 + i)
    # file and directory with the same name, duplicate items, items before their directory
    add("same", 11)
    lines.append(dline("same"))
    add("same/inner.txt", 12)
    add("dup.txt", 13)
    add("dup.txt", 14)
    add("late/b/c/file.txt", 15)
    lines.append(dline("late/b", mode="0700"))
    # odd paths
    add("/abs/path.txt", 16)
    add("./dot/x.txt", 17)
    add("p//q.txt", 18)
    add("../../escape.txt", 19)
    lines.append(vline("", 5))                               # file without a name: reported
    lines.append(dline(""))                                  # the root itself
    add("ctrl\x01char.txt", 20)
    add("hidden.txt", 21, attr=2)
    add("unknown_time.txt", 22, mtime=-1)
    add("t1969.txt", 23, mtime=-100)
    add("t1850.txt", 24, mtime=-5000000000)
    add("t2100.txt", 25, mtime=4102444800)
    add("t3000.txt", 26, mtime=32503680000)
    add("setuid", 27, mode="04755")
    add("derive_mode", 28, mode="0")
    # Joliet lookups (Windows, Linux) ignore case and trailing dots/spaces; Rock Ridge does not
    ci = ["Readme.TXT", "README.txt", "readme.txt", "ÄÖÜ.txt", "äöü.txt", "Привет.txt", "привет.txt",
          "trail.", "trail", "sp ", "sp", "ΣΊΣΥΦΟΣ", "σίσυφος"]
    for i, nm in enumerate(ci):
        add("ci/" + nm, 40 + i)
    arc = t.path("names.iso")
    t0 = time.time()
    res = drv_run(t, drv, arc, lines)
    dt = time.time() - t0
    ok = res["rc"] == 0 and res["errs"] == [(lines.index(vline("", 5)), 2)]
    if not t.record(ok, "names create", "rc=%r errs=%r %s" % (res["rc"], res["errs"], res["stderr"][-200:])):
        return
    iso = iso_check(t, arc, "names")
    if not iso:
        return
    rr = {k: v for k, v in iso.rr.items()}
    # Joliet/RR uniquification: every file survives with distinct names and right sizes
    jfiles = sorted(v["size"] for k, v in iso.jol.items() if k.startswith("jol/"))
    t.record(jfiles == [200 + i for i in range(6)], "names Joliet collisions kept", "%r" % jfiles)
    jl = [k for k in iso.jol if k.startswith("jol/")]
    t.record(all(len(k[4:]) <= JMAX and k.endswith(".txt") and k.startswith("jol/AAAA") for k in jl),
             "names Joliet truncation", "%r" % [len(k) for k in jl])
    want = ["abs/path.txt", "dot/x.txt", "p/q.txt", "escape.txt", "same", "same~1/inner.txt", "dup.txt", "dup~1.txt",
            "late/b/c/file.txt", "ctrl\x01char.txt"]
    t.record(all(w in rr for w in want), "names odd paths", "%r" % [w for w in want if w not in rr])
    t.record(stat.S_IMODE(rr["late/b"]["mode"]) == 0o700, "names late directory item")
    t.record(stat.S_IMODE(rr["setuid"]["mode"]) == 0o4755 and stat.S_IMODE(rr["derive_mode"]["mode"]) == 0o644,
             "names modes")
    t.record("hidden.txt" in iso.hidden and len(iso.hidden) == 1, "names hidden flag (Joliet)", "%r" % iso.hidden)
    t.record(len([k for k in rr if k.startswith("모음/")]) == 1500, "names 1500 same-primary files")
    jci = [k[3:] for k in iso.jol if k.startswith("ci/")]
    t.record(all("ci/" + nm in rr for nm in ci) and len(jci) == len(ci) and
             len({jfold_key(k).upper() for k in jci}) == len(ci), "names Joliet case-insensitive", "%r" % sorted(jci))
    d1850 = rr["t1850.txt"]["date"]                          # libarchive clamps < 1901 itself
    kexp = lambda tree: {k: None if v["dir"] else pat_data(v["size"]) for k, v in tree.items()}
    KERNEL.append(("names", arc, kexp(rr), kexp(iso.jol), {k: v["mode"] for k, v in rr.items()},
                   {"t1969.txt": -100, "t2100.txt": 4102444800, "t3000.txt": 5869583999, "setuid": 1600000000}))
    iso.close()
    # contents through both readers (names as stored)
    out = t.path("names_bsdtar")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    r = t.sh(["bsdtar", "-xpf", arc, "-C", out], check=False)
    got = read_full_tree(out)
    exp_sizes = sorted(sizes)
    got_sizes = sorted(len(v) for v in got.values() if isinstance(v, bytes))
    content_ok = all(v == pat_data(len(v)) for v in got.values() if isinstance(v, bytes))
    t.record(r.returncode == 0 and got_sizes == exp_sizes and content_ok, "names bsdtar contents",
             "rc=%d %d vs %d files %s" % (r.returncode, len(got_sizes), len(exp_sizes), r.stderr[-200:]))
    mt = {p: int(os.lstat(os.path.join(out, p)).st_mtime) for p in ("t1969.txt", "t2100.txt", "t3000.txt")}
    t.record(mt["t1969.txt"] == -100 and mt["t2100.txt"] == 4102444800 and mt["t3000.txt"] == 5869583999 and
             d1850 == b"\0\1\1\0\0\0\0", "names extreme mtimes (clamped to 1900..2155)", "%r %r" % (mt, d1850))
    shutil.rmtree(out, ignore_errors=True)
    out = t.path("names_7z")
    shutil.rmtree(out, ignore_errors=True)
    r = t.sh(["7z", "x", "-y", "-o" + out, arc], check=False)
    got = read_full_tree(out)
    got_sizes = sorted(len(v) for v in got.values() if isinstance(v, bytes))
    content_ok = all(v == pat_data(len(v)) for v in got.values() if isinstance(v, bytes))
    t.record(r.returncode == 0 and got_sizes == exp_sizes and content_ok, "names 7z contents",
             "rc=%d %d vs %d" % (r.returncode, len(got_sizes), len(exp_sizes)))
    shutil.rmtree(out, ignore_errors=True)
    rx = t.sh(["xorriso", "-indev", arc, "-find", "/", "-exec", "lsdl"], check=False)
    t.record(rx.returncode == 0 and not re.search(rb"WARNING|FAILURE|SORRY", rx.stderr), "names xorriso")
    check_isovfy(t, arc, "names")
    t.record(True, "names timing", "%.2fs for %d items" % (dt, len(lines)))

def case_rr_long(t, drv):
    """Names over 253 UTF-8 bytes: Rock Ridge shortens them (keeping the extension)
    and numbers the clashes. Their Joliet names (103 Hangul = 309 bytes) cannot be
    created on Linux, so 7z is not used here."""
    lines = []
    for i in range(4):
        nm = "rr/" + "한" * 100 + "%d.txt" % i
        lines.append(vline(nm, 300 + i))
    lines.append(vline("rr/" + "가" * 90 + ".verylongextension_kept_whole", 400))
    lines.append(dline("rr/" + "디" * 120))
    arc = t.path("rrlong.iso")
    res = drv_run(t, drv, arc, lines)
    if not t.record(res["rc"] == 0, "rr long create", res["stderr"][-200:]):
        return
    iso = iso_check(t, arc, "rr long")
    if not iso:
        return
    rl = sorted(k for k in iso.rr if k.startswith("rr/") and not iso.rr[k]["dir"])
    t.record(len(rl) == 5 and all(len(k[3:].encode()) <= RRMAX for k in rl), "rr long truncation",
             "%r" % [len(k[3:].encode()) for k in rl])
    t.record(sum(k.endswith(".txt") for k in rl) == 4 and sum("~" in k for k in rl) == 3, "rr long clashes numbered")
    t.record(any(k.endswith(".verylongextension_kept_whole") for k in rl), "rr long extension kept")
    rs = sorted(v["size"] for k, v in iso.rr.items() if k.startswith("rr/") and not v["dir"])
    t.record(rs == [300, 301, 302, 303, 400], "rr long sizes", "%r" % rs)
    rd = [k for k in iso.rr if iso.rr[k]["dir"] and k.startswith("rr/")]
    t.record(len(rd) == 1 and len(rd[0][3:].encode()) == RRMAX // 3 * 3, "rr long directory name",
             "%r" % [len(k[3:].encode()) for k in rd])
    exp = {k: pat_data(iso.rr[k]["size"]) for k in rl}
    exp.update({"rr": None, rd[0]: None} if rd else {})
    iso.close()
    check_bsdtar(t, arc, exp, "rr long")
    check_xorriso(t, arc, exp, "rr long")
    KERNEL.append(("rr long", arc, exp, None, None, None))

def case_errors(t, drv):
    base = [vline("ok1.bin", 5000),
            "e\t0644\t1600000000\t0\t10000\tfail_open.bin",
            "s\t0644\t1600000000\t0\t300000\t1000\tshort.bin",
            "r\t0644\t1600000000\t0\t2000000\t1100000\treaderr.bin",
            vline("ok2.bin", 7000)]
    total = 5000 + 10000 + 300000 + 2000000 + 7000
    arc = t.path("errors_skip.iso")
    res = drv_run(t, drv, arc, ["opt\tonerror\tskip"] + base)
    ok = res["rc"] == 0 and res["errs"] == [(1, 1), (2, 9), (3, 1)]
    t.record(ok, "errors skip: reported", "rc=%r errs=%r" % (res["rc"], res["errs"]))
    t.record(res["prog"] is not None and res["prog"][1:] == (total, total, 1), "errors progress", "%r" % (res["prog"],))
    t.record(res["opens"] == (5, 4), "errors open/close pairs", "%r" % (res["opens"],))   # fail_open is not closed
    exp = {"ok1.bin": pat_data(5000), "ok2.bin": pat_data(7000), "fail_open.bin": bytes(10000),
           "short.bin": pat_data(300000)[:1000] + bytes(299000),
           "readerr.bin": pat_data(2000000)[:1100000] + bytes(900000)}
    if res["rc"] == 0:
        check_all(t, arc, exp, "errors skip")
    arc = t.path("errors_abort.iso")
    res = drv_run(t, drv, arc, ["opt\tonerror\tabort"] + base)
    t.record(res["rc"] == 1 and res["errs"] == [(1, 1)], "errors abort", "rc=%r errs=%r" % (res["rc"], res["errs"]))
    arc = t.path("errors_none.iso")
    res = drv_run(t, drv, arc, ["opt\tonerror\tnone"] + base[:3])
    t.record(res["rc"] == 1 and not res["errs"], "errors without on_error", "rc=%r" % res["rc"])
    arc = t.path("cancel.iso")
    res = drv_run(t, drv, arc, ["opt\tcancel\t%d" % (2 << 20), vline("big.bin", 8 << 20), vline("after.bin", 10)])
    t.record(res["rc"] == 8 and res["written"] < (5 << 20), "cancel", "rc=%r written=%d" % (res["rc"], res["written"]))

def case_roundtrip(t):
    """the shared helper: gzt c iso, 7z extraction (Joliet) and 고깃ZIP's own extraction"""
    files = {"a.txt": b"alpha\n", "dir": None, "dir/b.bin": blob(5000, 11), "dir/빈 파일": b"",
             "한글 폴더": None, "한글 폴더/문서.hwp": blob(40000, 12)}
    t.check_roundtrip("iso", files, level=0, label="roundtrip gzt c iso", env=NOLEAK)

def case_empty(t, drv):
    arc = t.path("empty.iso")
    res = drv_run(t, drv, arc, ["opt\tlabel\tEMPTY"])
    if t.record(res["rc"] == 0, "empty image create", "" if res["rc"] == 0 else res["out"][-200:] + res["stderr"][-300:]):
        check_all(t, arc, {}, "empty image")
    arc = t.path("emptydirs.iso")
    res = drv_run(t, drv, arc, [dline("a"), dline("a/b"), dline("c"), vline("c/zero", 0)])
    t.record(res["opens"] == (1, 1), "empty file opened and closed", "%r" % (res["opens"],))
    if t.record(res["rc"] == 0, "empty dirs create", "" if res["rc"] == 0 else res["out"][-200:] + res["stderr"][-300:]):
        check_all(t, arc, {"a": None, "a/b": None, "c": None, "c/zero": b""}, "empty dirs")

def case_many(t, drv):
    lines = []
    n = 0
    for d in range(40):
        lines.append(dline("dir%02d" % d))
        for f in range(500):
            lines.append(vline("dir%02d/file_%04d_%s.dat" % (d, f, "x" * (f % 50)), f % 7))
            n += 1
    arc = t.path("many.iso")
    t0 = time.time()
    res = drv_run(t, drv, arc, lines)
    dt = time.time() - t0
    if t.record(res["rc"] == 0, "many files create", res["stderr"][-200:]):
        iso = iso_check(t, arc, "many files")
        if iso:
            t.record(len(iso.rr) == n + 40 and len(iso.jol) == n + 40, "many files count")
            iso.close()
        r = t.sh(["bsdtar", "-tf", arc], check=False)
        t.record(r.returncode == 0 and len(r.stdout.splitlines()) >= n + 40, "many files bsdtar list")
    t.record(True, "many files timing", "%.2fs for %d items (%.0f items/s incl. driver)" % (dt, n + 40, (n + 40) / max(dt, 1e-6)))

def stream_check(t, cmd, size, label):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    pos, ok, chunk = 0, True, 1 << 22
    while True:
        b = p.stdout.read(chunk)
        if not b:
            break
        if b != pat_chunk(pos, pos + len(b), size):
            ok = False
            p.kill()
            break
        pos += len(b)
    p.wait()
    return t.record(ok and pos == size, label, "%d of %d bytes ok=%r" % (pos, size, ok))

def case_big(t, drv):
    size = (4 << 30) + (100 << 20) + 12345
    arc = t.path("big.iso")
    t0 = time.time()
    res = drv_run(t, drv, arc, ["opt\tsparse\t1", vline("big.bin", size), vline("small.txt", 1000), dline("d"),
                                vline("d/after.bin", 3000)], timeout=3600)
    dt = time.time() - t0
    if not t.record(res["rc"] == 0, "big create", "" if res["rc"] == 0 else "%s %s" % (res["out"][-200:], res["stderr"][-200:])):
        return
    t.record(True, "big timing", "%.1fs for %d bytes (%.0f MB/s incl. driver)" % (dt, size, size / dt / 1e6))
    iso = iso_check(t, arc, "big")
    if iso:
        e = iso.rr.get("big.bin", {})
        t.record(e.get("size") == size and e.get("n") == 2 and iso.jol.get("big.bin", {}).get("n") == 2,
                 "big multi-extent records", "%r" % e)
        iso.close()
    r = t.sh(["xorriso", "-indev", arc, "-find", "/", "-exec", "lsdl"], check=False)
    t.record(re.search(rb"\s%d\s+\w+\s+\d+\s+[\d:]+\s+'/big.bin'" % size, r.stdout) is not None, "big xorriso size")
    r = t.sh(["7z", "l", arc], check=False)
    t.record(re.search(rb"\s%d\s+%d\s+big.bin" % (size, size), r.stdout) is not None, "big 7z list")
    stream_check(t, ["7z", "x", "-so", arc, "big.bin"], size, "big 7z data")
    stream_check(t, ["bsdtar", "-xOf", arc, "big.bin"], size, "big bsdtar data")
    r = t.sh(["bsdtar", "-xOf", arc, "d/after.bin"], check=False)
    t.record(r.stdout == pat_data(3000), "big file after multi-extent")
    if kernel_env(t):                                        # the Linux driver reads it in run()
        h = hashlib.md5()
        for a in range(0, size, 1 << 24):
            h.update(pat_chunk(a, min(size, a + (1 << 24)), size))
        exp = {"big.bin": Digest("%d:%s" % (size, h.hexdigest())), "small.txt": pat_data(1000), "d": None,
               "d/after.bin": pat_data(3000)}
        KERNEL.append(("big", arc, exp, exp, None, None))
    else:
        os.remove(arc)

def rand_units(rnd, n):
    out = []
    while len(out) < n:
        k = rnd.random()
        if k < 0.45:
            out.append(rnd.randint(0x21, 0x7e))
        elif k < 0.65:
            out.append(0xAC00 + rnd.randint(0, 11171))
        elif k < 0.72:
            out.append(rnd.randint(1, 0x1f))
        elif k < 0.80:
            out.append(ord(rnd.choice(".;:*?~ \\")))
        elif k < 0.85:
            out.append(rnd.randint(0xD800, 0xDFFF))          # lone surrogate halves
        elif k < 0.90:
            out += [rnd.randint(0xD800, 0xDBFF), rnd.randint(0xDC00, 0xDFFF)]
        else:
            out.append(rnd.choice([0xFFFF, 0xFEFF, 0x00E9, 0x20AC, 0x3000, 0xFFFD]))
    return out[:n]

def hexu(units):
    return "".join("%04x" % u for u in units)

def case_fuzz(t, drv, rounds=30):
    """Random item lists (odd units, lone surrogates, clashes, deep paths, links,
    failing files): the writer must succeed and produce a structurally valid image
    that xorriso and bsdtar load."""
    probs = []
    slash = [ord("/")]
    for seed in range(rounds):
        rnd = random.Random(seed)
        vocab = [rand_units(rnd, rnd.choice([1, 2, 3, 8, 30, 31, 32, 64, 103, 104, 130, 260]))
                 for _ in range(12)] + [[0x2E], [0x2E, 0x2E], []]
        lines = ["opt\twide\t1", "opt\tonerror\tskip"]
        for i in range(rnd.randint(1, 70)):
            path = []
            for _ in range(rnd.choice([1, 1, 2, 3, 5, 9, 14])):
                path += (rnd.choice(vocab) if rnd.random() < 0.7 else rand_units(rnd, rnd.randint(1, 40))) + slash
            name = hexu(path[:-1])
            k = rnd.random()
            if k < 0.25:
                lines.append("d\t0%o\t%d\t%d\t%s" % (rnd.choice([0, 0o755, 0o700]), rnd.randint(-1, 4 << 30), 0x10, name))
            elif k < 0.40:
                tgt = []
                for _ in range(rnd.randint(1, 60)):
                    tgt += rand_units(rnd, rnd.randint(0, 40)) + slash
                lines.append("l\t0777\t%d\t0\t%s\t%s" % (rnd.randint(-1, 1 << 31), hexu(tgt[:rnd.randint(1, len(tgt))]), name))
            else:
                size = rnd.choice([0, 1, 2047, 2048, 2049, rnd.randint(0, 70000)])
                kind = rnd.choice("vvvvvves r")
                extra = {"s": "\t%d" % rnd.randint(0, size), "r": "\t%d" % rnd.randint(0, size)}.get(kind, "")
                lines.append("%s\t0%o\t%d\t%d\t%d%s\t%s" % (kind, rnd.choice([0, 0o644, 0o4755]), rnd.randint(-1, 1 << 33),
                                                          rnd.choice([0, 1, 2, 0x20]), size, extra, name))
        arc = t.path("fuzz.iso")
        res = drv_run(t, drv, arc, lines)
        if res["rc"] != 0 or "Sanitizer" in res["stderr"] or "runtime error" in res["stderr"]:
            probs.append("seed %d: rc=%r %s" % (seed, res["rc"], res["stderr"][-300:]))
            continue
        iso = Iso(arc).check()
        if iso.p:
            probs.append("seed %d: %s" % (seed, "; ".join(iso.p[:3])))
        iso.close()
        rx = t.sh(["xorriso", "-indev", arc, "-find", "/", "-exec", "lsdl"], check=False)
        if rx.returncode or re.search(rb"SORRY|FAILURE|FATAL", rx.stderr):
            probs.append("seed %d: xorriso %s" % (seed, rx.stderr[-200:]))
        rb = t.sh(["bsdtar", "-tf", arc], check=False)
        if rb.returncode:
            probs.append("seed %d: bsdtar %s" % (seed, rb.stderr[-200:]))
    t.record(not probs, "fuzz %d random item lists" % rounds, "; ".join(probs[:4]))

def case_hostile_items(t, drv):
    """Absurd sizes must fail cleanly (GZ_E_LIMIT) without writing anything huge."""
    arc = t.path("absurd.iso")
    res = drv_run(t, drv, arc, [vline("huge.bin", 1 << 60)])
    t.record(res["rc"] == 15 and res["written"] == 0, "absurd size -> GZ_E_LIMIT", "rc=%r" % res["rc"])
    res = drv_run(t, drv, arc, [vline("a%d" % i, (1 << 43) // 3) for i in range(4)])
    t.record(res["rc"] == 15 and res["written"] == 0, "volume > 8 TiB -> GZ_E_LIMIT", "rc=%r" % res["rc"])

def run(t):
    t.need("xorriso", "isoinfo", "7z", "bsdtar")
    drv = t.build_driver("tests/drivers/iso_wdrv.c")
    case_main_tree(t)
    case_roundtrip(t)
    case_label(t, drv)
    case_symlinks(t, drv)
    case_names(t, drv)
    case_rr_long(t, drv)
    case_errors(t, drv)
    case_empty(t, drv)
    case_many(t, drv)
    case_hostile_items(t, drv)
    case_fuzz(t, drv, int(os.environ.get("GZ_ISO_FUZZ", "30")))
    if os.environ.get("GZ_TEST_BIG"):
        case_big(t, drv)
    case_kernel(t)
    if os.path.exists(t.path("big.iso")):
        os.remove(t.path("big.iso"))
