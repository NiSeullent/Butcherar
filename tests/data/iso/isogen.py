"""
Minimal ISO 9660 image writer for reader edge cases (used by tests/cases/fmt_iso.py).

Real tools (genisoimage, xorriso) cover the common layouts; this writer builds what
they cannot: multi-extent files with small or out-of-order extents, interleaved
files, associated files, extended attribute records, Rock Ridge continuation areas
(also looping ones), directory loops and other hostile structures.

    img = Iso(rr=True)
    root = img.root
    d = img.dir(root, "sub")
    img.file(d, "a.txt", b"data", extents=[(0, 2), (2, 4)])   # byte ranges -> extents
    img.file(d, "big", records=[(lba, size), ...])             # raw extents (sparse images)
    raw = img.build()

Every record can carry raw overrides (flags, lba, size, name bytes, system use).
"""
import struct

SEC = 2048


def both16(v):
    return struct.pack("<H", v) + struct.pack(">H", v)


def both32(v):
    return struct.pack("<I", v) + struct.pack(">I", v)


def rec_date(t=(126, 11, 1, 12, 30, 15, 36)):
    """years since 1900, month, day, hour, minute, second, GMT offset (15 min units)"""
    y, mo, d, h, mi, s, tz = t
    return bytes([y, mo, d, h, mi, s, tz & 0xff])


def dir_record(name, lba, size, flags=0, date=None, su=b"", ear=0, fus=0, gap=0):
    nl = len(name)
    pad = b"\0" if nl % 2 == 0 else b""
    body = bytes([ear]) + both32(lba) + both32(size) + (date or rec_date()) + bytes([flags, fus, gap]) + \
        both16(1) + bytes([nl]) + name + pad + su
    rl = 1 + len(body)
    if rl % 2:
        body += b"\0"
        rl += 1
    assert rl < 256, "record too long"
    return bytes([rl]) + body


def susp(sig, data, ver=1):
    return sig + bytes([4 + len(data), ver]) + data


def rr_nm(name, cont=False):
    return susp(b"NM", bytes([1 if cont else 0]) + name)


def rr_px(mode, links=1):
    return susp(b"PX", both32(mode) + both32(links) + both32(0) + both32(0))


def rr_tf_mtime(date7):
    return susp(b"TF", bytes([0x02]) + date7)


def rr_sl(components, cont=False):
    """components: list of (flags, bytes)"""
    body = b"".join(bytes([f, len(c)]) + c for f, c in components)
    return susp(b"SL", bytes([1 if cont else 0]) + body)


def rr_ce(lba, off, length):
    return susp(b"CE", both32(lba) + both32(off) + both32(length))


SP = susp(b"SP", b"\xbe\xef\x00")
ER = susp(b"ER", bytes([10, 0, 0, 1]) + b"RRIP_1991A")


class Node:
    def __init__(self, name, is_dir, parent=None):
        self.name, self.is_dir, self.parent = name, is_dir, parent
        self.children = []
        self.data = b""
        self.flags = 0
        self.su = b""                # Rock Ridge system use (without CE)
        self.records = None          # explicit records for files (multi-extent etc.)
        self.lba = 0
        self.size = 0
        self.override = {}


class Iso:
    def __init__(self, rr=False, joliet=False, block=SEC):
        self.rr, self.joliet = rr, joliet
        self.root = Node(b"\0", True)
        self.blobs = []              # (lba, bytes) placed raw
        self.next_lba = 0
        self.boot = None
        self.ce_areas = []           # (node, bytes) continuation areas to place

    def dir(self, parent, name, **kw):
        n = Node(name.encode() if isinstance(name, str) else name, True, parent)
        n.__dict__.update(kw)
        parent.children.append(n)
        return n

    def file(self, parent, name, data=b"", **kw):
        n = Node(name.encode() if isinstance(name, str) else name, False, parent)
        n.data = data
        n.__dict__.update(kw)
        parent.children.append(n)
        return n

    def alloc(self, nbytes):
        lba = self.next_lba
        self.next_lba += max(1, (nbytes + SEC - 1) // SEC)
        return lba

    def place(self, data):
        lba = self.alloc(len(data))
        self.blobs.append((lba, data))
        return lba

    # ---- layout ----
    def build(self, after_layout=None):
        self.next_lba = 16 + 3          # PVD, (boot), terminator ... reserve a few
        if self.boot:
            self.next_lba += 1
        dirs = []

        def walk(n):
            if n.is_dir:
                dirs.append(n)
                for c in n.children:
                    walk(c)
        walk(self.root)
        # directory extents: sized after building records twice
        for d in dirs:
            d.size = SEC * getattr(d, "nsec", 1)
            d.lba = self.alloc(d.size)
        # file data
        for d in dirs:
            for c in d.children:
                if c.is_dir:
                    continue
                if c.records is None:
                    if getattr(c, "interleave", None):
                        fus, gap = c.interleave
                        unit = fus * SEC
                        chunks = [c.data[i:i + unit] for i in range(0, len(c.data), unit)] or [b""]
                        start = self.next_lba
                        blob = b""
                        for k, ch in enumerate(chunks):
                            blob += ch.ljust(unit, b"\0")
                            if k + 1 < len(chunks):
                                blob += b"\xEE" * (gap * SEC)    # interleave gap: garbage
                        lba = self.place(blob)
                        assert lba == start
                        c.recs = [(lba, len(c.data), fus, gap)]
                    elif getattr(c, "extents", None):
                        # list of (start, end) byte ranges, each placed separately (reverse order)
                        placed = []
                        for (a, b) in reversed(c.extents):
                            placed.append((a, b, self.place(c.data[a:b] or b"\0")))
                        placed.sort()
                        c.recs = [(lba, b - a, 0, 0) for (a, b, lba) in placed]
                    else:
                        ear = getattr(c, "ear", 0)
                        blob = b"\xAA" * (ear * SEC) + c.data
                        lba = self.place(blob) if blob else 0
                        c.recs = [(lba, len(c.data), 0, 0)]
                        c.ear_len = ear
                else:
                    c.recs = [(lba, size, 0, 0) for (lba, size) in c.records]   # raw (lba, size) extents
        if self.boot:
            self.boot_img_lba = self.place(self.boot[1])
            self.boot_cat_lba = self.place(b"\0" * SEC)
        if after_layout:
            after_layout(self)
        # directory contents
        for d in dirs:
            recs = []
            parent = d.parent or d
            su0 = b""
            if d is self.root and self.rr:
                su0 = SP + rr_px(0o40755) + ER
            recs.append(dir_record(b"\0", d.lba, d.size, 2, su=su0 + getattr(d, "dot_su", b"")))
            recs.append(dir_record(b"\1", parent.lba, parent.size, 2))
            for c in d.children:
                su = c.su
                if self.rr and not getattr(c, "no_rr", False):
                    su = rr_px(0o40755 if c.is_dir else (0o120777 if getattr(c, "link", None) else 0o100644)) + \
                        (rr_nm(getattr(c, "rr_name", c.name)) if not getattr(c, "no_nm", False) else b"") + su
                    if getattr(c, "link", None):
                        su += rr_sl([(0, p) for p in c.link.split(b"/")])
                ov = c.override
                if c.is_dir:
                    recs.append(dir_record(ov.get("name", c.name), ov.get("lba", c.lba), ov.get("size", c.size),
                                           ov.get("flags", 2 | c.flags), su=ov.get("su", su), date=ov.get("date")))
                else:
                    rs = c.recs
                    for k, (lba, size, fus, gap) in enumerate(rs):
                        fl = c.flags | (0x80 if k + 1 < len(rs) else 0)
                        recs.append(dir_record(ov.get("name", c.name), ov.get("lba", lba), ov.get("size", size),
                                               ov.get("flags", fl), su=ov.get("su", su if k == 0 else b""),
                                               date=ov.get("date"), ear=getattr(c, "ear_len", 0), fus=fus, gap=gap))
            out = b""
            cur = b""
            for r in recs:
                if len(cur) + len(r) > SEC:
                    out += cur.ljust(SEC, b"\0")
                    cur = b""
                cur += r
            out += cur
            out = out.ljust(d.size, b"\0")
            assert len(out) == d.size, "directory %r needs more sectors" % d.name
            self.blobs.append((d.lba, out))
        total = self.next_lba + 2
        img = bytearray(total * SEC)
        for lba, data in self.blobs:
            img[lba * SEC:lba * SEC + len(data)] = data
        # volume descriptors
        root = self.root
        rootrec = dir_record(b"\0", root.lba, root.size, 2)[:34]
        pvd = bytearray(SEC)
        pvd[0:7] = b"\x01CD001\x01"
        pvd[40:72] = b"ISOGEN".ljust(32)
        pvd[80:88] = both32(total)
        pvd[120:124] = both16(1)
        pvd[124:128] = both16(1)
        pvd[128:132] = both16(SEC)
        pvd[156:190] = rootrec
        pvd[881] = 1
        vds = [bytes(pvd)]
        if self.boot:
            br = bytearray(SEC)
            br[0:7] = b"\x00CD001\x01"
            br[7:7 + 23] = b"EL TORITO SPECIFICATION"
            br[0x47:0x4b] = struct.pack("<I", self.boot_cat_lba)
            vds.append(bytes(br))
            media, data, count = self.boot[0], self.boot[1], self.boot[2]
            cat = bytearray(SEC)
            v = bytearray(32)
            v[0] = 1
            v[4:28] = b"ISOGEN".ljust(24, b"\0")
            v[30], v[31] = 0x55, 0xAA
            s = sum(struct.unpack("<16H", bytes(v))) & 0xffff
            v[28:30] = struct.pack("<H", (0x10000 - s) & 0xffff)
            cat[0:32] = v
            cat[32:64] = bytes([0x88, media, 0, 0, 0, 0]) + struct.pack("<H", count) + \
                struct.pack("<I", self.boot_img_lba) + b"\0" * 20
            img[self.boot_cat_lba * SEC:(self.boot_cat_lba + 1) * SEC] = cat
        term = bytearray(SEC)
        term[0:7] = b"\xffCD001\x01"
        vds.append(bytes(term))
        for i, v in enumerate(vds):
            img[(16 + i) * SEC:(17 + i) * SEC] = v
        return bytes(img)
