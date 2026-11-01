"""ISO 9660 / UDF readers: genisoimage / xorriso / mkudffs / pycdlib images, generated edge
cases (tests/data/iso/isogen.py, udfgen.py), 7-Zip comparison, metadata (modes, times,
hidden, links, views) through tests/drivers/fmt_iso_ls.c, hostile inputs.

GZ_TEST_SLOW=1 adds a real > 4 GiB multi-extent file (needs ~5 GB of disk)."""
import os, random, shutil, struct, subprocess, sys, importlib.util, calendar, time

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(os.path.dirname(HERE), "data", "iso")


def load(name):
    spec = importlib.util.spec_from_file_location("gz_iso_" + name, os.path.join(DATA, name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def blob(n, seed=1, text=False):
    rnd = random.Random(seed * 7919 + n)
    if text:
        words = ["고기", "삼겹살", "목살", "iso", "udf", "joliet", "rock", "ridge", "\n"]
        out = bytearray()
        while len(out) < n:
            out += rnd.choice(words).encode() + b" "
        return bytes(out[:n])
    return bytes(rnd.getrandbits(8) for _ in range(n))


MTIME = calendar.timegm((2021, 3, 4, 5, 6, 7))

FILES = {
    "readme.txt": blob(5000, 1, True),
    "문서/보고서.txt": blob(120000, 2, True),
    "문서/사진/고기.jpg": blob(70000, 3),
    "empty.txt": b"",
    "big.bin": bytes(range(256)) * (12 << 10) + b"tail",
    "a/b/c/d/e/f/g/h/i/j/deep.txt": b"deep file\n",
    "dir with space/file;semi.txt": b"semicolon",
    "Long_name_" + "x" * 80 + ".txt": b"long name",
    "UPPER.TXT": b"upper",
    "noext": b"no extension",
}


class Drv:
    def __init__(self, t):
        self.t = t
        self.exe = t.build_driver("tests/drivers/fmt_iso_ls.c")

    def run(self, *args):
        r = subprocess.run([self.exe] + list(args), capture_output=True, timeout=300)
        return r.returncode, r.stdout.decode("utf-8", "replace")

    def ls(self, img):
        rc, out = self.run("ls", img)
        typ, rows = None, {}
        for line in out.splitlines():
            p = line.split("\t")
            if p[0] == "TYPE":
                typ = p[1]
            elif len(p) >= 10 and p[0].isdigit():
                rows[p[8]] = dict(idx=int(p[0]), is_dir=int(p[1]), size=int(p[2]), attr=int(p[3], 16),
                                  mode=int(p[4], 8), aux=int(p[5]), link=int(p[6]), mtime=float(p[7]), target=p[9])
        return typ, rows

    def crc(self, img):
        rc, out = self.run("crc", img)
        rows = {}
        for line in out.splitlines():
            p = line.split("\t")
            if len(p) == 5 and p[0].isdigit():
                rows[p[4]] = (int(p[1]), int(p[2]), int(p[3], 16))
        return rows

    def viewcheck(self, img, label):
        rc, out = self.run("viewcheck", img)
        ok = rc == 0 and "BAD 0" in out
        return self.t.record(ok, "viewcheck " + label, out.strip().splitlines()[-1] if out.strip() else "rc=%d" % rc)


def tree_with_links(t, root, files, links=True):
    t.write_tree(root, files)
    for k in files:
        os.utime(os.path.join(root, k), (MTIME, MTIME))
    if links:
        os.symlink("../readme.txt", os.path.join(root, "문서", "link_up"))
        os.symlink("/usr/share/doc", os.path.join(root, "abs_link"))


def mkiso(t, out, src, *opts, tool="genisoimage", env=None, charset="utf-8"):
    if os.path.exists(out):
        os.remove(out)
    if tool == "xorriso":
        args = ["xorriso", "-as", "mkisofs", "-quiet"] + list(opts) + ["-o", out, src]
    else:
        args = ["genisoimage", "-quiet", "-input-charset", charset] + list(opts) + ["-o", out, src]
    t.sh(args, env=env)
    return out


# ---------------------------------------------------------------------------

def iso_tools(t, d):
    W = t.work
    src = os.path.join(W, "src")
    tree_with_links(t, src, FILES)
    exp = dict(FILES)
    exp["문서/link_up"] = b""
    exp["abs_link"] = b""

    # Rock Ridge + Joliet: Rock Ridge names win (long names, ';', deep tree relocated back)
    p = mkiso(t, t.path("rr_joliet.iso"), src, "-R", "-J", "-joliet-long")
    t.check_extract(p, exp, expect_type="ISO")
    typ, rows = d.ls(p)
    r = rows.get("문서/link_up", {})
    t.record(r.get("link") == 1 and r.get("target") == "../readme.txt" and r.get("mode") == 0o120777,
             "rr symlink", str(r))
    r = rows.get("abs_link", {})
    t.record(r.get("target") == "/usr/share/doc", "rr absolute symlink", str(r))
    t.record("rr_moved" not in rows and "a/b/c/d/e/f/g/h/i/j/deep.txt" in rows, "rr relocated dirs", "")
    r = rows.get("readme.txt", {})
    t.record(r.get("mode") == 0o100644 and abs(r.get("mtime", 0) - MTIME) < 1, "rr mode + TF time", str(r))
    d.viewcheck(p, "rr_joliet.iso")

    # rationalized Rock Ridge (-r) and xorriso
    p = mkiso(t, t.path("rr_r.iso"), src, "-r", "-J", "-joliet-long")
    t.check_extract(p, exp)
    p = mkiso(t, t.path("xorriso.iso"), src, "-R", "-J", "-joliet-long", tool="xorriso")
    t.check_extract(p, exp, label="xorriso.iso")
    typ, rows = d.ls(p)
    t.record(rows.get("문서/link_up", {}).get("target") == "../readme.txt", "xorriso symlink", "")

    # Joliet only (no Rock Ridge): symlinks are dropped, names from the UCS-2 tree
    src_nl = os.path.join(W, "src_nolinks")
    tree_with_links(t, src_nl, FILES, links=False)
    p = mkiso(t, t.path("joliet.iso"), src_nl, "-J", "-joliet-long", "-D")
    t.check_extract(p, {k.replace(";", "_"): v for k, v in FILES.items()})    # ';' is not allowed in Joliet
    t.check_vs_7z(p)
    typ, rows = d.ls(p)
    # Joliet keeps the recording date (local time + GMT offset): compare in UTC
    r = rows.get("readme.txt", {})
    t.record(abs(r.get("mtime", 0) - MTIME) < 1, "joliet record date", str(r))
    p = mkiso(t, t.path("joliet_tz.iso"), src_nl, "-J", "-joliet-long", "-D", env=dict(os.environ, TZ="Asia/Seoul"))
    typ, rows = d.ls(p)
    r = rows.get("readme.txt", {})
    t.record(abs(r.get("mtime", 0) - MTIME) < 1, "record date GMT offset +9", str(r))

    # Joliet 64-character limit: compare with 7-Zip (same truncation)
    p = mkiso(t, t.path("joliet64.iso"), src_nl, "-J", "-D")
    t.check_vs_7z(p)

    # plain ISO 9660 (level 1, 8.3 upper case, ';1' stripped), level 2 / 3 / 4
    p = mkiso(t, t.path("plain.iso"), src_nl, "-D")
    t.check_vs_7z(p)
    _, rows = d.ls(p)
    t.record("README.TXT" in rows and "NOEXT" in rows, "primary names", " ".join(sorted(rows)[:6]))
    asc = {k: v for k, v in FILES.items() if k.isascii()}
    t.write_tree(os.path.join(W, "src_ascii"), asc)
    for lvl in ("2", "3", "4"):
        p = mkiso(t, t.path("level%s.iso" % lvl), os.path.join(W, "src_ascii"), "-D", "-iso-level", lvl,
                  charset="iso8859-1")
        t.check_vs_7z(p, label="level%s.iso vs 7z" % lvl)
    p = mkiso(t, t.path("level4.iso"), os.path.join(W, "src_ascii"), "-D", "-iso-level", "4", charset="iso8859-1")
    t.check_extract(p, asc, label="level4.iso (ISO 9660:1999 tree)")
    p = mkiso(t, t.path("level4_rr.iso"), src, "-R", "-iso-level", "4", charset="iso8859-1")
    t.check_extract(p, exp)

    # Korean names in the Joliet tree, compare with 7-Zip
    kr = {"한글/가나다.txt": b"ga na da", "한글/띄어 쓰기.txt": b"spacing", "깍두기.bin": blob(3000, 9)}
    t.write_tree(os.path.join(W, "src_kr"), kr)
    p = mkiso(t, t.path("korean.iso"), os.path.join(W, "src_kr"), "-J")
    t.check_extract(p, kr)
    t.check_vs_7z(p)

    # hidden files: -hide drops from ISO/RR, -hide-joliet from Joliet, -hidden sets the existence bit
    hs = {"visible.txt": b"v", "secret.txt": b"s", "hid.txt": b"h", "jhide.txt": b"j"}
    t.write_tree(os.path.join(W, "src_hide"), hs)
    p = mkiso(t, t.path("hide_rr.iso"), os.path.join(W, "src_hide"), "-R", "-J", "-hide", "secret.txt",
              "-hidden", "hid.txt", "-hide-joliet", "jhide.txt")
    typ, rows = d.ls(p)
    t.record("secret.txt" not in rows and "jhide.txt" in rows and rows.get("hid.txt", {}).get("attr", 0) & 2 and
             not rows.get("visible.txt", {}).get("attr", 1) & 2, "hide/hidden (rr)", str(sorted(rows)))
    p = mkiso(t, t.path("hide_j.iso"), os.path.join(W, "src_hide"), "-J", "-hide-joliet", "jhide.txt", "-hidden", "hid.txt")
    typ, rows = d.ls(p)
    t.record("jhide.txt" not in rows and rows.get("hid.txt", {}).get("attr", 0) & 2, "hide/hidden (joliet)",
             str(sorted(rows)))

    # El Torito
    bsrc = os.path.join(W, "src_boot")
    t.write_tree(bsrc, {"boot/boot.img": blob(6000, 11), "boot/floppy.img": blob(1474560, 12),
                        "boot/efi.img": blob(40960, 13), "boot/hd.img": b"\0" * 510 + b"\x55\xaa" + blob(4096, 14),
                        "x.txt": b"x"})
    p = mkiso(t, t.path("boot_noemul.iso"), bsrc, "-J", "-R", "-b", "boot/boot.img", "-c", "boot/boot.cat",
              "-no-emul-boot", "-boot-load-size", "4")
    t.check_vs_7z(p, allow_extra=True)
    _, rows = d.ls(p)
    t.record(rows.get("[BOOT]/Boot-NoEmul.img", {}).get("size") == 2048, "boot no-emul size", "")
    p = mkiso(t, t.path("boot_floppy.iso"), bsrc, "-J", "-b", "boot/floppy.img", "-c", "boot/boot.cat")
    t.check_vs_7z(p)
    _, rows = d.ls(p)
    t.record(rows.get("[BOOT]/Boot-1.44M.img", {}).get("size") == 1474560, "boot floppy", "")
    p = mkiso(t, t.path("boot_multi.iso"), bsrc, "-J", "-R", "-b", "boot/boot.img", "-c", "boot/boot.cat",
              "-no-emul-boot", "-boot-load-size", "4", "-eltorito-alt-boot", "-e", "boot/efi.img", "-no-emul-boot",
              tool="xorriso")
    t.check_vs_7z(p, allow_extra=True)
    _, rows = d.ls(p)
    t.record("[BOOT]/1-Boot-NoEmul.img" in rows and "[BOOT]/2-Boot-NoEmul.img" in rows, "boot multi",
             " ".join(k for k in rows if k.startswith("[BOOT]")))

    # UDF bridge from genisoimage (UDF 1.02 + ISO 9660): UDF is preferred
    p = mkiso(t, t.path("bridge.iso"), src_nl, "-J", "-R", "-udf", "-joliet-long")
    t.check_extract(p, {k.replace(";", "_"): v for k, v in FILES.items()}, expect_type="UDF")
    t.check_vs_7z(p)
    d.viewcheck(p, "bridge.iso")
    _, rows = d.ls(p)
    r = rows.get("readme.txt", {})
    t.record(abs(r.get("mtime", 0) - MTIME) < 1 and r.get("mode", 0) & 0o777, "udf bridge time / mode", str(r))
    # broken UDF side of a bridge disc: the ISO 9660 tree is used instead
    raw = bytearray(open(p, "rb").read())
    tags = {}
    for sec in range(len(raw) // 2048):
        b = raw[sec * 2048:sec * 2048 + 16]
        if b[1] == 0 and (sum(b[0:4]) + sum(b[5:16])) & 0xff == b[4] and struct.unpack_from("<I", b, 12)[0] in (sec, ):
            tags.setdefault(struct.unpack_from("<H", b, 0)[0], []).append(sec)
    nofsd = bytearray(raw)
    for sec in range(len(raw) // 2048):                    # file set descriptors (partition relative)
        b = raw[sec * 2048:sec * 2048 + 16]
        if struct.unpack_from("<H", b, 0)[0] == 256 and (sum(b[0:4]) + sum(b[5:16])) & 0xff == b[4]:
            nofsd[sec * 2048:sec * 2048 + 512] = b"\0" * 512
    noanchor = bytearray(raw)
    for sec in tags.get(2, []):
        noanchor[sec * 2048:sec * 2048 + 512] = b"\0" * 512
    exp_iso = FILES                                        # Rock Ridge names on the ISO side
    for tag, img in (("no_fsd", nofsd), ("no_anchor", noanchor)):
        q = t.path("bridge_%s.iso" % tag)
        open(q, "wb").write(bytes(img))
        t.check_extract(q, exp_iso, expect_type="ISO", label="bridge %s -> ISO 9660" % tag)

    return {"rr": t.path("rr_joliet.iso"), "joliet": t.path("joliet.iso"), "plain": t.path("plain.iso"),
            "bridge": t.path("bridge.iso"), "boot": t.path("boot_multi.iso"), "xorriso": t.path("xorriso.iso")}


# ---------------------------------------------------------------------------

def iso_generated(t, d):
    G = load("isogen")
    out = {}

    def save(name, img):
        p = t.path(name)
        open(p, "wb").write(img)
        out[name] = p
        return p

    data = blob(9000, 21)
    # multi-extent file (extents stored in reverse order), associated and hidden files
    iso = G.Iso()
    iso.file(iso.root, b"MULTI.BIN;1", data, extents=[(0, 2048), (2048, 6144), (6144, 9000)])
    iso.file(iso.root, b"CONTIG.BIN;1", data, extents=[(0, 4096), (4096, 9000)])
    iso.file(iso.root, b"ASSOC.TXT;1", b"resource fork", flags=4)
    iso.file(iso.root, b"ASSOC.TXT;1", b"main data")
    iso.file(iso.root, b"HIDDEN.TXT;1", b"hidden", flags=1)
    iso.file(iso.root, b"NOEXT.;1", b"no extension")
    iso.file(iso.root, b"EMPTY.TXT;1", b"")
    sub = iso.dir(iso.root, b"SUB")
    iso.file(sub, b"IN.TXT;1", b"in sub")
    p = save("gen_basic.iso", iso.build())
    t.check_extract(p, {"MULTI.BIN": data, "CONTIG.BIN": data, "ASSOC.TXT": b"main data", "HIDDEN.TXT": b"hidden",
                        "NOEXT": b"no extension", "EMPTY.TXT": b"", "SUB/IN.TXT": b"in sub", "SUB": None}, allow_extra=True)
    _, rows = d.ls(p)
    t.record(rows.get("HIDDEN.TXT", {}).get("attr", 0) & 2, "hidden flag", str(rows.get("HIDDEN.TXT")))
    rc, txt = d.run("ls", p)
    aux = sorted(line.split("\t")[5] for line in txt.splitlines() if "\tASSOC.TXT\t" in line)
    t.record(aux == ["0", "1"], "associated entry is aux", str(aux))
    t.record(rows.get("MULTI.BIN", {}).get("size") == 9000, "multi-extent size", "")
    d.viewcheck(p, "gen_basic.iso")
    t.check_vs_7z(p, allow_extra=True)

    # what 7-Zip does not read: interleaved files, extended attribute records, version > 1
    iso = G.Iso()
    iso.file(iso.root, b"INTER.BIN;1", data, interleave=(1, 2))
    iso.file(iso.root, b"INTER3.BIN;1", data, interleave=(3, 1))
    iso.file(iso.root, b"EAR.TXT;1", b"after the extended attribute record", ear=1)
    iso.file(iso.root, b"VER.TXT;12", b"version 12")
    p = save("gen_ext.iso", iso.build())
    t.check_extract(p, {"INTER.BIN": data, "INTER3.BIN": data, "EAR.TXT": b"after the extended attribute record",
                        "VER.TXT": b"version 12"})
    d.viewcheck(p, "gen_ext.iso")

    # Rock Ridge: names, continuation areas (also a CE that points to itself), symlink components
    iso = G.Iso(rr=True)
    long_name = ("rock ridge 이름 " * 20).encode()

    def ce_layout(img):
        # NM continued in a continuation area, plus a looping CE inside that area
        area_lba = img.next_lba
        part2 = G.rr_nm(long_name[100:300], cont=True) + G.rr_nm(long_name[300:], cont=False)
        area = part2 + G.rr_ce(area_lba, 0, len(part2) + 28)     # points to itself: must stop
        img.place(area)
        f = img.ce_node
        f.no_nm = True
        f.su = G.rr_nm(long_name[:100], cont=True) + G.rr_ce(area_lba, 0, len(area))
    f = iso.file(iso.root, b"LONG.TXT;1", b"long name data")
    iso.ce_node = f
    iso.file(iso.root, b"LINK.;1", b"", link=b"../target/file", rr_name=b"LINK")
    iso.file(iso.root, b"NORR.TXT;1", b"plain", no_rr=True)
    iso.file(iso.root, b"NAMED.TXT;1", b"named", rr_name="이름 있는 파일.txt".encode())
    p = save("gen_rr.iso", iso.build(after_layout=ce_layout))
    t.check_extract(p, {long_name.decode(): b"long name data", "LINK": b"", "NORR.TXT": b"plain",
                        "이름 있는 파일.txt": b"named"}, allow_extra=True)
    _, rows = d.ls(p)
    t.record(rows.get("LINK", {}).get("target") == "../target/file", "rr SL components", str(rows.get("LINK")))

    # El Torito media types written directly
    for media, name, size in ((2, "Boot-1.44M.img", 1474560), (4, "Boot-HardDisk.img", 512 * 4), (0, "Boot-NoEmul.img", 2048)):
        iso = G.Iso()
        iso.file(iso.root, b"A.TXT;1", b"a")
        iso.boot = (media, blob(size + 4096, 30 + media), 4)
        p = save("gen_boot%d.iso" % media, iso.build())
        _, rows = d.ls(p)
        got = rows.get("[BOOT]/" + name, {}).get("size")
        want = min(size, os.path.getsize(p) - 0) if media != 4 else size
        t.record(got is not None and got <= want, "el torito media %d" % media, "size %s" % got)
        t.check_vs_7z(p, label="gen_boot%d.iso vs 7z" % media)

    # multi-extent file > 4 GiB in a sparse image: second extent first on disk, markers at the
    # extent boundaries (only a few blocks are really written)
    first = 0xFFFFF800
    second = (1 << 20) + 123
    lba2 = 64
    lba1 = lba2 + (second + 2047) // 2048 + 8
    iso = G.Iso()
    iso.file(iso.root, b"BIG.BIN;1", records=[(lba1, first), (lba2, second)])
    iso.file(iso.root, b"SMALL.TXT;1", b"small")
    head = iso.build()
    assert len(head) <= lba2 * 2048
    marks = {lba1 * 2048: b"HEAD" * 512, lba1 * 2048 + first - 2048: b"END1" * 512,
             lba2 * 2048: b"MID!" * 512, lba2 * 2048 + second - 123: b"T" * 123}
    p = t.path("gen_sparse4g.iso")
    with open(p, "wb") as f:
        f.write(head)
        for o, m in marks.items():
            f.seek(o)
            f.write(m)
        f.truncate(lba1 * 2048 + first + 4096)
    import zlib
    crc, pos = 0, 0
    zb = b"\0" * (1 << 22)
    for o, m in sorted(((o - lba1 * 2048, m) for o, m in marks.items() if o >= lba1 * 2048)) + \
            sorted(((o - lba2 * 2048 + first, m) for o, m in marks.items() if o < lba1 * 2048)):
        while pos < o:
            k = min(o - pos, len(zb))
            crc = zlib.crc32(zb[:k], crc)
            pos += k
        crc = zlib.crc32(m, crc)
        pos += len(m)
    rows = d.crc(p)
    t.record(rows.get("BIG.BIN") == (0, first + second, crc), "multi-extent > 4 GiB (sparse image)",
             "%s want %d %08x" % (rows.get("BIG.BIN"), first + second, crc))
    _, lrows = d.ls(p)
    rc, txt = d.run("view", p, str(lrows.get("BIG.BIN", {}).get("idx", 0)), str(first - 4), "8")
    t.record(txt.splitlines()[-1:] == [(b"END1" + b"MID!").hex()], "multi-extent view across extents", txt[-60:])
    os.remove(p)

    # 300 nested directories: listing stops at the depth limit
    iso = G.Iso()
    n = iso.root
    for k in range(300):
        n = iso.dir(n, b"D%d" % k)
    iso.file(n, b"BOTTOM.TXT;1", b"too deep")
    p = save("gen_deep.iso", iso.build())
    check_hostile(t, d, p, "300 nested directories")
    _, rows = d.ls(p)
    t.record(250 <= len(rows) <= 260, "depth limit", "%d entries" % len(rows))

    # hostile structures
    iso = G.Iso()
    sub = iso.dir(iso.root, b"LOOP")
    iso.file(sub, b"F.TXT;1", b"f")
    iso.dir(sub, b"BACK", override={"lba": 0})          # patched after layout: points to the root
    huge = iso.file(iso.root, b"HUGE.BIN;1", b"x", override={"size": 0xffffffff})
    far = iso.file(iso.root, b"FAR.BIN;1", b"x", override={"lba": 0x7fffffff})

    def loop_layout(img):
        sub.children[1].override["lba"] = img.root.lba
        sub.children[1].override["size"] = img.root.size
    p = save("hostile_loop.iso", iso.build(after_layout=loop_layout))
    check_hostile(t, d, p, "hostile directory loop")
    _, rows = d.ls(p)
    t.record("LOOP/F.TXT" in rows and "LOOP/BACK" in rows and len(rows) < 20, "directory loop listed once", str(len(rows)))
    return out


# ---------------------------------------------------------------------------

def udf_generated(t, d):
    U = load("udfgen")
    out = {}
    payload = {"big.bin": blob(300000, 41), "sub/a.txt": blob(20000, 42, True), "한글/파일.txt": "안녕하세요".encode() * 100,
               "sub/deep/z.bin": blob(5000, 43), "small.txt": b"tiny embedded", "split.bin": blob(70000, 44),
               "empty.txt": b"", "Ünïcödé.txt": b"latin-1 name", "名前.txt": b"16-bit name"}

    def build(name, check_7z=False, fad="short", **kw):
        u = U.Udf(**kw)
        sub = u.dir(u.root, "sub")
        u.file(u.root, "big.bin", payload["big.bin"])
        u.file(sub, "a.txt", payload["sub/a.txt"], ad=fad)
        kr = u.dir(u.root, "한글")
        u.file(kr, "파일.txt", payload["한글/파일.txt"], ad="long")
        deep = u.dir(sub, "deep", ad="inicb")
        u.file(deep, "z.bin", payload["sub/deep/z.bin"])
        u.file(u.root, "small.txt", payload["small.txt"], ad="inicb")
        u.file(u.root, "split.bin", payload["split.bin"], split=9000, aed=2)
        u.file(u.root, "empty.txt", b"")
        u.file(u.root, "Ünïcödé.txt", payload["Ünïcödé.txt"])
        u.file(u.root, "名前.txt", payload["名前.txt"], name16=True, iu=b"IMPL" * 8)
        u.file(u.root, "hidden.txt", b"hidden", hidden=True)
        u.file(u.root, "deleted.txt", b"gone", deleted=True)
        u.symlink(u.root, "link", ["..", "sub", "a.txt"])
        u.symlink(u.root, "abslink", ["/", "etc", "hosts"])
        u.file(u.root, "s4096.txt", b"newest version", strategy4096=True)
        p = t.path(name)
        open(p, "wb").write(u.build())
        out[name] = p
        exp = dict(payload)
        exp.update({"hidden.txt": b"hidden", "link": b"", "abslink": b"", "s4096.txt": b"newest version"})
        t.check_extract(p, exp, expect_type="UDF", label=name)
        _, rows = d.ls(p)
        ok = rows.get("hidden.txt", {}).get("attr", 0) & 2 and "deleted.txt" not in rows and \
            rows.get("link", {}).get("target") == "../sub/a.txt" and rows.get("abslink", {}).get("target") == "/etc/hosts" and \
            rows.get("big.bin", {}).get("mode") == 0o100644 and rows.get("sub", {}).get("mode") == 0o40755 and \
            abs(rows.get("big.bin", {}).get("mtime", 0) - (calendar.timegm((2026, 11, 1, 12, 30, 15)) - 9 * 3600 + 0.123456)) < 0.001
        t.record(ok, name + " metadata", str({k: rows.get(k) for k in ("hidden.txt", "link", "big.bin")})[:300])
        d.viewcheck(p, name)
        if check_7z:
            # 7-Zip refuses volumes with symlinks, allocation extent chains or indirect entries:
            # compare a volume without them
            u = U.Udf(**kw)
            sub = u.dir(u.root, "sub")
            u.file(u.root, "big.bin", payload["big.bin"])
            u.file(sub, "a.txt", payload["sub/a.txt"], ad=fad)
            kr = u.dir(u.root, "한글")
            u.file(kr, "파일.txt", payload["한글/파일.txt"], ad="long")
            u.file(u.dir(sub, "deep", ad="inicb"), "z.bin", payload["sub/deep/z.bin"])
            u.file(u.root, "small.txt", payload["small.txt"], ad="inicb")
            u.file(u.root, "split.bin", payload["split.bin"], split=9000)
            u.file(u.root, "empty.txt", b"")
            u.file(u.root, "Ünïcödé.txt", payload["Ünïcödé.txt"])
            u.file(u.root, "名前.txt", payload["名前.txt"], name16=True, iu=b"IMPL" * 8)
            u.file(u.root, "hidden.txt", b"hidden", hidden=True)
            u.file(u.root, "deleted.txt", b"gone", deleted=True)
            p7 = t.path("7z_" + name)
            open(p7, "wb").write(u.build())
            t.check_vs_7z(p7, label=name + " vs 7z")
        return p

    build("udf_102_fe.udf", layout="type1", rev=0x102, check_7z=True)
    build("udf_201_efe.udf", layout="type1", rev=0x201, check_7z=True)
    build("udf_201_long.udf", layout="type1", rev=0x201, fad="long")
    build("udf_201_ext.udf", layout="type1", rev=0x201, fad="ext")
    build("udf_260.udf", layout="type1", rev=0x260, check_7z=True)
    build("udf_512.udf", layout="type1", rev=0x201, bs=512)
    build("udf_4096.udf", layout="type1", rev=0x250, bs=4096)
    build("udf_250_meta.udf", layout="meta", rev=0x250, check_7z=True)
    build("udf_260_meta.udf", layout="meta", rev=0x260, check_7z=True)
    build("udf_260_meta_split.udf", layout="meta", rev=0x260, meta_split=True)
    build("udf_250_mirror.udf", layout="meta", rev=0x250, break_main_meta=True)
    build("udf_150_vat.udf", layout="vat", rev=0x150, vat15=True, efe=False)
    build("udf_201_vat.udf", layout="vat", rev=0x201)
    build("udf_150_spar.udf", layout="sparable", rev=0x150, remap=True, efe=False)
    build("udf_201_spar.udf", layout="sparable", rev=0x201, remap=True)
    build("udf_reserve_vds.udf", layout="type1", rev=0x201, break_main_vds=True)
    build("udf_end_anchor.udf", layout="type1", rev=0x201, anchors="end")

    # crafted hostile structures: directory loops, hard-linked directories and files, references
    # outside every partition, allocation extent and indirect entry loops
    for layout, rev in (("type1", 0x201), ("vat", 0x201), ("meta", 0x250), ("sparable", 0x150)):
        u = U.Udf(layout=layout, rev=rev, remap=True)
        sub = u.dir(u.root, "sub")
        f = u.file(sub, "ok.txt", b"fine")
        u.ref(sub, "loop", target=u.root)
        u.ref(u.root, "again", target=sub)
        u.ref(u.root, "hard.txt", target=f, is_dir=False)
        for k, part in enumerate((0, 1, 2, 7)):
            u.ref(u.root, "bad%d" % k, loc=0xfffffff0 - k, part=part, is_dir=bool(k & 1))
        u.file(u.root, "aedloop.bin", blob(30000, 71), split=4000, aed=1, aed_loop=True, info=10 ** 9)
        u.file(u.root, "ieloop.txt", b"newer", strategy4096=True, ie_loop=True)
        p = t.path("hostile_%s.udf" % layout)
        open(p, "wb").write(u.build())
        out["hostile_" + layout] = p
        check_hostile(t, d, p, "hostile udf structures " + layout)
        rows = d.crc(p)
        import zlib
        ok = rows.get("sub/ok.txt", (1,))[0] == 0 and rows.get("hard.txt") == rows.get("sub/ok.txt") and \
            "sub/loop" in rows and "again" in rows and "again/ok.txt" not in rows and \
            rows.get("ieloop.txt", (1,))[0] == 0 and rows.get("aedloop.bin", (0,))[0] != 0 and \
            all(k in rows for k in ("bad0", "bad1", "bad2", "bad3"))
        t.record(ok, "hostile udf listing " + layout, str(sorted(rows.items()))[:400])

    # sparse / unrecorded extents and a file > 4 GiB (only 1 MiB recorded)
    u = U.Udf(layout="type1", rev=0x201)
    head, tail = blob(4096, 51), blob(5000, 52)
    zero = (1 << 30) - 2048
    segs = [("data", head)] + [("zero", zero, 1 + (k & 1)) for k in range(5)] + [("data", tail)]
    u.file(u.root, "huge.bin", segs=segs)
    u.file(u.root, "holes.bin", segs=[("zero", 4096, 2), ("data", b"middle"), ("zero", 10000, 1)])
    p = t.path("udf_sparse.udf")
    open(p, "wb").write(u.build())
    total = len(head) + 5 * zero + len(tail)
    import zlib
    crc = zlib.crc32(head)
    zb = b"\0" * (1 << 20)
    left = 5 * zero
    while left:
        k = min(left, len(zb))
        crc = zlib.crc32(zb[:k], crc)
        left -= k
    crc = zlib.crc32(tail, crc)
    rows = d.crc(p)
    t.record(rows.get("huge.bin") == (0, total, crc), "udf > 4 GiB sparse file", "%s want %d %08x" % (rows.get("huge.bin"), total, crc))
    holes = b"\0" * 4096 + b"middle" + b"\0" * 10000
    t.record(rows.get("holes.bin") == (0, len(holes), zlib.crc32(holes)), "udf unrecorded extents", str(rows.get("holes.bin")))
    _, lrows = d.ls(p)
    rc, txt = d.run("view", p, str(lrows.get("huge.bin", {}).get("idx", 0)), str(total - 5000), "5000")
    lines = txt.splitlines()
    hx = lines[-1] if lines and lines[-2:-1] and lines[-2].startswith("SIZE") else ""
    t.record(bytes.fromhex(hx) == tail, "udf view at > 4 GiB offset", txt[:80])

    # mkudffs: empty volumes of every layout it can make
    if t.tool("mkudffs"):
        for i, args in enumerate((["-m", "hd", "-r", "2.01"], ["-m", "hd", "-b", "512", "-r", "1.02"],
                                  ["-m", "hd", "-b", "4096", "-r", "2.01"], ["-m", "cdrw", "-r", "1.50"],
                                  ["-m", "dvdrw", "-r", "2.01"], ["-m", "cdr", "-r", "1.50"], ["-m", "cdr", "-r", "2.01"],
                                  ["-m", "bdr", "-r", "2.50"], ["-m", "dvdram", "-r", "2.00"], ["-m", "hd", "--ad=short"],
                                  ["-m", "hd", "--ad=long"], ["-m", "hd", "--noefe", "-r", "2.01"])):
            p = t.path("mkudffs_%d.udf" % i)
            if os.path.exists(p):
                os.remove(p)
            r = t.sh(["mkudffs", "--new-file", "--label=GZTEST"] + args + [p, "16000"],
                     check=False)
            if r.returncode:
                t.record(False, "mkudffs " + " ".join(args), r.stderr.decode()[-200:])
                continue
            rc, txt = d.run("ls", p)
            rows = [line.split("\t") for line in txt.splitlines()[1:]]
            # empty volume; sparable media carry a hidden "Non-Allocatable Space" system file
            ok = rc == 0 and txt.startswith("TYPE\tUDF\t") and all(len(x) > 3 and int(x[3], 16) & 2 for x in rows)
            t.record(ok, "mkudffs " + " ".join(args), txt.strip()[:120])
            out["mkudffs_%d" % i] = p
    return out


def pycdlib_images(t, d):
    try:
        import pycdlib
    except ImportError:
        return t.record(True, "pycdlib not installed (skipped)", "")
    files = {"/readme.txt": blob(3000, 61, True), "/dir/data.bin": blob(50000, 62)}
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", udf="2.60")
    iso.add_directory("/DIR", rr_name="dir", joliet_path="/dir", udf_path="/dir")
    iso.add_fp(__import__("io").BytesIO(files["/readme.txt"]), len(files["/readme.txt"]), "/README.TXT;1",
               rr_name="readme.txt", joliet_path="/readme.txt", udf_path="/readme.txt")
    iso.add_fp(__import__("io").BytesIO(files["/dir/data.bin"]), len(files["/dir/data.bin"]), "/DIR/DATA.BIN;1",
               rr_name="data.bin", joliet_path="/dir/data.bin", udf_path="/dir/data.bin")
    iso.add_symlink("/LINK.;1", rr_symlink_name="link", rr_path="readme.txt", udf_symlink_path="/link", udf_target="readme.txt")
    p = t.path("pycdlib.iso")
    iso.write(p)
    iso.close()
    exp = {k[1:]: v for k, v in files.items()}
    exp["link"] = b""
    t.check_extract(p, exp, expect_type="UDF")
    _, rows = d.ls(p)
    t.record(rows.get("link", {}).get("target") == "readme.txt", "pycdlib udf symlink", str(rows.get("link")))
    return {"pycdlib": p}


# ---------------------------------------------------------------------------

def check_hostile(t, d, path, label):
    """open + list + extract every entry (streamed) under the driver: no crash, hang or leak"""
    try:
        r = subprocess.run([d.exe, "crc", path], capture_output=True, timeout=60)
    except subprocess.TimeoutExpired:
        return t.record(False, label, "timeout")
    err = r.stderr.decode(errors="replace")
    bad = r.returncode not in (0, 1) or "Sanitizer" in err or "runtime error" in err
    return t.record(not bad, label, "rc=%d %s" % (r.returncode, err[-600:] if bad else ""))


def hostile(t, d, images):
    """truncated / bit-flipped / overwritten variants of every image; GZ_ISO_FUZZ=n for more flips"""
    rnd = random.Random(int(os.environ.get("GZ_ISO_SEED", "1234")))
    nflip = int(os.environ.get("GZ_ISO_FUZZ", "24"))
    W = t.path("hostile")
    os.makedirs(W, exist_ok=True)
    for name, p in sorted(images.items()):
        raw = open(p, "rb").read()
        if len(raw) > (8 << 20):
            continue
        base = os.path.join(W, os.path.basename(p))
        cases = []
        for cut in (len(raw) // 2, 16 * 2048 + 100, 257 * 2048, len(raw) - 2048 - 1):
            if 0 < cut < len(raw):
                cases.append(("trunc%d" % cut, raw[:cut]))
        # flips concentrated on the metadata area (descriptors, directories, entries)
        hot = [o for o in range(16 * 2048, min(len(raw), 600 * 2048), 7) if raw[o]]
        for k in range(nflip):
            b = bytearray(raw)
            for _ in range(1 + k % 6):
                o = rnd.choice(hot) if hot and k % 3 else rnd.randrange(len(raw))
                b[o] ^= 1 << rnd.randrange(8)
            cases.append(("flip%d" % k, bytes(b)))
        for k in range(6):                                  # random runs of 0xff / 0x00
            b = bytearray(raw)
            o = rnd.choice(hot) if hot else 0
            b[o:o + 8] = (b"\xff" if k & 1 else b"\x00") * 8
            cases.append(("fill%d" % k, bytes(b)))
        for tag, data in cases:
            hp = base + "." + tag
            open(hp, "wb").write(data)
            if check_hostile(t, d, hp, "hostile %s %s" % (os.path.basename(p), tag)):
                os.remove(hp)


def big_multiextent(t, d):
    if not os.environ.get("GZ_TEST_SLOW"):
        return
    W = t.path("slow")
    src = os.path.join(W, "src")
    os.makedirs(src, exist_ok=True)
    fp = os.path.join(src, "big.bin")
    size = (4 << 30) + 12345
    with open(fp, "wb") as f:
        f.truncate(size)
        f.seek(0)
        f.write(b"HEAD" * 1000)
        f.seek(size - 4000)
        f.write(b"TAIL" * 1000)
    p = os.path.join(W, "big.iso")
    mkiso(t, p, src, "-R", "-J", "-iso-level", "3", tool="xorriso")
    rows = d.crc(p)
    import zlib
    crc = zlib.crc32(b"HEAD" * 1000)
    left = size - 8000
    zb = b"\0" * (1 << 22)
    while left:
        k = min(left, len(zb))
        crc = zlib.crc32(zb[:k], crc)
        left -= k
    crc = zlib.crc32(b"TAIL" * 1000, crc)
    t.record(rows.get("big.bin") == (0, size, crc), "multi-extent > 4 GiB", str(rows.get("big.bin")))
    shutil.rmtree(W, ignore_errors=True)


def run(t):
    t.need("genisoimage", "xorriso", "7z")
    d = Drv(t)
    images = {}
    images.update(iso_tools(t, d))
    images.update(iso_generated(t, d))
    images.update(udf_generated(t, d))
    images.update(pycdlib_images(t, d) or {})
    hostile(t, d, images)
    big_multiextent(t, d)
