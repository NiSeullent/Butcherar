"""ZIP / TAR / GZIP regression cases: code pages, NFD, Zip Slip, ZIP64, SFX, encryption, tar variants."""
import os, io, gzip, random, shutil, subprocess, tarfile, unicodedata, zipfile
from gztest import normalize

def blob(n, kind=0, seed=1):
    rnd = random.Random(seed + n)
    if kind == 0:
        return bytes(rnd.getrandbits(8) for _ in range(n))
    words = ["고기", "삼겹살", "목살", "갈비", "zip", "archive", "hello", "world", "\n"]
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(words).encode() + b" "
    return bytes(out[:n])

FILES = {
    "readme.txt": blob(5000, 1),
    "문서/보고서.txt": blob(120000, 1),
    "문서/사진/고기.jpg": blob(70000, 0),
    "empty.txt": b"",
    "deep/a/b/c/d/e.bin": blob(300000, 1),
    "big.bin": blob(3 << 20, 1),
}

class RawInfo(zipfile.ZipInfo):
    """ZipInfo whose name bytes are written verbatim, without the UTF-8 flag."""
    def __init__(self, raw, **kw):
        super().__init__(raw.decode("latin-1"), **kw)
        self.raw_name = raw
    def _encodeFilenameFlags(self):
        return self.raw_name, self.flag_bits & ~0x800

def zip_expect(path, password=None, names=None, from_files=False):
    exp = []
    with zipfile.ZipFile(path) as z:
        if password:
            z.setpassword(password.encode())
        for i, info in enumerate(z.infolist()):
            nm = names[i] if names else info.filename
            if info.is_dir():
                exp.append((nm, None))
            elif from_files:
                exp.append((nm, FILES[normalize(nm)]))
            else:
                exp.append((nm, z.read(info)))
    return exp

def run(t):
    W = t.work
    # 1) deflate, UTF-8 names
    p = t.path("utf8.zip")
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("문서/", b"")
        for k, v in FILES.items():
            z.writestr(k, v)
    utf8_exp = zip_expect(p)
    t.check_extract(p, utf8_exp, expect_type="ZIP")
    for tier in (0, 3, 6):
        t.check_extract(p, utf8_exp, tier=tier, label="utf8.zip tier %d" % tier)

    # 2) CP949 names without the UTF-8 flag
    p = t.path("cp949.zip")
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in FILES.items():
            zi = RawInfo(k.encode("cp949"), date_time=(2020, 5, 17, 13, 45, 10))
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, v)
    t.check_extract(p, zip_expect(p, names=list(FILES.keys())), acp=949)

    # 2b) CP949 names that are also valid UTF-8 must stay CP949
    p = t.path("cp949_ambiguous.zip")
    amb = ["캡처.png", "캡처v2.png", "Win캡처.png", "Img캡처.jpg", "캡처_v2.png", "짤.png", "readme.txt"]
    with zipfile.ZipFile(p, "w") as z:
        for k in amb:
            z.writestr(RawInfo(k.encode("cp949")), k.encode())
    t.check_extract(p, zip_expect(p, names=amb), acp=949)

    # 2c) genuine UTF-8 names without the flag
    p = t.path("latin_utf8.zip")
    lat = ["Résumé.pdf", "café/menu.txt", unicodedata.normalize("NFD", "été.txt"), "Ångström.txt",
           "Отчёт.txt", "Αθήνα.txt", "Größe.txt", "Documentos/Apresentação.pptx", "Příloha.pdf",
           "Müşteri.xlsx", unicodedata.normalize("NFD", "Việt Nam.txt"), unicodedata.normalize("NFD", "Füße.jpg"),
           "Wartość.xlsx", "Účetnictví.xlsx", "Öğrenci listesi.xlsx", "Hóa đơn.pdf", "Facture à payer.pdf",
           "1º Trimestre.xlsx", "Licenţă.pdf", "видео.mp4"]
    with zipfile.ZipFile(p, "w") as z:
        for k in lat:
            z.writestr(RawInfo(k.encode("utf-8")), k.encode())
    lexp = zip_expect(p, names=lat)
    for acp in (949, 936, 932):
        t.check_extract(p, lexp, acp=acp, label="latin_utf8.zip acp %d" % acp)
    p = t.path("decisive_utf8.zip")
    dec = ["Rapport – mars.pdf", "Lettre à Marie.docx", "Facture à payer.pdf", "Ølstue.txt"]
    with zipfile.ZipFile(p, "w") as z:
        for k in dec:
            z.writestr(RawInfo(k.encode("utf-8")), k.encode())
    t.check_extract(p, zip_expect(p, names=dec), acp=949)
    p = t.path("cyrillic_utf8.tar")
    with tarfile.open(p, "w", format=tarfile.GNU_FORMAT, encoding="utf-8") as tf:
        ti = tarfile.TarInfo("Отчёт.txt"); ti.size = 3; tf.addfile(ti, io.BytesIO(b"abc"))
    for acp in (949, 936):
        t.check_extract(p, {"Отчёт.txt": b"abc"}, acp=acp, label="cyrillic_utf8.tar acp %d" % acp)

    # 2d) GBK on Chinese Windows
    p = t.path("gbk.zip")
    gbk = ["通知.doc", "通讯录.xls", "v通知.doc", "Re通知.txt", "討論.txt", "負責人.xlsx", "readme.txt"]
    with zipfile.ZipFile(p, "w") as z:
        for k in gbk:
            z.writestr(RawInfo(k.encode("gbk")), k.encode())
    t.check_extract(p, zip_expect(p, names=gbk), acp=936)

    # 3) macOS NFD Hangul + backslashes
    p = t.path("macnfd.zip")
    nfd = []
    with zipfile.ZipFile(p, "w", zipfile.ZIP_STORED) as z:
        for k in ["한글파일.txt", "폴더\\하위\\깍두기.txt", "__MACOSX/._x"]:
            n = unicodedata.normalize("NFD", k)
            z.writestr(RawInfo(n.encode("utf-8")), k.encode())
            nfd.append(n)
    t.check_extract(p, zip_expect(p, names=nfd), acp=949)

    # 4) zip slip / absolute paths
    p = t.path("slip.zip")
    slip = ["../../evil.txt", "/abs/path.txt", "C:\\Windows\\x.txt", "./ok/./fine.txt", "a/../b.txt"]
    with zipfile.ZipFile(p, "w") as z:
        for k in slip:
            z.writestr(zipfile.ZipInfo(k), k.encode())
    t.check_extract(p, zip_expect(p, names=slip))

    # 5) ZIP64 + SFX prefix
    p = t.path("zip64.zip")
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(700):
            z.writestr("many/f%05d.txt" % i, ("file %d " % i).encode() * 3)
        with z.open("forced64.bin", "w", force_zip64=True) as f:
            f.write(FILES["big.bin"])
    t.check_extract(p, zip_expect(p))
    sfx = t.path("sfx.exe")
    with open(sfx, "wb") as f:
        f.write(b"MZ" + blob(40000))
        f.write(open(t.path("utf8.zip"), "rb").read())
    t.check_extract(sfx, utf8_exp, label="sfx.exe")

    # 6) 7-Zip made: Deflate64, ZipCrypto, AES
    src = t.write_tree(os.path.join(W, "src"), FILES)
    if t.tool("7z"):
        def sz(name, *opts):
            out = t.path(name)
            if os.path.exists(out):
                os.remove(out)
            t.sh(["7z", "a", "-tzip", out, "."] + list(opts), cwd=src)
            return out
        t.check_extract(sz("d64.zip", "-mm=Deflate64", "-mx=9"), FILES)
        t.check_extract(sz("zipcrypto.zip", "-pgogi1234", "-mem=ZipCrypto"), FILES, pw="gogi1234")
        aes = sz("aes256.zip", "-pgogi1234", "-mem=AES256")
        t.check_extract(aes, FILES, pw="gogi1234")
        t.check_extract(sz("aes128store.zip", "-pgogi1234", "-mem=AES128", "-mm=Copy"), FILES, pw="gogi1234")
        r, rows, out = t.extract(aes, pw="nope")
        ok = rows and all(st == 6 or isdir for st, isdir, size, name in rows.values())
        t.record(ok, "wrong password rejected", str(list(rows.values())[:3]))
    try:
        import pyzipper
        for bits in (128, 192, 256):
            p = t.path("pyaes%d.zip" % bits)
            with pyzipper.AESZipFile(p, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
                z.setpassword(b"meat")
                z.setencryption(pyzipper.WZ_AES, nbits=bits)
                for k, v in FILES.items():
                    z.writestr(k, v)
            t.check_extract(p, FILES, pw="meat")
        # Korean password, UTF-8 bytes (Bandizip / 7-Zip style) and CP949 bytes (old Windows tools)
        for enc in ("utf-8", "cp949"):
            p = t.path("kpw_%s.zip" % enc)
            with pyzipper.AESZipFile(p, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
                z.setpassword("고기맛".encode(enc))
                z.writestr("a.txt", FILES["readme.txt"])
            t.check_extract(p, {"a.txt": FILES["readme.txt"]}, pw="고기맛", acp=949, label="korean password " + enc)
    except ImportError:
        pass
    if t.tool("zip"):
        p = t.path("infozip.zip")
        if os.path.exists(p):
            os.remove(p)
        t.sh(["zip", "-q", "-r", "-P", "secret", p, "."], cwd=src)
        t.check_extract(p, FILES, pw="secret", allow_extra=True)

    # 9) tar variants
    def tar_case(name, mode, fmt):
        p = t.path(name)
        exp = dict(FILES)
        with tarfile.open(p, mode, format=fmt) as tf:
            for k, v in FILES.items():
                ti = tarfile.TarInfo(k); ti.size = len(v); ti.mtime = 1600000000
                tf.addfile(ti, io.BytesIO(v))
            long = "long/" + "아주긴이름" * 30 + ".txt"
            ti = tarfile.TarInfo(long); ti.size = 3; tf.addfile(ti, io.BytesIO(b"abc"))
            exp[long] = b"abc"
            ti = tarfile.TarInfo("dir1"); ti.type = tarfile.DIRTYPE; tf.addfile(ti)
            ti = tarfile.TarInfo("link1"); ti.type = tarfile.SYMTYPE; ti.linkname = "readme.txt"; tf.addfile(ti)
        t.check_extract(p, exp, allow_extra=True)
        r, typ, rows = t.listing(p)
        lk = [x for x in rows if x["name"].startswith("link1")]
        t.record(lk and lk[0]["name"] == "link1 -> readme.txt" and (lk[0]["mode"] & 0o170000) == 0o120000,
                 name + " symlink target", str(lk))
    tar_case("pax.tar", "w", tarfile.PAX_FORMAT)
    tar_case("gnu.tar", "w", tarfile.GNU_FORMAT)
    tar_case("pax.tar.gz", "w:gz", tarfile.PAX_FORMAT)
    tar_case("gnu.tgz", "w:gz", tarfile.GNU_FORMAT)

    # 10) .gz single + multi member
    p = t.path("single.txt.gz")
    with open(p, "wb") as raw, gzip.GzipFile("single.txt", "wb", fileobj=raw) as g:
        g.write(FILES["big.bin"])
    t.check_extract(p, {"single.txt": FILES["big.bin"]}, expect_type="GZIP")
    p = t.path("multi.dat.gz")
    with open(p, "wb") as f:
        f.write(gzip.compress(b"first member\n", mtime=0))
        f.write(gzip.compress(FILES["readme.txt"], mtime=0))
    t.check_extract(p, {"multi.dat": b"first member\n" + FILES["readme.txt"]})

    # 11) hostile tar headers
    def tar_header(name, size_field, typeflag=b"0"):
        h = bytearray(512)
        h[0:len(name)] = name
        h[100:108] = b"0000644\0"
        h[124:136] = size_field
        h[136:148] = b"00000000000\0"
        h[156:157] = typeflag
        h[257:263] = b"ustar\0"
        h[263:265] = b"00"
        h[148:156] = b"        "
        h[148:156] = b"%06o\0 " % sum(h)
        return bytes(h)
    p = t.path("evil_pax.tar")
    meta = b"1 path=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    with open(p, "wb") as f:
        f.write(tar_header(b"pax", b"%011o\0" % len(meta), b"x") + meta.ljust(512, b"\0"))
        f.write(tar_header(b"ok.txt", b"%011o\0" % 2) + b"ok".ljust(512, b"\0") + bytes(1024))
    t.check_hostile(p)
    p = t.path("evil_wrap.tar")
    with open(p, "wb") as f:
        f.write(tar_header(b"big.bin", b"\x80\x00\x00\x00" + b"\xff" * 6 + b"\xfe\x00") + bytes(2048))
    t.check_hostile(p)
