#!/usr/bin/env python3
"""
고깃ZIP documentation generator: keeps the generated parts of README.md,
web/index.html and .github/release-notes.md in step with the code.

  * the program version (src/core/version.h) wherever a document names a release:
    "고깃ZIP 2.0.0", "GogitZIP 2.0.0", package names "GogitZIP-2.0.0-linux-...",
    "gogitzip_2.0.0_amd64.deb", data-version="2.0.0"
  * the format tables, lists and counts between marker comments
        <!-- gen:KEY -->...<!-- /gen:KEY -->
    built from the format / writer registry: every "GZ_FORMAT(sym)" and
    "GZ_WRITER(sym)" marker line in src/core, src/codec and src/fmt (the same
    lines tools/gen_registry.sh turns into the program's tables), the display
    name and extensions of each gz_format and the method / encryption masks of
    each gz_writer. Descriptions and categories come from META below.

  python3 tools/gen_docs.py            update the documents
  python3 tools/gen_docs.py --check    exit 1 when a document is stale (tests/cases/release_meta.py)
  python3 tools/gen_docs.py --json     print the registry as parsed

A new reader still gets a row without a META entry (category "기타", its registry
name as description); --check prints a note so it can be described properly.
"""
import glob, html, json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = ["README.md", os.path.join("web", "index.html"), os.path.join(".github", "release-notes.md")]

# ---------------------------------------------------------------- registry

STR = r'"((?:[^"\\]|\\.)*)"'


def version(root=ROOT):
    t = open(os.path.join(root, "src", "core", "version.h"), encoding="utf-8").read()
    return re.search(r'#define GZ_APP_VERSION "([^"]+)"', t).group(1)


def registry(root=ROOT):
    """(readers, writers) in the order of the program's tables (sorted by symbol)."""
    readers, writers = {}, {}
    files = []
    for d in ("core", "codec", "fmt"):
        files += sorted(glob.glob(os.path.join(root, "src", d, "*.c")))
    for fn in files:
        t = open(fn, encoding="utf-8", errors="replace").read()
        for sym in re.findall(r'^GZ_FORMAT\((\w+)\)', t, re.M):
            m = re.search(r'const\s+gz_format\s+' + sym + r'\s*=\s*(?:GZ_STREAM_FORMAT\(\s*|\{\s*)' + STR + r'\s*,\s*' + STR, t)
            if not m:
                raise SystemExit("%s: cannot parse the definition of %s" % (fn, sym))
            readers[sym] = {"sym": sym, "name": m.group(1), "exts": m.group(2).split(), "file": os.path.relpath(fn, root)}
        for sym in re.findall(r'^GZ_WRITER\((\w+)\)', t, re.M):
            m = re.search(r'const\s+gz_writer\s+' + sym + r'\s*=\s*\{(.*?)\};', t, re.S)
            if not m:
                raise SystemExit("%s: cannot parse the definition of %s" % (fn, sym))
            body = m.group(1)
            # expand the file's own mask macros (#define M_GZ (M(DEFAULT) | M(STORE) ...))
            macros = dict(re.findall(r'^#define\s+(M_\w+)\s+(.*)$', t, re.M))
            for _ in range(4):
                body = re.sub(r'\b(M_\w+)\b', lambda x: macros.get(x.group(1), x.group(1)), body)
            strs = re.findall(STR, body)
            meth = [a or b for a, b in re.findall(r'GZ_WM_(\w+)|\bM\((\w+)\)', body)]
            enc = re.findall(r'GZ_WE_(\w+)', body)
            writers[sym] = {"sym": sym, "name": strs[0], "ext": strs[1],
                            "methods": [x.lower() for x in METHOD_ORDER if x.upper() in meth],
                            "enc": [x for x in ENC_ORDER if x.upper() in enc], "file": os.path.relpath(fn, root)}
    order = lambda d: [d[k] for k in sorted(d)]          # LC_ALL=C sort, as gen_registry.sh
    return order(readers), order(writers)


# ---------------------------------------------------------------- descriptions

CATS = [  # key, Korean, English
    ("archive", "압축 파일", "Archives"),
    ("installer", "설치 파일·실행 파일", "Installers & executables"),
    ("disk", "디스크 이미지", "Disk images"),
    ("fs", "파일 시스템", "File systems"),
    ("other", "기타", "Other"),
]

# registry name -> (category, display name or None or (Korean, English), Korean description,
# English description); table order
META = [
    ("7z", "archive", None, "LZMA·LZMA2·PPMd·BZip2·Deflate64·Zstd·LZ4, BCJ·BCJ2 필터, AES-256, 헤더 암호화",
     "LZMA/LZMA2/PPMd/BZip2/Deflate64/Zstd/LZ4, BCJ/BCJ2 filters, AES-256, encrypted headers"),
    ("ZIP", "archive", None, "Deflate·Deflate64·BZip2·LZMA·PPMd·Zstd·XZ·Implode·Shrink, ZIP64, WinZip AES·ZipCrypto, 분할(.z01), SFX",
     "Deflate/Deflate64/BZip2/LZMA/PPMd/Zstd/XZ/Implode/Shrink, ZIP64, WinZip AES/ZipCrypto, split (.z01), SFX"),
    ("RAR5", "archive", None, "RAR 5 ~ 7, 솔리드, 볼륨, AES-256 암호·헤더 암호화, BLAKE2sp",
     "RAR 5-7: solid, volumes, AES-256, encrypted headers, BLAKE2sp"),
    ("RAR", "archive", None, "RAR 1.4 ~ 4.x, 솔리드, 볼륨, AES-128 암호·헤더 암호화",
     "RAR 1.4-4.x: solid, volumes, AES-128, encrypted headers"),
    ("ALZ", "archive", None, "알집 4 ~ 7, 분할(.a00), ZipCrypto 암호, 한글 이름(CP949)",
     "ALZip 4-7: split sets (.a00), ZipCrypto, Korean names"),
    ("EGG", "archive", None, "알집 8 이상, 솔리드, 분할, AZO·LZMA·BZip2·Deflate, AES·LEA 암호",
     "ALZip 8+: solid, split sets, AZO/LZMA/BZip2/Deflate, AES and LEA encryption"),
    ("TAR", "archive", None, "ustar·GNU·pax·v7, 긴 이름과 링크, 압축된 TAR(.tar.gz 등)도 바로",
     "ustar/GNU/pax/v7, long names and links, compressed tarballs in one step"),
    ("GZIP", "archive", None, "여러 멤버, .tar.gz·.tgz", "multi-member, .tar.gz/.tgz"),
    ("BZIP2", "archive", None, "여러 스트림, .tar.bz2", "multi-stream, .tar.bz2"),
    ("XZ", "archive", None, "BCJ·Delta 필터, CRC-64·SHA-256 검사, .tar.xz", "BCJ/Delta filters, CRC-64/SHA-256 checks, .tar.xz"),
    ("ZSTD", "archive", None, "Zstandard, .tar.zst", "Zstandard, .tar.zst"),
    ("LZMA", "archive", None, "LZMA-alone (.lzma)", "LZMA-alone (.lzma)"),
    ("LZIP", "archive", None, "lzip (.lz)", "lzip (.lz)"),
    ("LZ4", "archive", None, "LZ4 프레임 (.lz4)", "LZ4 frames"),
    ("LZO", "archive", None, "lzop (.lzo)", "lzop"),
    ("Z", "archive", None, "Unix compress (.Z)", "Unix compress (.Z)"),
    ("CAB", "archive", None, "MSZIP·Quantum·LZX, 여러 CAB에 걸친 파일, 실행 파일 속 CAB",
     "MSZIP/Quantum/LZX, multi-cabinet sets, CABs inside executables"),
    ("ARJ", "archive", None, "ARJ 0.x ~ 3.x, 볼륨, SFX, 암호(XOR)", "ARJ 0.x-3.x, volumes, SFX, garbled files"),
    ("LZH", "archive", "LZH / LHA", "lh0 ~ lh7·lzs·lz5, 헤더 레벨 0 ~ 3, SFX", "lh0-lh7/lzs/lz5, header levels 0-3, SFX"),
    ("CPIO", "archive", None, "newc·crc·odc·바이너리, initramfs", "newc/crc/odc/binary, initramfs"),
    ("CHM", "archive", None, "Windows 도움말 (LZX)", "Windows HTML Help (LZX)"),
    ("SZDD", "archive", "SZDD / KWAJ", "MS compress.exe (SETUP.EX_ 등)", "MS compress.exe files (SETUP.EX_ ...)"),
    ("PBZX", "archive", None, "macOS 업데이트·설치 페이로드", "macOS update / installer payloads"),
    ("Split", "archive", ("분할 파일", "Split files"), "7-Zip·HJSplit 분할 파일(.001)을 이어서 열기", "split files (.001) joined and opened"),
    ("NSIS", "installer", None, "NSIS 2 ~ 3 설치 파일 (zlib·BZip2·LZMA, 솔리드)", "NSIS 2-3 installers (zlib/BZip2/LZMA, solid)"),
    ("Inno Setup", "installer", None, "Inno Setup 1.3 ~ 7.x 설치 파일, 암호", "Inno Setup 1.3-7.x installers, passwords"),
    ("Compound", "installer", "MSI / OLE", "Windows Installer(.msi·.msp·.msm), Office 97 ~ 2003 문서, Outlook .msg",
     "Windows Installer (.msi/.msp/.msm), Office 97-2003 documents, Outlook .msg"),
    ("XAR", "installer", None, "macOS 설치 패키지(.pkg), .xip", "macOS installer packages (.pkg), .xip"),
    ("RPM", "installer", None, "RPM 패키지 (gzip·bzip2·xz·zstd 페이로드)", "RPM packages (gzip/bzip2/xz/zstd payloads)"),
    ("AR", "installer", None, "Debian 패키지(.deb), 정적 라이브러리(.a·.lib)", "Debian packages (.deb), static libraries (.a/.lib)"),
    ("PE", "installer", None, "Windows 실행 파일·DLL: 섹션, 리소스(아이콘·버전·문자열), 덧붙은 데이터",
     "Windows executables/DLLs: sections, resources (icons, version, strings), overlay"),
    ("ELF", "installer", None, "Linux 실행 파일·라이브러리: 섹션, 세그먼트", "Linux executables/libraries: sections, segments"),
    ("Mach-O", "installer", None, "macOS 실행 파일, 유니버설 바이너리", "macOS executables, universal binaries"),
    ("ISO", "disk", None, "ISO 9660·Joliet·Rock Ridge, El Torito 부트 이미지, 4GB 넘는 파일",
     "ISO 9660/Joliet/Rock Ridge, El Torito boot images, files over 4 GB"),
    ("UDF", "disk", None, "UDF 1.02 ~ 2.60 (DVD·Blu-ray)", "UDF 1.02-2.60 (DVD, Blu-ray)"),
    ("DMG", "disk", None, "macOS 디스크 이미지 (ADC·zlib·bzip2·LZFSE·XZ)", "macOS disk images (ADC/zlib/bzip2/LZFSE/XZ)"),
    ("WIM", "disk", None, "Windows 이미지 WIM·ESD·SWM (XPRESS·LZX·LZMS)", "Windows images WIM/ESD/SWM (XPRESS/LZX/LZMS)"),
    ("VHD", "disk", None, "Virtual PC·Hyper-V (고정·동적·차이 디스크)", "Virtual PC/Hyper-V (fixed, dynamic, differencing)"),
    ("VHDX", "disk", None, "Hyper-V VHDX", "Hyper-V VHDX"),
    ("VMDK", "disk", None, "VMware (sparse·streamOptimized·flat)", "VMware (sparse, streamOptimized, flat)"),
    ("VDI", "disk", None, "VirtualBox", "VirtualBox"),
    ("QCOW2", "disk", "QCOW / QCOW2", "QEMU (압축 클러스터 포함)", "QEMU (compressed clusters too)"),
    ("Sparse", "disk", None, "Android sparse 이미지", "Android sparse images"),
    ("MBR", "disk", "MBR / GPT", "파티션 테이블 MBR·GPT·Apple Partition Map", "partition maps: MBR, GPT, Apple Partition Map"),
    ("NTFS", "fs", None, "압축·WOF 압축, 대체 데이터 스트림, 링크", "compression (LZNT1, WOF), alternate streams, links"),
    ("FAT", "fs", None, "FAT12·FAT16·FAT32, 긴 이름", "FAT12/16/32, long names"),
    ("exFAT", "fs", None, "exFAT", "exFAT"),
    ("ext", "fs", "ext2/3/4", "ext2·ext3·ext4 (익스텐트, 인라인 데이터)", "ext2/ext3/ext4 (extents, inline data)"),
    ("HFS+", "fs", "HFS / HFS+", "HFS·HFS+·HFSX, 압축된 파일", "HFS/HFS+/HFSX, compressed files"),
    ("APFS", "fs", None, "Apple File System (암호화되지 않은 볼륨)", "Apple File System (unencrypted volumes)"),
    ("SquashFS", "fs", None, "SquashFS 3.x·4.0 (gzip·lzma·xz·lzo·lz4·zstd)", "SquashFS 3.x/4.0 (gzip/lzma/xz/lzo/lz4/zstd)"),
    ("CramFS", "fs", None, "CramFS", "CramFS"),
]

METHOD_ORDER = ["store", "deflate", "deflate64", "bzip2", "lzma", "lzma2", "ppmd", "zstd"]
METHOD_NAME = {"store": ("저장", "Store"), "deflate": ("Deflate",) * 2, "deflate64": ("Deflate64",) * 2,
               "bzip2": ("BZip2",) * 2, "lzma": ("LZMA",) * 2, "lzma2": ("LZMA2",) * 2, "ppmd": ("PPMd",) * 2,
               "zstd": ("Zstandard",) * 2}
ENC_ORDER = ["zipcrypto", "aes256"]
ENC_NAME = {"zipcrypto": "ZipCrypto", "aes256": "AES-256"}
# what the masks do not say (writer name -> Korean, English)
WRITER_NOTES = {
    "7z": ("BCJ·ARM64 필터, 파일 이름 암호화", "BCJ/ARM64 filters, encrypted names"),
    "ZIP": ("ZIP64", "ZIP64"),
    "ISO": ("Joliet·Rock Ridge", "Joliet, Rock Ridge"),
    "TAR": ("ustar·pax: 긴 이름·링크·권한", "ustar/pax: long names, links, permissions"),
}


def rows(readers, writers):
    """Readers in table order with category, description and what we write."""
    meta = {m[0]: m for m in META}
    by_name = {r["name"]: r for r in readers}
    out = []
    for r in readers:
        m = meta.get(r["name"])
        cat, disp, ko, en = (m[1], m[2], m[3], m[4]) if m else ("other", None, r["name"], r["name"])
        dko, den = disp if isinstance(disp, tuple) else (disp or r["name"],) * 2
        out.append(dict(r, cat=cat, disp=dko, disp_en=den, ko=ko, en=en, w=[]))
    # every writer lands on the reader of the same name, else on the one reading its
    # last extension ("TAR.GZ" / "tar.gz" -> GZIP)
    idx = {x["name"]: x for x in out}
    for w in writers:
        tgt = idx.get(w["name"])
        if not tgt:
            last = w["ext"].rsplit(".", 1)[-1]
            tgt = next((x for x in out if last in x["exts"]), None)
        if tgt:
            tgt["w"].append(w)
    for x in out:                        # the writer of the same name first: ".xz, .tar.xz"
        x["w"].sort(key=lambda w: w["name"] != x["name"])
    pos = {m[0]: i for i, m in enumerate(META)}
    catpos = {c[0]: i for i, c in enumerate(CATS)}
    out.sort(key=lambda x: (catpos[x["cat"]], pos.get(x["name"], 999), x["name"].lower()))
    unplaced = [w["name"] for w in writers if not any(w in x["w"] for x in out)]
    return out, unplaced, sorted(set(by_name) - set(meta))


def write_cell(x, lang):
    """'저장 · Deflate (.gz, .tar.gz)' + encryption + notes; '' when we only read it."""
    if not x["w"]:
        return ""
    k = 0 if lang == "ko" else 1
    meth = [m for m in METHOD_ORDER if any(m in w["methods"] for w in x["w"])]
    enc = [e for e in ENC_ORDER if any(e in w["enc"] for w in x["w"])]
    s = " · ".join(METHOD_NAME[m][k] for m in meth) if meth != ["store"] else ""   # TAR, ISO: no methods
    if enc:
        s += " + " + " · ".join(ENC_NAME[e] for e in enc)
    notes = [WRITER_NOTES[w["name"]][k] for w in x["w"] if w["name"] in WRITER_NOTES]
    if notes:
        s += (", " if s else "") + ", ".join(notes)
    return (s + " " if s else "") + "(" + ", ".join("." + w["ext"] for w in x["w"]) + ")"


# ---------------------------------------------------------------- renderers

def md_tables(rs):
    out = []
    for key, ko, en in CATS:
        part = [x for x in rs if x["cat"] == key]
        if not part:
            continue
        out += ["", "#### %s (%d)" % (ko, len(part)), "",
                "| 형식 | 확장자 | 읽기 | 만들기 |", "|---|---|---|---|"]
        for x in part:
            w = write_cell(x, "ko")
            out.append("| **%s** | %s | ✓ %s | %s |" % (x["disp"], " ".join(x["exts"]), x["ko"], ("✓ " + w) if w else "—"))
    return "\n".join(out) + "\n\n"


def md_list(rs, lang):
    k = 1 if lang == "ko" else 2
    out = [""]
    for c in CATS:
        part = [x["disp" if lang == "ko" else "disp_en"] for x in rs if x["cat"] == c[0]]
        if part:
            out.append("- **%s** (%d): %s" % (c[k], len(part), ", ".join(part)))
    return "\n".join(out) + "\n"


def md_writers(rs, lang):
    out = [""]
    for x in rs:
        if x["w"]:
            out.append("- **%s**: %s" % (x["disp" if lang == "ko" else "disp_en"], write_cell(x, lang)))
    return "\n".join(out) + "\n"


def html_table(rs):
    e = html.escape
    catname = {c[0]: c[1] for c in CATS}
    out = ['<table class="fmt-table" id="fmt-table">',
           '<thead><tr><th scope="col">형식</th><th scope="col">확장자</th><th scope="col">읽기</th><th scope="col">만들기</th></tr></thead>',
           "<tbody>"]
    for x in rs:
        w = write_cell(x, "ko")
        key = " ".join([x["name"], x["disp"], x["disp_en"], x["en"]] + x["exts"]).lower()
        out.append('<tr data-cat="%s" data-w="%d" data-key="%s"><th scope="row"><b>%s</b><span class="cat">%s</span></th>'
                   '<td class="ext">%s</td><td>%s</td><td class="w">%s</td></tr>'
                   % (x["cat"], 1 if w else 0, e(key), e(x["disp"]), e(catname[x["cat"]]),
                      " ".join("<code>.%s</code>" % e(s) for s in x["exts"]), e(x["ko"]),
                      ('<span class="yes">%s</span>' % e(w)) if w else '<span class="no">읽기 전용</span>'))
    out += ["</tbody>", "</table>"]
    return "\n" + "\n".join(out) + "\n"


def html_filters(rs):
    out = ['<button type="button" class="chip" data-cat="" aria-pressed="true">전체 <span>%d</span></button>' % len(rs)]
    for key, ko, en in CATS:
        n = sum(1 for x in rs if x["cat"] == key)
        if n:
            out.append('<button type="button" class="chip" data-cat="%s" aria-pressed="false">%s <span>%d</span></button>' % (key, html.escape(ko), n))
    nw = sum(1 for x in rs if x["w"])
    out.append('<button type="button" class="chip" data-cat="write" aria-pressed="false">만들기 가능 <span>%d</span></button>' % nw)
    return "\n" + "\n".join(out) + "\n"


def blocks(root=ROOT):
    readers, writers = registry(root)
    rs, unplaced, undescribed = rows(readers, writers)
    nfmt = len(readers)
    nwfmt = len(writers)
    return {
        "nread": str(nfmt),
        "nwrite": str(nwfmt),
        "nwritefmt": str(sum(1 for x in rs if x["w"])),
        "formats-md": md_tables(rs),
        "formats-list-ko": md_list(rs, "ko"),
        "formats-list-en": md_list(rs, "en"),
        "writers-ko": md_writers(rs, "ko"),
        "writers-en": md_writers(rs, "en"),
        "formats-html": html_table(rs),
        "formats-filters": html_filters(rs),
    }, unplaced, undescribed


# ---------------------------------------------------------------- documents

VERSION_RES = [
    r'(고깃ZIP )(\d+\.\d+\.\d+)\b',
    r'(GogitZIP )(\d+\.\d+\.\d+)\b',
    r'(GogitZIP-)(\d+\.\d+\.\d+)(?=-)',
    r'(gogitzip_)(\d+\.\d+\.\d+)(?=_)',
    r'(data-version=")(\d+\.\d+\.\d+)(?=")',
]
MARK = re.compile(r'<!-- gen:([\w-]+) -->(.*?)<!-- /gen:\1 -->', re.S)


def render(text, gen, ver):
    """Document text with every marker block and release version brought up to date."""
    def blk(m):
        if m.group(1) not in gen:
            raise SystemExit("unknown marker gen:%s" % m.group(1))
        return "<!-- gen:%s -->%s<!-- /gen:%s -->" % (m.group(1), gen[m.group(1)], m.group(1))
    text = MARK.sub(blk, text)
    for rx in VERSION_RES:
        text = re.sub(rx, lambda m: m.group(1) + ver, text)
    return text


def stale(root=ROOT):
    """[(path, current text, wanted text)] for documents that need regenerating."""
    gen, _, _ = blocks(root)
    ver = version(root)
    out = []
    for rel in DOCS:
        p = os.path.join(root, rel)
        old = open(p, encoding="utf-8").read()
        new = render(old, gen, ver)
        if new != old:
            out.append((rel, old, new))
    return out


def main():
    if "--json" in sys.argv:
        r, w = registry()
        print(json.dumps({"version": version(), "readers": r, "writers": w}, ensure_ascii=False, indent=1))
        return
    _, unplaced, undescribed = blocks()
    if unplaced:
        print("note: writers without a matching reader row:", ", ".join(unplaced))
    if undescribed:
        print("note: readers without a description (add them to META in tools/gen_docs.py):", ", ".join(undescribed))
    bad = stale()
    if "--check" in sys.argv:
        for rel, _, _ in bad:
            print("stale:", rel, "(run: python3 tools/gen_docs.py)")
        sys.exit(1 if bad else 0)
    for rel, _, new in bad:
        with open(os.path.join(ROOT, rel), "w", encoding="utf-8") as f:
            f.write(new)
        print("updated", rel)


if __name__ == "__main__":
    main()
