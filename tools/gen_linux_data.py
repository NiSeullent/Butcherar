#!/usr/bin/env python3
"""
고깃ZIP Linux desktop data generator.

Writes (outputs are committed; run again after adding formats or changing artwork):

  data/linux/icons/hicolor/NxN/apps/gogitzip.png   application icon (16..512), rendered
                                                   with the same vector code as res/app.ico
  data/linux/gogitzip.desktop                      launcher + MimeType list
  data/linux/gogitzip-mime.xml                     shared-mime-info package for archive
                                                   extensions the freedesktop database lacks
  data/linux/dolphin/*.desktop, thunar/*.xml       file manager menus (same MIME / pattern list)
  src/gtk/mimetypes.h                              extension -> MIME table used at run time
                                                   (file associations)

The readable extensions are collected from the format modules (src/fmt/*.c,
the second string of every gz_format / GZ_STREAM_FORMAT definition).

  python3 tools/gen_linux_data.py            regenerate
  python3 tools/gen_linux_data.py --check    exit 1 when a generated text file is stale, or when
                                             a readable extension is in neither EXT_MIME nor DOCS
"""
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

# extension -> MIME types (first = main type). Standard freedesktop names where they exist.
EXT_MIME = [
    ("zip", ["application/zip", "application/x-zip-compressed"]),
    ("zipx", ["application/zip"]),
    ("7z", ["application/x-7z-compressed"]),
    ("rar", ["application/vnd.rar", "application/x-rar"]),
    ("r00", ["application/x-rar-volume"]),
    ("alz", ["application/x-alz"]),
    ("egg", ["application/x-egg"]),
    ("001", ["application/x-split-archive"]),
    ("tar", ["application/x-tar"]),
    ("gz", ["application/gzip", "application/x-gzip"]),
    ("gzip", ["application/gzip"]),
    ("tgz", ["application/x-compressed-tar"]),
    ("taz", ["application/x-tarz"]),
    ("tpz", ["application/x-compressed-tar"]),
    ("bz2", ["application/x-bzip2", "application/x-bzip"]),
    ("bzip2", ["application/x-bzip2"]),
    ("tbz2", ["application/x-bzip2-compressed-tar", "application/x-bzip-compressed-tar"]),
    ("tbz", ["application/x-bzip1-compressed-tar", "application/x-bzip-compressed-tar"]),
    ("xz", ["application/x-xz"]),
    ("txz", ["application/x-xz-compressed-tar"]),
    ("lzma", ["application/x-lzma"]),
    ("tlz", ["application/x-lzma-compressed-tar"]),
    ("lz", ["application/x-lzip"]),
    ("zst", ["application/zstd"]),
    ("zstd", ["application/zstd"]),
    ("tzst", ["application/x-zstd-compressed-tar"]),
    ("lz4", ["application/x-lz4"]),
    ("tlz4", ["application/x-lz4-compressed-tar"]),
    ("lzo", ["application/x-lzop"]),
    ("tzo", ["application/x-tzo"]),
    ("z", ["application/x-compress"]),
    ("cab", ["application/vnd.ms-cab-compressed"]),
    ("iso", ["application/x-cd-image", "application/x-iso9660-image"]),
    ("udf", ["application/x-udf-image"]),
    ("img", ["application/x-raw-disk-image"]),
    ("arj", ["application/x-arj"]),
    ("lzh", ["application/x-lha", "application/x-lzh-compressed"]),
    ("lha", ["application/x-lha"]),
    ("cpio", ["application/x-cpio"]),
    ("rpm", ["application/x-rpm"]),
    ("deb", ["application/vnd.debian.binary-package", "application/x-deb"]),
    ("udeb", ["application/vnd.debian.binary-package"]),
    ("ipk", ["application/x-ipk"]),
    ("ar", ["application/x-archive"]),
    ("a", ["application/x-archive"]),
    ("wim", ["application/x-ms-wim"]),
    ("swm", ["application/x-ms-wim"]),
    ("esd", ["application/x-ms-wim"]),
    ("dmg", ["application/x-apple-diskimage"]),
    ("xar", ["application/x-xar"]),
    ("pkg", ["application/x-xar"]),
    ("squashfs", ["application/vnd.squashfs"]),
    ("sqfs", ["application/vnd.squashfs"]),
    ("sfs", ["application/vnd.squashfs"]),
    ("squash", ["application/vnd.squashfs"]),
    ("snap", ["application/vnd.snap"]),
    ("cramfs", ["application/x-cramfs-image"]),
    ("cram", ["application/x-cramfs-image"]),
    ("vhd", ["application/x-vhd-disk"]),
    ("vhdx", ["application/x-vhdx-disk"]),
    ("avhdx", ["application/x-vhdx-disk"]),
    ("vmdk", ["application/x-vmdk-disk"]),
    ("qcow", ["application/x-qemu-disk"]),
    ("qcow2", ["application/x-qemu-disk"]),
    ("qcow2c", ["application/x-qemu-disk"]),
    ("vdi", ["application/x-vdi-disk", "application/x-virtualbox-vdi"]),
    ("msi", ["application/x-msi", "application/x-ole-storage"]),
    ("msp", ["application/x-ms-patch"]),
    ("mst", ["application/x-ms-transform"]),
    ("msm", ["application/x-msm"]),
    ("nsis", ["application/x-nsis"]),
    ("vfd", ["application/x-raw-floppy-disk-image"]),
    ("flp", ["application/x-raw-floppy-disk-image"]),
    ("ima", ["application/x-raw-floppy-disk-image"]),
    ("ext2", ["application/x-ext2-image"]),
    ("ext3", ["application/x-ext3-image"]),
    ("ext4", ["application/x-ext4-image"]),
    ("exfat", ["application/x-exfat-image"]),
    ("ntfs", ["application/x-ntfs-image"]),
    ("simg", ["application/x-android-sparse-image"]),
    ("ace", ["application/x-ace"]),
    ("zoo", ["application/x-zoo"]),
    ("arc", ["application/x-arc"]),
    ("sit", ["application/x-stuffit"]),
    ("hfs", ["application/x-hfs-image"]),
    ("hfsx", ["application/x-hfs-image"]),
    ("hfsplus", ["application/x-hfs-image"]),
    ("apfs", ["application/x-apfs-image"]),
    ("chm", ["application/vnd.ms-htmlhelp"]),
    ("jar", ["application/x-java-archive", "application/java-archive"]),
    ("apk", ["application/vnd.android.package-archive"]),
    ("epub", ["application/epub+zip"]),
    ("xpi", ["application/x-xpinstall"]),
]

# documents, packages other programs install, programs, libraries, system files, later volumes of
# a set and generic names: readable, but never claimed as their default program (nor offered in
# the extract menus). Every readable extension is in EXT_MIME or here (--check fails otherwise).
DOCS = {"docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "doc", "xls", "ppt", "msg", "jar", "war", "ear",
        "apk", "ipa", "xpi", "appx", "nupkg", "whl", "chm", "chi", "chq", "chw", "exe", "dll", "bin", "raw",
        "mbr", "gpt", "dsk", "hdd", "fat", "ext", "img", "a",
        "snap", "ddeb", "mpkg", "xip", "pbzx", "smi",                       # packages, installers
        "so", "o", "ko", "dylib", "bundle", "macho", "elf", "efi", "sys", "drv", "ocx", "cpl", "scr", "mui",
        "ax", "acm", "tsp", "prx", "lib", "te", "axf", "mod",                # programs, libraries, drivers
        "38_", "bm_", "ch_", "cp_", "dl_", "dr_", "ex_", "fo_", "hl_", "in_", "ov_", "sy_", "tx_",
        "lzs",                                                                # compressed setup files
        "a00", "z01"}                                                         # later volumes

# types the freedesktop database does not define: described in gogitzip-mime.xml
CUSTOM = {
    "application/x-udf-image": ("UDF disk image", "UDF 디스크 이미지", "application/x-cd-image"),
    "application/vnd.squashfs": ("SquashFS image", "SquashFS 이미지", None),
    "application/x-lz4-compressed-tar": ("Tar archive (LZ4-compressed)", "LZ4로 압축한 TAR 압축 파일", None),
    "application/x-ms-patch": ("Windows Installer patch", "Windows Installer 패치", "application/x-ole-storage"),
    "application/x-ms-transform": ("Windows Installer transform", "Windows Installer 변환", "application/x-ole-storage"),
    "application/x-msm": ("Windows Installer merge module", "Windows Installer 병합 모듈", "application/x-ole-storage"),
    "application/x-ext2-image": ("ext2 file system image", "ext2 파일 시스템 이미지", "application/x-raw-disk-image"),
    "application/x-ext3-image": ("ext3 file system image", "ext3 파일 시스템 이미지", "application/x-raw-disk-image"),
    "application/x-ext4-image": ("ext4 file system image", "ext4 파일 시스템 이미지", "application/x-raw-disk-image"),
    "application/x-exfat-image": ("exFAT file system image", "exFAT 파일 시스템 이미지", "application/x-raw-disk-image"),
    "application/x-android-sparse-image": ("Android sparse image", "Android 스파스 이미지", None),
    "application/x-hfs-image": ("HFS+ disk image", "HFS+ 디스크 이미지", "application/x-raw-disk-image"),
    "application/x-apfs-image": ("APFS disk image", "APFS 디스크 이미지", "application/x-raw-disk-image"),
    "application/x-ntfs-image": ("NTFS file system image", "NTFS 파일 시스템 이미지", "application/x-raw-disk-image"),
    "application/x-cramfs-image": ("CramFS file system image", "CramFS 파일 시스템 이미지", None),
    "application/x-egg": ("EGG archive", "EGG 압축 파일", None),
    "application/x-rar-volume": ("RAR archive volume", "RAR 분할 압축 파일", None),
    "application/x-split-archive": ("Split archive (first part)", "분할 압축 파일 (첫 부분)", None),
    "application/x-ipk": ("OpenWrt package", "OpenWrt 패키지", None),
    "application/x-nsis": ("NSIS installer", "NSIS 설치 파일", None),
}
# extra globs for existing freedesktop types
EXTRA_GLOBS = {"tpz": "application/x-compressed-tar", "zstd": "application/zstd", "esd": "application/x-ms-wim",
               "gzip": "application/gzip", "bzip2": "application/x-bzip2",
               "avhdx": "application/x-vhdx-disk", "qcow2c": "application/x-qemu-disk"}


def readable_exts():
    exts = set()
    pat = re.compile(r'(?:GZ_STREAM_FORMAT\(\s*|const\s+gz_format\s+\w+\s*=\s*\{\s*)"[^"]*"\s*,\s*"([^"]*)"', re.S)
    fdir = os.path.join(ROOT, "src", "fmt")
    for fn in sorted(os.listdir(fdir)):
        if fn.endswith(".c"):
            for m in pat.finditer(open(os.path.join(fdir, fn), encoding="utf-8", errors="replace").read()):
                exts.update(m.group(1).lower().split())
    return exts


def desktop_text(types):
    return """[Desktop Entry]
Type=Application
Version=1.0
Name=GogitZIP
Name[ko]=고깃ZIP
GenericName=Archive Manager
GenericName[ko]=압축 프로그램
Comment=Open, extract and create archives
Comment[ko]=압축 파일을 열고, 풀고, 새로 만듭니다
Keywords=zip;7z;rar;tar;archive;extract;compress;압축;압축풀기;
Exec=gogitzip-gtk %F
TryExec=gogitzip-gtk
Icon=gogitzip
Terminal=false
StartupNotify=true
StartupWMClass=gogitzip-gtk
Categories=GTK;Utility;Archiving;Compression;
MimeType={types};
Actions=new-archive;

[Desktop Action new-archive]
Name=New archive
Name[ko]=새로 압축
Exec=gogitzip-gtk --compress
""".format(types=";".join(types))


def mime_xml():
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<!-- generated by tools/gen_linux_data.py: archive types the freedesktop.org database lacks -->',
           '<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">']
    globs = {}
    for ext, types in EXT_MIME:
        if types[0] in CUSTOM:
            globs.setdefault(types[0], []).append(ext)
    for t in sorted(CUSTOM):
        en, ko, sub = CUSTOM[t]
        out.append('  <mime-type type="%s">' % t)
        out.append('    <comment>%s</comment>' % en)
        out.append('    <comment xml:lang="ko">%s</comment>' % ko)
        if sub:
            out.append('    <sub-class-of type="%s"/>' % sub)
        out.append('    <generic-icon name="package-x-generic"/>')
        for g in globs.get(t, []):
            out.append('    <glob pattern="*.%s"/>' % g)
        out.append('  </mime-type>')
    for ext in sorted(EXTRA_GLOBS):
        out.append('  <mime-type type="%s">' % EXTRA_GLOBS[ext])
        out.append('    <glob pattern="*.%s"/>' % ext)
        out.append('  </mime-type>')
    out.append('</mime-info>')
    return "\n".join(out) + "\n"


def header_text():
    out = ["/* generated by tools/gen_linux_data.py - do not edit */",
           "#ifndef GZ_GTK_MIMETYPES_H", "#define GZ_GTK_MIMETYPES_H",
           "/* extension -> MIME type of archives GogitZIP may become the default program for */",
           "typedef struct { const char *ext, *mime; } gz_ext_mime;",
           "static const gz_ext_mime k_ext_mime[] = {"]
    for ext, types in EXT_MIME:
        if ext in DOCS:
            continue
        for t in types:
            out.append('    { "%s", "%s" },' % (ext, t))
    out += ["    { 0, 0 }", "};", "#endif", ""]
    return "\n".join(out)


def archive_types():
    """MIME types and extensions of archives (documents excluded)"""
    seen, types, exts = set(), [], []
    for ext, ts in EXT_MIME:
        if ext in DOCS:
            continue
        exts.append(ext)
        for t in ts:
            if t not in seen:
                seen.add(t)
                types.append(t)
    return types, exts


def dolphin_text():
    types, _ = archive_types()
    return """# generated by tools/gen_linux_data.py
# Dolphin (KDE) service menu: copy to ~/.local/share/kio/servicemenus/ (KDE 5.85+ / 6)
# and make it executable (chmod +x).
[Desktop Entry]
Type=Service
MimeType={types};
Actions=gzExtractHere;gzExtractSmart;gzExtract;gzTest;
X-KDE-Priority=TopLevel
X-KDE-Submenu=GogitZIP
X-KDE-Submenu[ko]=고깃ZIP
Icon=gogitzip

[Desktop Action gzExtractHere]
Name=Extract here
Name[ko]=여기에 풀기
Icon=gogitzip
Exec=gogitzip-gtk --extract-here %F

[Desktop Action gzExtractSmart]
Name=Extract to a new folder
Name[ko]=폴더를 만들어 풀기
Icon=gogitzip
Exec=gogitzip-gtk --extract-smart %F

[Desktop Action gzExtract]
Name=Extract...
Name[ko]=압축 풀기...
Icon=gogitzip
Exec=gogitzip-gtk --extract %F

[Desktop Action gzTest]
Name=Test archive
Name[ko]=압축 파일 테스트
Icon=gogitzip
Exec=gogitzip-gtk --test %F
""".format(types=";".join(types))


DOLPHIN_COMPRESS = """# generated by tools/gen_linux_data.py
# Dolphin (KDE) service menu for any file or folder: copy next to gogitzip-extract.desktop.
[Desktop Entry]
Type=Service
MimeType=application/octet-stream;inode/directory;
Actions=gzCompress;
X-KDE-Priority=TopLevel
Icon=gogitzip

[Desktop Action gzCompress]
Name=Compress with GogitZIP...
Name[ko]=고깃ZIP으로 압축하기...
Icon=gogitzip
Exec=gogitzip-gtk --compress %F
"""


def thunar_text():
    _, exts = archive_types()
    pats = ";".join("*.%s" % e for e in exts) + ";" + ";".join("*.%s" % e.upper() for e in exts if e != e.upper())
    acts = [("gogitzip-extract-here", "고깃ZIP: 여기에 풀기", "GogitZIP: Extract here", "--extract-here", pats, False),
            ("gogitzip-extract-smart", "고깃ZIP: 폴더를 만들어 풀기", "GogitZIP: Extract to a new folder",
             "--extract-smart", pats, False),
            ("gogitzip-extract", "고깃ZIP: 압축 풀기...", "GogitZIP: Extract...", "--extract", pats, False),
            ("gogitzip-compress", "고깃ZIP: 새로 압축...", "GogitZIP: Compress...", "--compress", "*", True)]
    out = ["<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
           "<!-- generated by tools/gen_linux_data.py",
           "     Thunar custom actions: merge the <action> elements into ~/.config/Thunar/uca.xml",
           "     (inside <actions>), then restart Thunar (thunar -q). -->",
           "<actions>"]
    for uid, ko, en, opt, p, dirs in acts:
        out += ["<action>",
                "\t<icon>gogitzip</icon>",
                "\t<name>%s</name>" % en,
                "\t<name xml:lang=\"ko\">%s</name>" % ko,
                "\t<unique-id>%s</unique-id>" % uid,
                "\t<command>gogitzip-gtk %s %%F</command>" % opt,
                "\t<description>%s</description>" % en,
                "\t<description xml:lang=\"ko\">%s</description>" % ko,
                "\t<patterns>%s</patterns>" % p]
        if dirs:
            out.append("\t<directories/>")
        out += ["\t<other-files/>", "</action>"]
    out.append("</actions>")
    return "\n".join(out) + "\n"


def all_types():
    seen, types = set(), []
    for ext, ts in EXT_MIME:
        for t in ts:
            if t not in seen:
                seen.add(t)
                types.append(t)
    return types


def write_icons():
    import gen_assets
    for s in (16, 22, 24, 32, 48, 64, 128, 256, 512):
        d = os.path.join(ROOT, "data", "linux", "icons", "hicolor", "%dx%d" % (s, s), "apps")
        os.makedirs(d, exist_ok=True)
        gen_assets.logo(s).save(os.path.join(d, "gogitzip.png"), optimize=True)


def unmapped(readable):
    """readable extensions neither mapped to a MIME type nor deliberately left out"""
    return sorted(set(readable) - {e for e, _ in EXT_MIME} - DOCS)


def main():
    check = "--check" in sys.argv
    texts = {
        os.path.join("data", "linux", "gogitzip.desktop"): desktop_text(all_types()),
        os.path.join("data", "linux", "gogitzip-mime.xml"): mime_xml(),
        os.path.join("src", "gtk", "mimetypes.h"): header_text(),
        os.path.join("data", "linux", "dolphin", "gogitzip-extract.desktop"): dolphin_text(),
        os.path.join("data", "linux", "dolphin", "gogitzip-compress.desktop"): DOLPHIN_COMPRESS,
        os.path.join("data", "linux", "thunar", "uca-gogitzip.xml"): thunar_text(),
    }
    missing = unmapped(readable_exts())
    stale = []
    for rel, txt in texts.items():
        p = os.path.join(ROOT, rel)
        old = open(p, encoding="utf-8").read() if os.path.exists(p) else None
        if old != txt:
            stale.append(rel)
            if not check:
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w", encoding="utf-8") as f:
                    f.write(txt)
    if check:
        # a new reader nobody classified: the launcher, the file manager menus and
        # --set-default-apps would silently leave its files out (as .alz/.egg once were)
        if missing:
            print("unmapped: readable extensions in neither EXT_MIME nor DOCS:", " ".join(missing))
        if stale:
            print("stale:", " ".join(stale))
        sys.exit(1 if stale or missing else 0)
    write_icons()
    print("wrote", ", ".join(texts), "and the hicolor icons")
    if missing:
        print("error: readable extensions in neither EXT_MIME nor DOCS:", " ".join(missing))
        sys.exit(1)


if __name__ == "__main__":
    main()
