#!/bin/sh
# 고깃ZIP Linux packages (called by `make dist-linux` and `make deb`).
#
#   tools/linux/pkg.sh tar VERSION ARCH OUTDIR TREE   -> OUTDIR/GogitZIP-VERSION-linux-ARCH.tar.gz
#   tools/linux/pkg.sh deb VERSION ARCH OUTDIR TREE   -> OUTDIR/gogitzip_VERSION_ARCH.deb
#
# TREE is a staging directory filled by `make install DESTDIR=TREE PREFIX=` (bin/, share/):
# the same files `make install` puts on a system. ARCH: uname -m for the tarball
# (x86_64, aarch64), the Debian name for the package (amd64, arm64).
# SOURCE_DATE_EPOCH (CI: the commit time) makes both archives reproducible.
# STRIP (default: strip) removes debug information from the programs.
set -eu

kind=$1 ver=$2 arch=$3 out=$4 tree=$5
top=$(cd "$(dirname "$0")/../.." && pwd)
epoch=${SOURCE_DATE_EPOCH:-$(date +%s)}
strip=${STRIP:-strip}

for f in bin/gogitzip bin/gogitzip-gtk share/applications/gogitzip.desktop; do
    [ -f "$tree/$f" ] || { echo "pkg.sh: $tree/$f is missing" >&2; exit 1; }
done
"$strip" --strip-unneeded "$tree/bin/gogitzip" "$tree/bin/gogitzip-gtk"
mkdir -p "$out"

# lowest glibc the programs need (GLIBC_2.x symbol versions), for the README and Depends
glibc=$(objdump -T "$tree/bin/gogitzip" "$tree/bin/gogitzip-gtk" 2>/dev/null |
        sed -n 's/.*GLIBC_\([0-9][0-9.]*\).*/\1/p' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)
glibc=${glibc:-2.17}

stamp() {   # every file and directory gets the same time stamp
    find "$1" -exec touch -h -d "@$epoch" {} +
}

case $kind in
tar)
    name=GogitZIP-$ver-linux-$arch
    stage=$out/$name
    rm -rf "$stage"
    mkdir -p "$stage"
    cp -R "$tree/bin" "$tree/share" "$stage/"
    install -m755 "$top/tools/linux/install.sh" "$top/tools/linux/uninstall.sh" "$stage/"
    sed -e "s/@VERSION@/$ver/g" -e "s/@ARCH@/$arch/g" -e "s/@GLIBC@/$glibc/g" \
        "$top/tools/linux/README.txt" > "$stage/README.txt"
    cp "$top/LICENSE" "$stage/LICENSE.txt"
    # right-click menus for Nautilus, Dolphin and Thunar (copied by hand, see README.txt)
    mkdir -p "$stage/file-manager"
    cp -R "$top/data/linux/nautilus" "$top/data/linux/dolphin" "$top/data/linux/thunar" "$stage/file-manager/"
    find "$stage" -type d -exec chmod 755 {} +
    find "$stage/share" "$stage/README.txt" "$stage/LICENSE.txt" "$stage/file-manager" -type f -exec chmod 644 {} +
    chmod 755 "$stage"/file-manager/nautilus/* "$stage"/file-manager/dolphin/*
    stamp "$stage"
    (cd "$out" && tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" -cf - "$name") |
        gzip -9n > "$out/$name.tar.gz"
    rm -rf "$stage"
    echo "$out/$name.tar.gz"
    ;;
deb)
    name=gogitzip_${ver}_$arch
    stage=$out/$name
    rm -rf "$stage"
    mkdir -p "$stage/usr" "$stage/DEBIAN" "$stage/usr/share/doc/gogitzip"
    cp -R "$tree/bin" "$tree/share" "$stage/usr/"
    {
        echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"
        echo "Upstream-Name: GogitZIP"
        echo "Source: https://github.com/NiSeullent/Butcherar"
        echo
        echo "Files: *"
        echo "Copyright: 2026 Butcherar contributors"
        echo "License: MIT"
        # the license text after the copyright line, as an indented field (" ." = blank line)
        awk 'f && NF { p = 1 } p { print (NF ? " " $0 : " .") } /^Copyright/ { f = 1 }' "$top/LICENSE"
    } > "$stage/usr/share/doc/gogitzip/copyright"
    find "$stage/usr" -type d -exec chmod 755 {} +
    find "$stage/usr/share" -type f -exec chmod 644 {} +
    chmod 755 "$stage/usr/bin/gogitzip" "$stage/usr/bin/gogitzip-gtk"
    size=$(du -sk "$stage/usr" | cut -f1)
    # Ubuntu 24.04 / Debian 13 renamed the GTK library package (64-bit time_t transition)
    cat > "$stage/DEBIAN/control" <<EOF
Package: gogitzip
Version: $ver
Architecture: $arch
Maintainer: Butcherar project <NiSeullent@users.noreply.github.com>
Installed-Size: $size
Depends: libc6 (>= $glibc), libgtk-3-0 (>= 3.22) | libgtk-3-0t64
Section: utils
Priority: optional
Homepage: https://niseullent.github.io/Butcherar/
Description: lightweight, fast archive manager (고깃ZIP)
 GogitZIP opens, tests and extracts more than 50 archive, installer, disk
 image and file system formats (ZIP, 7z, RAR, ALZ, EGG, TAR, CAB, MSI, ISO,
 DMG, WIM, VHD, NTFS, SquashFS ...) and creates ZIP, 7z, TAR, GZIP, BZIP2,
 XZ, ZSTD and ISO files, with AES-256 encryption.
 .
 This package contains the GTK 3 application (gogitzip-gtk) and the command
 line tool (gogitzip).
EOF
    (cd "$stage" && find usr -type f | LC_ALL=C sort | xargs md5sum) > "$stage/DEBIAN/md5sums"
    chmod 644 "$stage/DEBIAN/control" "$stage/DEBIAN/md5sums"
    stamp "$stage"
    SOURCE_DATE_EPOCH=$epoch dpkg-deb --root-owner-group -Zxz --build "$stage" "$out/$name.deb" >/dev/null
    rm -rf "$stage"
    echo "$out/$name.deb"
    ;;
*)
    echo "usage: $0 tar|deb VERSION ARCH OUTDIR TREE" >&2
    exit 2
    ;;
esac
