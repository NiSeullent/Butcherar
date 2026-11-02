#!/bin/sh
# 고깃ZIP (GogitZIP) - install the prebuilt Linux package.
#
#   ./install.sh                 your account only: ~/.local (as root: /usr/local)
#   sudo ./install.sh --system   every user: /usr/local
#   ./install.sh --prefix DIR    anywhere (DIR/bin, DIR/share)
#
# Copies bin/ and share/ (programs, launcher, MIME types, icons, AppStream data) into
# the prefix, writes the list of installed files and an uninstaller to
# PREFIX/share/gogitzip/, then refreshes the MIME, launcher and icon caches.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
if [ "$(id -u)" = 0 ]; then prefix=/usr/local; else prefix=${HOME:?}/.local; fi

usage() {
    sed -n '2,9s/^# \{0,1\}//p' "$0"
    exit "$1"
}
while [ $# -gt 0 ]; do
    case $1 in
    --user) prefix=${HOME:?}/.local ;;
    --system) prefix=/usr/local ;;
    --prefix) [ $# -ge 2 ] || usage 2; prefix=$2; shift ;;
    --prefix=*) prefix=${1#--prefix=} ;;
    -h|--help) usage 0 ;;
    *) echo "install.sh: unknown option: $1" >&2; usage 2 ;;
    esac
    shift
done
case $prefix in /*) ;; *) prefix=$(pwd)/$prefix ;; esac
prefix=${prefix%/}

[ -x "$here/bin/gogitzip-gtk" ] || { echo "install.sh: run it from the unpacked GogitZIP folder" >&2; exit 1; }
if ! mkdir -p "$prefix/bin" "$prefix/share/gogitzip" 2>/dev/null || [ ! -w "$prefix/bin" ]; then
    echo "install.sh: cannot write to $prefix (for /usr/local: sudo ./install.sh --system)" >&2
    exit 1
fi

# GTK 3 is the only library the window needs besides the C library
if command -v ldconfig >/dev/null 2>&1 || [ -x /sbin/ldconfig ]; then
    if ! { ldconfig -p 2>/dev/null || /sbin/ldconfig -p 2>/dev/null; } | grep -q 'libgtk-3\.so\.0'; then
        echo "note: GTK 3 was not found. The command line tool works; for the window install it:"
        echo "      Debian/Ubuntu: sudo apt install libgtk-3-0   Fedora: sudo dnf install gtk3   Arch: sudo pacman -S gtk3"
    fi
fi

list=$prefix/share/gogitzip/installed-files.txt
tmp=$list.new
: > "$tmp"
cd "$here"
find bin share -type f | LC_ALL=C sort | while IFS= read -r f; do
    case $f in bin/*) mode=755 ;; *) mode=644 ;; esac
    mkdir -p "$prefix/$(dirname "$f")"
    if [ "$f" = share/applications/gogitzip.desktop ]; then
        # absolute program path: ~/.local/bin is often not on the desktop session's PATH
        exe=$prefix/bin/gogitzip-gtk
        case $exe in *' '*) exe="\"$exe\"" ;; esac
        sed -e "s|^Exec=gogitzip-gtk|Exec=$exe|" -e "s|^TryExec=gogitzip-gtk|TryExec=$prefix/bin/gogitzip-gtk|" \
            "$f" > "$prefix/$f.new"
        chmod "$mode" "$prefix/$f.new"
        mv -f "$prefix/$f.new" "$prefix/$f"
    else
        # replace instead of overwriting in place: a running program keeps its old file
        cp "$f" "$prefix/$f.new"
        chmod "$mode" "$prefix/$f.new"
        mv -f "$prefix/$f.new" "$prefix/$f"
    fi
    echo "$f" >> "$tmp"
done
cp "$here/uninstall.sh" "$prefix/share/gogitzip/uninstall.sh"
chmod 755 "$prefix/share/gogitzip/uninstall.sh"
echo share/gogitzip/uninstall.sh >> "$tmp"
echo share/gogitzip/installed-files.txt >> "$tmp"
mv -f "$tmp" "$list"

# refresh the caches when the tools exist (desktops pick the changes up anyway, later)
refresh() {    # TOOL DIR [OPTIONS...] -> TOOL OPTIONS DIR
    tool=$1 dir=$2
    shift 2
    command -v "$tool" >/dev/null 2>&1 || return 0
    [ -d "$dir" ] || return 0
    "$tool" "$@" "$dir" >/dev/null 2>&1 || true
}
refresh update-mime-database "$prefix/share/mime"
refresh update-desktop-database "$prefix/share/applications" -q
refresh gtk-update-icon-cache "$prefix/share/icons/hicolor" -q -t -f

echo "고깃ZIP was installed to $prefix"
echo "  window:       $prefix/bin/gogitzip-gtk (also in the applications menu)"
echo "  command line: $prefix/bin/gogitzip"
echo "  uninstall:    $prefix/share/gogitzip/uninstall.sh"
case ":${PATH:-}:" in
*":$prefix/bin:"*) ;;
*) echo "note: $prefix/bin is not on your PATH; add it to use 'gogitzip' in a terminal" ;;
esac
