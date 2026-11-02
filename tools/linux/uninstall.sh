#!/bin/sh
# 고깃ZIP (GogitZIP) - remove what install.sh installed.
#
#   PREFIX/share/gogitzip/uninstall.sh    (copied there by install.sh: knows its prefix)
#   ./uninstall.sh [--user | --system | --prefix DIR]   from the unpacked package
#
# Only the files listed in PREFIX/share/gogitzip/installed-files.txt (or, without that
# list, the files this package contains) are removed; then the caches are refreshed.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
prefix=
if [ -f "$here/installed-files.txt" ]; then
    prefix=$(cd "$here/../.." && pwd)
elif [ "$(id -u)" = 0 ]; then
    prefix=/usr/local
else
    prefix=${HOME:?}/.local
fi

usage() {
    sed -n '2,8s/^# \{0,1\}//p' "$0"
    exit "$1"
}
while [ $# -gt 0 ]; do
    case $1 in
    --user) prefix=${HOME:?}/.local ;;
    --system) prefix=/usr/local ;;
    --prefix) [ $# -ge 2 ] || usage 2; prefix=$2; shift ;;
    --prefix=*) prefix=${1#--prefix=} ;;
    -h|--help) usage 0 ;;
    *) echo "uninstall.sh: unknown option: $1" >&2; usage 2 ;;
    esac
    shift
done
case $prefix in /*) ;; *) prefix=$(pwd)/$prefix ;; esac
prefix=${prefix%/}

list=$prefix/share/gogitzip/installed-files.txt
if [ -f "$list" ]; then
    files=$(cat "$list")
elif [ -d "$here/bin" ] && [ -d "$here/share" ]; then
    files=$(cd "$here" && find bin share -type f)
else
    echo "uninstall.sh: nothing to remove in $prefix" >&2
    exit 1
fi
[ -e "$prefix/bin/gogitzip-gtk" ] || [ -f "$list" ] || { echo "uninstall.sh: 고깃ZIP is not installed in $prefix" >&2; exit 1; }

# a plain relative path inside the prefix only ("bin/x", "share/..."), never "../"
echo "$files" | while IFS= read -r f; do
    case $f in
    ''|/*|*..*) continue ;;
    bin/*|share/*) rm -f "$prefix/$f" ;;
    esac
done
rmdir "$prefix/share/gogitzip" 2>/dev/null || true

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

echo "고깃ZIP was removed from $prefix"
