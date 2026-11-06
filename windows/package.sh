#!/bin/bash
#
# The self-contained release of the Windows port, from an MSYS2 UCRT64 shell
# after windows/build.sh:
#
#   windows/package.sh VERSION [--sources]
#
# From the install in PREFIX (default: install/), it makes in DIST (default:
# dist/) libvirt-windows-VERSION.zip: libvirt with the MSYS2 DLLs it runs
# with, their licenses and the list of their packages.  With --sources, also
# libvirt-windows-VERSION-third-party-sources.zip: the MSYS2 source packages
# of those DLLs, for the (L)GPL ones among them.
#
# PREFIX should be a fresh install: the run state of daemons that ran from
# it (var/) is left out, but edited configuration files would go in.
#
# SPDX-License-Identifier: LGPL-2.1-or-later

set -e

SRC=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=${PREFIX:-$SRC/install}
DIST=${DIST:-$SRC/dist}
VERSION=$1
SOURCES=$2

if [ -z "$VERSION" ]; then
    echo "usage: $0 VERSION [--sources]" >&2
    exit 1
fi
if [ "$MSYSTEM" != UCRT64 ]; then
    echo "run this from an MSYS2 UCRT64 shell" >&2
    exit 1
fi

NAME=libvirt-windows-$VERSION
OUT=$DIST/$NAME
rm -rf "$OUT" "$DIST/$NAME.zip" "$DIST/$NAME-third-party-sources" \
       "$DIST/$NAME-third-party-sources.zip"
mkdir -p "$OUT"

# Runtime files only: no headers, import libraries, pkg-config files, run
# state, nor the files a running install renamed
# (links followed: they are written as emulated links below)
cp -rL --preserve=timestamps "$PREFIX/bin" "$PREFIX/sbin" "$PREFIX/libexec" \
      "$PREFIX/lib" "$PREFIX/etc" "$PREFIX/share" "$OUT/"
rm -rf "$OUT/lib/pkgconfig" "$OUT/share/doc"
# the directories of logs, state and sockets, as the install makes them,
# empty: the daemons expect them (a zip keeps empty directories)
(cd "$PREFIX" && find var -type d) | while read -r d; do mkdir -p "$OUT/$d"; done
find "$OUT" \( -name "*.a" -o -name "*.busy-*" -o -name "*.new" \) -delete
find "$OUT" \( -name "*.exe" -o -name "*.dll" \) -exec strip --strip-debug {} +

# Zip archives keep no symbolic links, and cp made copies of them: the
# links of the install (real ones, or emulated as libvirt and MSYS2 write
# them without the privilege) become emulated links again, relative so that
# they hold wherever the folder goes
python3 - "$PREFIX" "$OUT" <<'EOF'
import os, sys

prefix, out = sys.argv[1], sys.argv[2]
magic = b'!<symlink>\xff\xfe'

for top in ('bin', 'sbin', 'libexec', 'lib', 'etc', 'share'):
    for root, dirs, files in os.walk(os.path.join(prefix, top)):
        for name in files + dirs:
            path = os.path.join(root, name)
            target = None
            if os.path.islink(path):
                target = os.readlink(path)
            elif os.path.isfile(path) and os.path.getsize(path) <= 4096:
                with open(path, 'rb') as f:
                    data = f.read()
                if data.startswith(magic):
                    target = data[len(magic):].decode('utf-16-le').rstrip('\0')
            if target is None:
                continue
            if target.startswith('\\\\?\\'):
                target = target[4:]
            if os.path.isabs(target):
                target = os.path.relpath(target, root)
            dest = os.path.join(out, os.path.relpath(path, prefix))
            if os.path.isdir(dest) and not os.path.islink(dest):
                continue    # a link to a directory stays a copy
            if os.path.lexists(dest):
                os.remove(dest)
            with open(dest, 'wb') as f:
                f.write(magic + (target.replace('/', '\\') + '\0').encode('utf-16-le'))
            print('link', os.path.relpath(dest, out), '->', target)
EOF

# The DLLs of MSYS2 the binaries need, recursively
dlls=$(mktemp)
todo=$(find "$OUT" \( -name "*.exe" -o -name "*.dll" \))
while [ -n "$todo" ]; do
    next=""
    for f in $todo; do
        for d in $(objdump -p "$f" | awk '/DLL Name/ { print $3 }'); do
            if [ -f "/ucrt64/bin/$d" ] && ! grep -qix "$d" "$dlls"; then
                echo "$d" >> "$dlls"
                next="$next /ucrt64/bin/$d"
            fi
        done
    done
    todo=$next
done

# Windows looks for DLLs beside the program: each directory of programs
# gets them, with libvirt's own (relocation works from any of them)
for dir in bin sbin libexec; do
    for d in $(cat "$dlls"); do
        cp "/ucrt64/bin/$d" "$OUT/$dir/"
    done
    if [ "$dir" != bin ]; then
        cp "$OUT"/bin/libvirt*.dll "$OUT/$dir/"
    fi
done

# Their packages, licenses and sources
pkgs=$(for d in $(cat "$dlls"); do pacman -Qoq "/ucrt64/bin/$d"; done | sort -u)
third="$OUT/THIRD-PARTY.txt"
{
    echo "Third-party components: the DLLs beside the programs come from these"
    echo "MSYS2 packages (https://www.msys2.org), unmodified.  Their licenses are in"
    echo "share/licenses; the source of each package is published by MSYS2 as"
    echo "https://repo.msys2.org/mingw/sources/BASE-VERSION.src.tar.zst, and with"
    echo "each release of libvirt-windows as ...-third-party-sources.zip."
    echo
    printf '%-40s %-22s %-28s %s\n' PACKAGE VERSION BASE LICENSE
} > "$third"
srcdir=$DIST/$NAME-third-party-sources
for p in $pkgs; do
    ver=$(pacman -Q "$p" | awk '{ print $2 }')
    desc=/var/lib/pacman/local/$p-$ver/desc
    base=$(awk '/^%BASE%/ { getline; print }' "$desc")
    lic=$(awk '/^%LICENSE%/ { while ((getline l) > 0 && l != "") printf "%s ", l }' "$desc")
    printf '%-40s %-22s %-28s %s\n' "$p" "$ver" "${base:-$p}" "$lic" >> "$third"
    name=${p#mingw-w64-ucrt-x86_64-}
    mkdir -p "$OUT/share/licenses/$name"
    if [ -d "/ucrt64/share/licenses/$name" ]; then
        cp -r "/ucrt64/share/licenses/$name/." "$OUT/share/licenses/$name/"
    else
        # packages that keep their license with their documentation
        pacman -Qlq "$p" | grep -iE '/(COPYING|LICEN[CS]E|COPYRIGHT)[^/]*$' |
            while read -r f; do
                [ -f "$f" ] && cp "$f" "$OUT/share/licenses/$name/"
            done
    fi
    if [ "$SOURCES" = --sources ]; then
        mkdir -p "$srcdir"
        file="${base:-$p}-$ver.src.tar.zst"
        [ -f "$srcdir/$file" ] ||
            curl -sSfL -o "$srcdir/$file" "https://repo.msys2.org/mingw/sources/$file"
        # no license in the package: those of its upstream source
        if [ -z "$(ls -A "$OUT/share/licenses/$name")" ]; then
            tmp=$(mktemp -d)
            tar -C "$tmp" --zstd -xf "$srcdir/$file"
            for t in $(find "$tmp" -name "*.tar.*" -o -name "*.tgz"); do
                tar -C "$tmp" -xf "$t" --wildcards --no-anchored \
                    'COPYING*' 'LICENSE*' 'LICENCE*' 'COPYRIGHT*' 2>/dev/null || true
            done
            find "$tmp" -maxdepth 3 -type f \
                \( -iname 'COPYING*' -o -iname 'LICEN[CS]E*' -o -iname 'COPYRIGHT*' \) \
                -exec cp {} "$OUT/share/licenses/$name/" \;
            rm -rf "$tmp"
        fi
    fi
    if [ -z "$(ls -A "$OUT/share/licenses/$name")" ]; then
        echo "no license file for $p: package with --sources" >&2
        [ "$SOURCES" = --sources ] && exit 1
    fi
done
rm -f "$dlls"

cp "$SRC/COPYING" "$SRC/COPYING.LESSER" "$SRC/windows/stop-daemons.ps1" "$OUT/"
cp "$SRC/windows/package-README.txt" "$OUT/README.txt"
sed -i "s/@VERSION@/$VERSION/" "$OUT/README.txt"

cd "$DIST"
python3 -m zipfile -c "$NAME.zip" "$NAME"
if [ "$SOURCES" = --sources ]; then
    python3 -m zipfile -c "$NAME-third-party-sources.zip" "$NAME-third-party-sources"
fi
ls -l "$DIST"/*.zip
