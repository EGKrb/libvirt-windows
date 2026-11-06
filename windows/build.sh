#!/bin/bash
#
# Build and install the Windows port of libvirt, from an MSYS2 UCRT64 shell.
#
#   windows/build.sh deps      install the MSYS2 packages it needs
#   windows/build.sh           configure (once), build and install
#
# BUILD (default: build/) and PREFIX (default: install/) are relative to the
# source tree unless absolute.  The install goes over running daemons and
# networks and keeps edited configuration files (scripts/windows-install.py).
#
# SPDX-License-Identifier: LGPL-2.1-or-later

set -e

SRC=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$SRC/build}
PREFIX=${PREFIX:-$SRC/install}

PACKAGES="
  mingw-w64-ucrt-x86_64-gcc
  mingw-w64-ucrt-x86_64-meson
  mingw-w64-ucrt-x86_64-ninja
  mingw-w64-ucrt-x86_64-pkgconf
  mingw-w64-ucrt-x86_64-python
  mingw-w64-ucrt-x86_64-python-docutils
  mingw-w64-ucrt-x86_64-dlfcn
  mingw-w64-ucrt-x86_64-gettext-runtime
  mingw-w64-ucrt-x86_64-glib2
  mingw-w64-ucrt-x86_64-gnutls
  mingw-w64-ucrt-x86_64-libxml2
  mingw-w64-ucrt-x86_64-libxslt
  mingw-w64-ucrt-x86_64-portablexdr
  mingw-w64-ucrt-x86_64-json-c
  mingw-w64-ucrt-x86_64-curl
  mingw-w64-ucrt-x86_64-cyrus-sasl
  mingw-w64-ucrt-x86_64-libssh
  mingw-w64-ucrt-x86_64-libssh2
  mingw-w64-ucrt-x86_64-readline
  mingw-w64-ucrt-x86_64-libslirp
  gettext
  perl
  git
"

if [ "$1" = deps ]; then
    # shellcheck disable=SC2086
    pacman -S --needed --noconfirm $PACKAGES
    exit 0
fi

if [ "$MSYSTEM" != UCRT64 ]; then
    echo "run this from an MSYS2 UCRT64 shell" >&2
    exit 1
fi

cd "$SRC"
if [ ! -f subprojects/keycodemapdb/meson.build ]; then
    git submodule update --init subprojects/keycodemapdb
fi

if [ ! -f "$BUILD/build.ninja" ]; then
    meson setup "$BUILD" \
        --prefix="$(cygpath -m "$PREFIX")" \
        -Ddocs=disabled \
        -Dtests=disabled \
        -Dwerror=false \
        -Dgit_werror=disabled \
        -Ddriver_libvirtd=enabled \
        -Ddriver_qemu=enabled \
        -Ddriver_network=enabled \
        -Ddriver_secret=enabled \
        -Ddriver_storage=disabled \
        -Ddriver_vbox=disabled
fi

ninja -C "$BUILD"
python3 scripts/windows-install.py "$BUILD"
