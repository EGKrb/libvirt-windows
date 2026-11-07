#!/usr/bin/env python3

import os
import sys

destdir = os.environ.get('DESTDIR', os.sep)
dirname = sys.argv[1]
target = sys.argv[2]
link = sys.argv[3]

if 'DESTDIR' in os.environ:
    # a Windows path keeps its drive, which would discard DESTDIR
    dirname = os.path.splitdrive(dirname)[1]
workdir = os.path.join(destdir, dirname.lstrip('/\\'))

os.makedirs(workdir, exist_ok=True)
os.chdir(workdir)

if os.path.lexists(link):
    os.remove(link)

if os.name == 'nt':
    # Windows does not resolve a relative link target written with '/'
    # (and os.sep is '/' in the Python of MSYS2)
    target = target.replace('/', '\\')

try:
    os.symlink(target, link)
except OSError:
    if os.name != 'nt':
        raise
    # Windows without the privilege of symbolic links: the link libvirt
    # (virWin32Symlink) and Cygwin/MSYS2 emulate, a system file
    import ctypes
    with open(link, 'wb') as f:
        f.write(b'!<symlink>\xff\xfe' + (target + '\0').encode('utf-16-le'))
    if not ctypes.windll.kernel32.SetFileAttributesW(os.path.abspath(link), 0x4):
        raise
