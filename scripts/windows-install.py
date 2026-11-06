#!/usr/bin/env python3
#
# windows-install.py BUILDDIR: "meson install" for Windows, which an install
# over a running libvirt and edited configuration files do not break.
#
# - Windows refuses to replace an executable or a DLL that a process runs
#   (a network switch, a daemon, a guest's helper), but lets it be renamed:
#   such a file is renamed to NAME.busy-STAMP, its process keeps running the
#   old code, as on Linux it keeps the deleted inode, and the next start
#   uses the new one.  Those files are removed by a later install, once
#   nothing runs them.
# - The files under the configuration directory are kept when they exist,
#   as packages install them (%config(noreplace)): the new version of an
#   edited file is put beside it as NAME.new, like an .rpmnew.
#
# SPDX-License-Identifier: LGPL-2.1-or-later

import json
import os
import shutil
import subprocess
import sys
import time


def meson():
    return shutil.which('meson') or 'meson'


def is_busy(path):
    try:
        with open(path, 'r+b'):
            return False
    except PermissionError:
        return True
    except OSError:
        return False


def remove_stale(dirs):
    for d in dirs:
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for name in names:
            if '.busy-' in name:
                try:
                    os.remove(os.path.join(d, name))
                except OSError:
                    pass    # still running


def main():
    builddir = sys.argv[1]
    installed = json.loads(subprocess.check_output(
        [meson(), 'introspect', builddir, '--installed'], text=True))
    options = {o['name']: o['value'] for o in json.loads(subprocess.check_output(
        [meson(), 'introspect', builddir, '--buildoptions'], text=True))}
    destdir = os.environ.get('DESTDIR', '')
    confdir = os.path.normcase(os.path.normpath(
        destdir + os.path.join(options['prefix'], options['sysconfdir'])))

    stamp = time.strftime('%Y%m%d%H%M%S')
    backupdir = os.path.join(builddir, 'windows-install-backup')
    shutil.rmtree(backupdir, ignore_errors=True)
    os.makedirs(backupdir)

    dests = sorted(set(os.path.normpath(destdir + d) for d in installed.values()))
    remove_stale(set(os.path.dirname(d) for d in dests))

    before = set()
    for root, _, names in os.walk(confdir):
        before.update(os.path.normcase(os.path.join(root, n)) for n in names)

    kept = {}
    for dest in dests:
        if not os.path.exists(dest):
            continue
        if os.path.normcase(dest).startswith(confdir + os.sep):
            backup = os.path.join(backupdir, str(len(kept)))
            shutil.copy2(dest, backup)
            kept[dest] = backup
        elif is_busy(dest):
            busy = '%s.busy-%s' % (dest, stamp)
            os.replace(dest, busy)
            print('in use, renamed: %s' % busy)

    rc = subprocess.call([meson(), 'install', '--no-rebuild', '-C', builddir])

    for dest, backup in kept.items():
        new = dest + '.new'
        with open(backup, 'rb') as f:
            old_data = f.read()
        try:
            with open(dest, 'rb') as f:
                new_data = f.read()
        except OSError:
            new_data = None
        if new_data is not None and new_data != old_data:
            with open(new, 'wb') as f:
                f.write(new_data)
            print('kept %s, new version in %s' % (dest, new))
        elif os.path.exists(new):
            os.remove(new)
        os.replace(backup, dest)

    # an autostart link is made with its configuration (the default network)
    # by the first install only: a configuration kept had its autostart
    # turned off if the link was gone
    keptconf = set(os.path.normcase(d) for d in kept)
    for root, _, names in os.walk(confdir):
        if os.path.basename(root) != 'autostart':
            continue
        for n in names:
            link = os.path.join(root, n)
            conf = os.path.normcase(os.path.join(os.path.dirname(root), n))
            if os.path.normcase(link) not in before and conf in keptconf:
                os.remove(link)
                print('autostart left off: %s' % link)

    shutil.rmtree(backupdir, ignore_errors=True)
    return rc


if __name__ == '__main__':
    sys.exit(main())
