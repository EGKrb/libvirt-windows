#!/usr/bin/env python3

import os
import sys

destdir = os.environ.get('DESTDIR', os.sep)

for dirname in sys.argv[1:]:
    if 'DESTDIR' in os.environ:
        # a Windows path keeps its drive, which would discard DESTDIR
        dirname = os.path.splitdrive(dirname)[1]
    os.makedirs(os.path.join(destdir, dirname.lstrip('/\\')), exist_ok=True)
