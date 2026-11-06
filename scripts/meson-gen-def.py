#!/usr/bin/env python3

import re
import sys

if len(sys.argv) != 3:
    print('invalid arguments')
    print('usage: {0} INPUT OUTPUT'.format(sys.argv[0]))
    sys.exit(1)

infilepath = sys.argv[1]
outfilepath = sys.argv[2]

with open(infilepath) as f:
    text = f.read()

text = re.sub(r'^(|.*[#:}*].*|LIBVIRT_.*)\n?', '', text, flags=re.M)
text = re.sub(r'\n$', '', text)
text = re.sub(r'^[ ]*(.*);', r'    \1', text, flags=re.M)

# Exported variables: the import library must not give them a code thunk,
# or the DLLs and modules using them without dllimport (libvirt-qemu,
# libvirt-lxc, libvirt-admin, driver modules) read the thunk as their value.
# Functions named like them exist (virObjectIsClass), hence an explicit list.
data_symbols = {
    'virConnectAuthPtrDefault',
    'virConnectClass',
    'virConnectCloseCallbackDataClass',
    'virDomainCheckpointClass',
    'virDomainClass',
    'virDomainSnapshotClass',
    'virHostMemSetParametersValidation',
    'virInitctlFifos',
    'virInterfaceClass',
    'virNetworkClass',
    'virNetworkPortClass',
    'virNodeDeviceClass',
    'virNWFilterBindingClass',
    'virNWFilterClass',
    'virSecretClass',
    'virStoragePoolClass',
    'virStorageVolClass',
    'virStreamClass',
}
text = re.sub(r'^    (\w+)$',
              lambda m: m.group(0) + (' DATA' if m.group(1) in data_symbols else ''),
              text, flags=re.M)

with open(outfilepath, 'w') as f:
    f.write('EXPORTS\n')
    f.write(text)
