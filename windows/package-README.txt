libvirt for Windows @VERSION@ (unofficial port of libvirt 12.9.0)
=================================================================

https://github.com/EGKrb/libvirt-windows

Not an official libvirt release, and not affiliated with the libvirt
project. The Windows changes were written with an AI assistant: nothing of
it is to be submitted to libvirt. Experimental software.

This folder is self-contained: the DLLs libvirt needs are beside its
programs, nothing else is to be installed, and it can be moved. Prefer a
short path such as C:\libvirt: libvirt's UNIX sockets live in it, and a
socket path has 108 characters at most (for a longer folder, libvirt uses
its 8.3 short name when the volume makes them).

Requirements
------------
- Windows 10 1803 or later, x64.
- For guests: QEMU for Windows with the patch of windows/qemu in the
  repository (without it WHPX crashes while libvirt probes QEMU), and the
  "Windows Hypervisor Platform" optional feature for hardware acceleration.
- Forward modes route and open of virtual networks: wintun.dll (amd64,
  https://www.wintun.net) in libexec, and administrator rights.
- Interfaces type='ethernet', and bridges to the host's LAN (a network
  bridge of Windows named as the libvirt bridge): the TAP-Windows6 driver of
  OpenVPN (9.27 or later) in the driver store, and administrator rights.
- The Windows firewall puts the TAP and Wintun interfaces in the Public
  profile. A route network (or open with zone='libvirt') gets the rules of
  firewalld's libvirt zone (ICMP, DHCP, DNS, SSH, TFTP from its subnets,
  group "libvirt"); anything else needs a rule of yours.

Start
-----
From PowerShell, in this folder:

    sbin\virtnetworkd.exe --daemon
    sbin\virtqemud.exe --daemon
    sbin\virtstoraged.exe --daemon
    sbin\virtnodedevd.exe --daemon
    sbin\virtinterfaced.exe --daemon
    sbin\virtnwfilterd.exe --daemon
    bin\virsh.exe -c qemu:///system net-list --all

The "default" network (NAT, 192.168.122.0/24) starts with virtnetworkd.
Storage pools are directories (pool type "dir"); a pool of the images,
which migrations with --copy-storage-all also create their disks in:

    bin\virsh.exe -c qemu:///system pool-define-as default dir --target C:\libvirt\var\lib\libvirt\images
    bin\virsh.exe -c qemu:///system pool-build default
    bin\virsh.exe -c qemu:///system pool-start default
    bin\virsh.exe -c qemu:///system pool-autostart default

Pools of type netfs link their target directory to a share (\\HOST\DIR),
pools of type fs mount a volume (E: or \\?\Volume{GUID}\) on it: both take
administrator rights (or the developer mode of Windows for netfs).

Network filters (nwfilter) apply to the interfaces of guests on a libvirt
network, enforced by its switch.

LXC: containers run in a small Alpine Linux VM. Once, with Internet access
(it downloads Alpine), then whenever LXC is wanted:

    sbin\virtlxcd.exe --setup -Qemu C:\path\to\qemu-system-x86_64.exe
    sbin\virtlxcd.exe --daemon
    bin\virsh.exe -c lxc:///system list --all

Domains use <domain type='whpx'>; see the README of the repository for a
complete example.

Stop
----
The daemons and network switches of this folder:

    .\stop-daemons.ps1 .

A daemon alone is stopped by its SIGTERM event:

    $p = (Get-Content var\run\virtqemud.pid).Trim()
    [System.Threading.EventWaitHandle]::OpenExisting("Local\libvirt-signal-$p-15").Set()

Files
-----
- etc\libvirt: configuration (networks in etc\libvirt\qemu\networks)
- var\log\libvirt: logs; a network's switch logs to network\NAME.log
- var\run\libvirt: run state, sockets, leases

License
-------
libvirt: the library under the LGPL 2.1 or later (COPYING.LESSER), some
tools under the GPL 2.0 or later (COPYING). The DLLs of other projects and
their licenses: THIRD-PARTY.txt and share\licenses.
