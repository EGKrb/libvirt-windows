# libvirt for Windows (unofficial port)

[![build](https://github.com/EGKrb/libvirt-windows/actions/workflows/build.yml/badge.svg)](https://github.com/EGKrb/libvirt-windows/actions/workflows/build.yml)

[Français](README.fr.md) · [Site](https://egkrb.github.io/libvirt-windows/)

libvirt 12.9.0 built natively for Windows x64: `virsh`, the daemons
(`virtqemud`, `virtnetworkd`, `virtsecretd`, `libvirtd`…) and QEMU guests
accelerated by the Windows Hypervisor Platform (WHPX). This is libvirt's own
code with its platform layers ported, not a rewrite: the same API, domain and
network XML, `virsh` commands and RPC protocol.

> [!IMPORTANT]
> **Not an official libvirt release**, and not affiliated with the libvirt
> project. The Windows changes were written with an AI assistant; libvirt
> declines contributions that include AI-generated content
> ([docs/hacking.rst](docs/hacking.rst)), so **nothing here is to be submitted
> upstream**. Experimental software: try it on machines you can afford to
> break.

The history shows the port as a diff: the first commit is libvirt as
downloaded, the second one is the Windows port.

## Status

Tested on Windows 11 (build 26300) with Ubuntu 24.04 guests; TAP and Wintun
(below) in a Windows 11 26300 virtual machine with Alpine guests.

| Area | Works and tested | Not done or not tested |
| --- | --- | --- |
| Daemons | `libvirtd` and the modular daemons, `--daemon`, reload and stop (signals as named events), reconnection to running guests after a restart | Windows services |
| Remote | UNIX sockets, `ext` transport | `ssh` transport (implemented, untested), TLS |
| Secrets | define, set, get, undefine, persistence | |
| QEMU | `whpx` domain type; define, start, destroy, suspend, resume; `screenshot`; `qemu-monitor-command`; `virsh console` (serial on a UNIX socket); NIC hotplug; `setmem` (balloon, memory given back to the host with the [QEMU patch](windows/qemu)); `dommemstat` | save/restore, migration, snapshots, SMBIOS sysinfo |
| Guest networking | `type='user'` (libslirp); `type='network'` and `type='bridge'` to a libvirt network; `type='ethernet'` on a TAP-Windows adapter (created, named, addressed and deleted by libvirt; `domifstat`) | `type='ethernet'` with `managed='no'` (written, untested); bridges to the host LAN |
| Virtual networks | forward mode `nat` and isolated; DHCP and DHCPv6 (ranges, hosts by MAC, DUID or name); DNS (hosts, TXT, SRV, PTR, forwarders, local domain); IPv6 (SLAAC or DHCPv6); `net-update`; `net-dhcp-leases`; `domifaddr`; autostart; QoS (`domiftune`, floors, network bandwidth); `domifstat`; forward modes `route` and `open` (Wintun) | |
| Other drivers | | storage, nodedev, interface, nwfilter, LXC, VirtualBox |

## How it works

| On Linux | On this port |
| --- | --- |
| `fork` + `exec` | `CreateProcess` suspended, resumed after the handshake |
| Signals | named events `Local\libvirt-signal-PID-SIG`, console control handlers |
| UNIX sockets | AF_UNIX sockets of Windows 10 1803 and later |
| `/run` emptied at boot | autostart marks older than the boot ignored |
| Symbolic links | symbolic links, or without the privilege system files as Cygwin/MSYS2 make them |
| PTY consoles | QEMU serial on a UNIX socket, `virsh console` through the Windows console |
| KVM | WHPX (`<domain type='whpx'>`), TCG otherwise |
| Bridge, TAP, dnsmasq, iptables | `libvirt_netswitch`: one process per network, an Ethernet switch on a UNIX socket that QEMU joins with `-netdev stream`, libslirp for NAT, its own DHCP/DHCPv6/DNS, QoS by token buckets |
| `tc` | the switch shapes what a guest receives and polices what it sends |
| Replacing running binaries | renamed `NAME.busy-STAMP` by the install, removed by the next one |

## Requirements

- Windows 10 1803 or later, x64. For hardware acceleration, the *Windows
  Hypervisor Platform* optional feature.
- [MSYS2](https://www.msys2.org/), UCRT64 environment.
- QEMU for Windows with the patch in [windows/qemu](windows/qemu): without it
  WHPX crashes while libvirt probes QEMU.

## Build

From an MSYS2 UCRT64 shell:

```sh
git clone --recurse-submodules https://github.com/EGKrb/libvirt-windows
cd libvirt-windows
windows/build.sh deps     # MSYS2 packages
windows/build.sh          # configure, build, install into install/
```

`BUILD` and `PREFIX` change the build and install directories. The install
can run while daemons and networks run, and keeps edited configuration files
(the new version goes beside them as `NAME.new`).

## Run

The DLLs come from MSYS2: put `install\bin`, `C:\msys64\ucrt64\bin` and QEMU
on `PATH`, then from PowerShell:

```powershell
install\sbin\virtnetworkd.exe --daemon
install\sbin\virtqemud.exe --daemon
install\bin\virsh.exe -c qemu:///system net-list --all
install\bin\virsh.exe -c qemu:///system define guest.xml
install\bin\virsh.exe -c qemu:///system start guest
install\bin\virsh.exe -c qemu:///system console guest
```

A guest with WHPX, the default network and a serial console:

```xml
<domain type='whpx'>
  <name>guest</name>
  <memory unit='MiB'>2048</memory>
  <vcpu>2</vcpu>
  <os><type arch='x86_64' machine='q35'>hvm</type></os>
  <features><acpi/><apic/></features>
  <cpu mode='host-passthrough'/>
  <devices>
    <emulator>C:\Program Files\qemu\qemu-system-x86_64.exe</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='C:/vms/guest.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
    </interface>
    <serial type='unix'>
      <source mode='bind' path='C:/vms/guest-serial0.sock'/>
    </serial>
    <console type='unix'>
      <source mode='bind' path='C:/vms/guest-serial0.sock'/>
      <target type='serial'/>
    </console>
    <graphics type='vnc' port='-1' listen='127.0.0.1'/>
  </devices>
</domain>
```

A daemon is stopped by its SIGTERM event:

```powershell
$p = (Get-Content install\var\run\virtqemud.pid).Trim()
[System.Threading.EventWaitHandle]::OpenExisting("Local\libvirt-signal-$p-15").Set()
```

Configuration is in `install\etc\libvirt`, logs in `install\var\log\libvirt`
(a network's switch logs to `network\NAME.log`), run state in
`install\var\run\libvirt`.

### Networks

- `nat` and isolated networks work out of the box, as the `default` network.
  Guests reach the host's services by the gateway address (`192.168.122.1`).
- `route` and `open` need [Wintun](https://www.wintun.net): `wintun.dll`
  (amd64) beside `install\libexec\libvirt_netswitch.exe`, and administrator
  rights. The host then has a `virbr0` interface with the gateway address, as
  on Linux.
- `type='ethernet'` needs the TAP-Windows6 driver of OpenVPN (9.27 or later,
  hardware id `root	ap0901`) in the driver store
  (`pnputil /add-driver OemVista.inf /install`), and administrator rights:
  libvirt creates an adapter named after the interface (`vnet0`), gives it
  the `<source><ip/></source>` addresses and routes, and deletes it with the
  guest.
- The Windows firewall puts these TAP and Wintun interfaces in the Public
  profile: what a guest opens to the host (a ping included) is blocked until
  a rule allows it.

## Layout

- `windows/build.sh`: build script; `windows/qemu`: the QEMU patch;
  `windows/site`: the GitHub Pages site.
- `scripts/windows-install.py`: install over a running libvirt.
- `src/network/netswitch.c`: the switch of a virtual network.
- The rest is libvirt, with the Windows changes in place. Every change
  since upstream: `git diff $(git rev-list --max-parents=0 HEAD)`.

## License

As libvirt: the library under the LGPL 2.1 or later, some tools under the
GPL 2.0 or later; see [COPYING](COPYING) and [COPYING.LESSER](COPYING.LESSER).
libvirt is a project of the libvirt developers: <https://libvirt.org>.
