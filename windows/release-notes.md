Unofficial port of libvirt 12.9.0 to Windows x64. **Not an official libvirt release**, not affiliated with the libvirt project; the Windows changes were written with an AI assistant and are not to be submitted upstream. Experimental software.

## Downloads

| File | Contents |
| --- | --- |
| `libvirt-windows-VERSION.zip` | Self-contained libvirt: `virsh`, the daemons, the network switch, with the MSYS2 DLLs they need, their licenses (`share/licenses`) and the list of their packages (`THIRD-PARTY.txt`). Nothing else to install. |
| `libvirt-windows-VERSION-third-party-sources.zip` | The MSYS2 source packages of those DLLs, as the (L)GPL asks. |
| `SHA256SUMS.txt` | Checksums. |

The source of libvirt itself is the repository at this tag (*Source code* below).

## Quick start

1. Extract the zip to a short path, such as `C:\libvirt` (UNIX socket paths are limited to 108 characters).
2. From PowerShell in that folder:

   ```powershell
   sbin\virtnetworkd.exe --daemon
   sbin\virtqemud.exe --daemon
   bin\virsh.exe -c qemu:///system net-list --all
   ```

3. Guests use `<domain type='whpx'>` and need QEMU for Windows with the patch in [windows/qemu](https://github.com/EGKrb/libvirt-windows/tree/main/windows/qemu); see the [README](https://github.com/EGKrb/libvirt-windows#run) for a complete example.

`.\stop-daemons.ps1 .` stops the daemons and network switches of the folder.

## What works

Daemons (modular and `libvirtd`), secrets, remote access over UNIX sockets, TLS and SSH, QEMU guests with WHPX (lifecycle, `virsh console`, screenshots, QMP, NIC hotplug, memory balloon, save/restore, dump, snapshots, live migration with or without storage copy), user networking, virtual networks (NAT, isolated, `route` and `open` through Wintun) with DHCP, DHCPv6, DNS, IPv6, QoS and Windows firewall rules, TAP-Windows interfaces and bridges to the host's LAN, network filters, storage pools of directories, volumes and shares, node devices, host interfaces, LXC in a Linux VM. The [status table](https://github.com/EGKrb/libvirt-windows#status) lists what is not done.

New in 0.6.0, tested on Windows 11 26300:

- NFS storage pools (`netfs` with source format `nfs`, NFS 3 and 4) without the Client for NFS of Windows, so on Windows Home too: `libvirt_nfsmount` mounts the export on the pool's directory with libnfs and [WinFsp](https://winfsp.dev), which must be installed. Tested against the nfsd of Linux: define, build, start, destroy, volumes created, resized, wiped, cloned, uploaded, downloaded and deleted, NFS 3 and 4. Without WinFsp, libvirt uses the Client for NFS of Windows as before.
- Fixes: `ftruncate` sets the end of a file in one call (it wrote zeros 4 KiB at a time), files on file systems of WinFsp are no longer taken for sockets.

New in 0.5.0:

- Network filters (`virtnwfilterd`): the filters of interfaces on a libvirt network (`clean-traffic`, your own) are applied by the network's switch, as ebtables/nftables apply them on Linux: every protocol and attribute of nwfilter, the chains and priorities, connection states (`ct state`, the replies of accepted connections), `reject`, filters changed on running guests, and the learning of the guest's IP address (`CTRL_IP_LEARNING` `any` and `dhcp`). Each interface now has its own socket on the switch, so that a guest cannot pass for another one by its MAC address.
- Host interfaces (`virtinterfaced`): `iface-list`, `iface-dumpxml` (a network bridge of Windows is a bridge with its members; IPv4 and IPv6 configuration), `iface-mac`, `iface-name`, `iface-start` and `iface-destroy`.
- Storage pools of type `netfs` (SMB shares) and `fs` (a volume mounted on the pool's directory, formatted by `pool-build --overwrite`); `find-storage-pool-sources` lists the shares of a host.
- LXC (`virtlxcd`): `lxc:///system` is the LXC driver of libvirt running in a small Alpine Linux VM under WHPX, which `virtlxcd --setup` makes once; same commands and XML as on Linux, the containers live in that VM.
- TLS (`qemu+tls://`), tested.
- Not possible: PCI passthrough needs Hyper-V's device assignment (`pcip.sys`), which Windows Home does not have.

Since 0.4.0: storage pools of directories, node devices, host information (SMBIOS, CPU, TSC), snapshots, SSH transports. Since 0.3.0: save, restore, `managedsave`, `dump` and live migration with WHPX (with the [QEMU patch](https://github.com/EGKrb/libvirt-windows/tree/main/windows/qemu)), bridges to the host's LAN, `managed='no'` TAP adapters. Since 0.2.0: TAP-Windows interfaces, forward modes `route` and `open` through Wintun, Windows firewall rules.
