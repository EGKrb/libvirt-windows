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

Daemons (modular and `libvirtd`), secrets, remote access over UNIX sockets and SSH, QEMU guests with WHPX (lifecycle, `virsh console`, screenshots, QMP, NIC hotplug, memory balloon, save/restore, dump, snapshots, live migration with or without storage copy), user networking, virtual networks (NAT, isolated, `route` and `open` through Wintun) with DHCP, DHCPv6, DNS, IPv6, QoS and Windows firewall rules, TAP-Windows interfaces and bridges to the host's LAN, storage pools of directories, node devices. The [status table](https://github.com/EGKrb/libvirt-windows#status) lists what is not done yet.

New in 0.4.0, tested on Windows 11 26300:

- Storage driver (`virtstoraged`): pools of type `dir` and their volumes (raw, and qcow2 with `qemu-img`): create, clone, resize, upload, download, wipe, delete. A migration with `--copy-storage-all` now creates the destination disk in the pool that holds its path, as on Linux.
- Node device driver (`virtnodedevd`): `nodedev-list` and `nodedev-dumpxml` of the computer, PCI and USB devices, network interfaces and disks, under their parents in the device tree of Windows.
- Host information: `virsh sysinfo` and `<smbios mode='host'/>` from the SMBIOS table, the host UUID from it, `nodeinfo`, `nodecpustats`, `nodecpumap`, the host CPU model and its TSC frequency in `capabilities`.
- Snapshots (internal and external, with memory, revert, delete) and `--copy-storage-all` migrations, tested.
- Remote access over SSH: `qemu+ssh` (with the `ssh` of Windows or of MSYS2), `qemu+libssh` and `qemu+libssh2`, with `virt-ssh-helper` on the remote side.
- Fix: 64-bit unsigned values carried by the RPC protocol could read back wrong (MSYS2's XDR library sign-extended them), for example sizes of 2 GiB and more.

Since 0.3.0: save, restore, `managedsave`, `dump` and live migration with WHPX (with the [QEMU patch](https://github.com/EGKrb/libvirt-windows/tree/main/windows/qemu)), bridges to the host's LAN, `managed='no'` TAP adapters. Since 0.2.0: TAP-Windows interfaces, forward modes `route` and `open` through Wintun, Windows firewall rules.
