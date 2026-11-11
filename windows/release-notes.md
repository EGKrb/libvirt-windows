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

Daemons (modular and `libvirtd`), secrets, QEMU guests with WHPX (lifecycle, `virsh console`, screenshots, QMP, NIC hotplug, memory balloon, save/restore, dump, live migration), user networking, virtual networks (NAT, isolated, `route` and `open` through Wintun) with DHCP, DHCPv6, DNS, IPv6, QoS, statistics and Windows firewall rules, TAP-Windows interfaces and bridges to the host's LAN. The [status table](https://github.com/EGKrb/libvirt-windows#status) lists what is not done yet: storage, nodedev, snapshots, migration with storage copy.

New in 0.3.0, tested on Windows 11 26300:

- `virsh save`, `restore`, `managedsave` and `dump`, and live migration (`virsh migrate --live`, direct or `--p2p`) between libvirt instances. They need the updated [QEMU patch](https://github.com/EGKrb/libvirt-windows/tree/main/windows/qemu), which adds to WHPX what migration needs (dirty page tracking, the guest's Hyper-V and CPU state, the partition's clock). With it, guests use the local APIC timer rather than Hyper-V's synthetic timers, whose state cannot be saved.
- Bridges to the host's LAN: an `<interface type='bridge'>`, or a network `<forward mode='bridge'/>`, on a network bridge of Windows named as the bridge (`br0`) gets a TAP-Windows adapter that libvirt adds to the bridge and deletes with the guest. See the README for making the bridge.
- `<interface type='ethernet'>` with `<target dev='NAME' managed='no'/>`: an existing TAP-Windows adapter, used as it is and left after the guest.

Since 0.2.0: TAP-Windows interfaces, forward modes `route` and `open` through Wintun (`wintun.dll` in `libexec`), and Windows firewall rules as firewalld's `libvirt` zone. TAP-Windows and Wintun need the TAP-Windows6 driver of OpenVPN (9.27 or later) or `wintun.dll`, and administrator rights.
