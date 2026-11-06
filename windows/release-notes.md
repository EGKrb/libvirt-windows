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

`windows\stop-daemons.ps1` of the repository stops the daemons and network switches of a folder.

## What works

Daemons (modular and `libvirtd`), secrets, QEMU guests with WHPX (lifecycle, `virsh console`, screenshots, QMP, NIC hotplug, memory balloon), user networking, virtual networks in NAT and isolated modes with DHCP, DHCPv6, DNS, IPv6, QoS and statistics. The [status table](https://github.com/EGKrb/libvirt-windows#status) lists what is not done yet: storage, nodedev, migration, TAP devices, and the route and open forward modes (written, untested).
