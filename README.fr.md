# libvirt pour Windows (portage non officiel)

[![build](https://github.com/EGKrb/libvirt-windows/actions/workflows/build.yml/badge.svg)](https://github.com/EGKrb/libvirt-windows/actions/workflows/build.yml)

[English](README.md) · [Site](https://egkrb.github.io/libvirt-windows/)

libvirt 12.9.0 compilé nativement pour Windows x64 : `virsh`, les démons
(`virtqemud`, `virtnetworkd`, `virtsecretd`, `libvirtd`…) et des invités QEMU
accélérés par la plateforme d'hyperviseur Windows (WHPX). C'est le code de
libvirt dont les couches système ont été portées, pas une réécriture : même
API, même XML de domaines et de réseaux, mêmes commandes `virsh`, même
protocole RPC.

> [!IMPORTANT]
> **Ce n'est pas une version officielle de libvirt**, et ce dépôt n'a aucun
> lien avec le projet libvirt. Les modifications pour Windows ont été écrites
> avec un assistant IA ; libvirt refuse les contributions qui contiennent du
> contenu généré par IA ([docs/hacking.rst](docs/hacking.rst)), donc **rien
> ici ne doit être proposé en amont**. Logiciel expérimental : à essayer sur
> des machines qu'on peut se permettre de casser.

L'historique présente le portage comme un diff : le premier commit est
libvirt tel que téléchargé, le second le portage Windows.

## État

Testé sous Windows 11 (build 26300) avec des invités Ubuntu 24.04.

| Domaine | Fonctionne et testé | Pas fait ou pas testé |
| --- | --- | --- |
| Démons | `libvirtd` et les démons modulaires, `--daemon`, rechargement et arrêt (signaux par événements nommés), reprise des invités après un redémarrage | services Windows |
| Accès distant | sockets UNIX, transport `ext` | transport `ssh` (écrit, non testé), TLS |
| Secrets | define, set, get, undefine, persistance | |
| QEMU | type de domaine `whpx` ; define, start, destroy, suspend, resume ; `screenshot` ; `qemu-monitor-command` ; `virsh console` (série sur socket UNIX) ; ajout et retrait de cartes à chaud ; `setmem` (ballon, mémoire rendue à l'hôte avec le [correctif QEMU](windows/qemu)) ; `dommemstat` | save/restore, migration, instantanés, sysinfo SMBIOS |
| Réseau des invités | `type='user'` (libslirp) ; `type='network'` et `type='bridge'` vers un réseau libvirt | `type='ethernet'` et ponts vers le réseau local de l'hôte (TAP, prévu) |
| Réseaux virtuels | modes `nat` et isolé ; DHCP et DHCPv6 (plages, réservations par MAC, DUID ou nom) ; DNS (hôtes, TXT, SRV, PTR, redirecteurs, domaine local) ; IPv6 (SLAAC ou DHCPv6) ; `net-update` ; `net-dhcp-leases` ; `domifaddr` ; autostart ; QoS (`domiftune`, floors, bande passante du réseau) ; `domifstat` | modes `route` et `open` (écrits, nécessitent Wintun, non testés) |
| Autres pilotes | | stockage, nodedev, interface, nwfilter, LXC, VirtualBox |

## Fonctionnement

| Sous Linux | Dans ce portage |
| --- | --- |
| `fork` + `exec` | `CreateProcess` suspendu, repris après la poignée de main |
| Signaux | événements nommés `Local\libvirt-signal-PID-SIG`, gestionnaires de contrôle console |
| Sockets UNIX | sockets AF_UNIX de Windows 10 1803 et suivants |
| `/run` vidé au démarrage | marques d'autostart antérieures au démarrage ignorées |
| Liens symboliques | liens symboliques, ou sans le privilège fichiers système comme ceux de Cygwin/MSYS2 |
| Consoles PTY | port série QEMU sur socket UNIX, `virsh console` par la console Windows |
| KVM | WHPX (`<domain type='whpx'>`), sinon TCG |
| Bridge, TAP, dnsmasq, iptables | `libvirt_netswitch` : un processus par réseau, switch Ethernet sur socket UNIX que QEMU rejoint par `-netdev stream`, libslirp pour le NAT, DHCP/DHCPv6/DNS intégrés, QoS par seaux à jetons |
| `tc` | le switch limite ce que reçoit un invité (file d'attente) et ce qu'il envoie (rejet) |
| Remplacer des binaires en cours d'exécution | renommés `NOM.busy-HORODATAGE` par l'installation, supprimés par la suivante |

## Prérequis

- Windows 10 1803 ou suivant, x64. Pour l'accélération matérielle, la
  fonctionnalité facultative *Plateforme de l'hyperviseur Windows*.
- [MSYS2](https://www.msys2.org/), environnement UCRT64.
- QEMU pour Windows avec le correctif de [windows/qemu](windows/qemu) : sans
  lui, WHPX plante quand libvirt sonde QEMU.

## Compilation

Depuis un shell MSYS2 UCRT64 :

```sh
git clone --recurse-submodules https://github.com/EGKrb/libvirt-windows
cd libvirt-windows
windows/build.sh deps     # paquets MSYS2
windows/build.sh          # configuration, compilation, installation dans install/
```

`BUILD` et `PREFIX` changent les dossiers de compilation et d'installation.
L'installation peut se faire pendant que démons et réseaux tournent, et garde
les fichiers de configuration modifiés (la nouvelle version est posée à côté,
en `NOM.new`).

## Utilisation

Les DLL viennent de MSYS2 : mettre `install\bin`, `C:\msys64\ucrt64\bin` et
QEMU dans le `PATH`, puis depuis PowerShell :

```powershell
install\sbin\virtnetworkd.exe --daemon
install\sbin\virtqemud.exe --daemon
install\bin\virsh.exe -c qemu:///system net-list --all
install\bin\virsh.exe -c qemu:///system define invite.xml
install\bin\virsh.exe -c qemu:///system start invite
install\bin\virsh.exe -c qemu:///system console invite
```

Un invité avec WHPX, le réseau par défaut et une console série :

```xml
<domain type='whpx'>
  <name>invite</name>
  <memory unit='MiB'>2048</memory>
  <vcpu>2</vcpu>
  <os><type arch='x86_64' machine='q35'>hvm</type></os>
  <features><acpi/><apic/></features>
  <cpu mode='host-passthrough'/>
  <devices>
    <emulator>C:\Program Files\qemu\qemu-system-x86_64.exe</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='C:/vms/invite.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
    </interface>
    <serial type='unix'>
      <source mode='bind' path='C:/vms/invite-serial0.sock'/>
    </serial>
    <console type='unix'>
      <source mode='bind' path='C:/vms/invite-serial0.sock'/>
      <target type='serial'/>
    </console>
    <graphics type='vnc' port='-1' listen='127.0.0.1'/>
  </devices>
</domain>
```

On arrête un démon par son événement SIGTERM :

```powershell
$p = (Get-Content install\var\run\virtqemud.pid).Trim()
[System.Threading.EventWaitHandle]::OpenExisting("Local\libvirt-signal-$p-15").Set()
```

La configuration est dans `install\etc\libvirt`, les journaux dans
`install\var\log\libvirt` (le switch d'un réseau écrit dans
`network\NOM.log`), l'état d'exécution dans `install\var\run\libvirt`.

### Réseaux

- Les réseaux `nat` et isolés fonctionnent directement, comme le réseau
  `default`. Les invités joignent les services de l'hôte par l'adresse de la
  passerelle (`192.168.122.1`).
- `route` et `open` nécessitent [Wintun](https://www.wintun.net) :
  `wintun.dll` (amd64) à côté de `install\libexec\libvirt_netswitch.exe`, et
  les droits administrateur. L'hôte a alors une interface `virbr0` avec
  l'adresse de la passerelle, comme sous Linux.

## Organisation

- `windows/build.sh` : script de compilation ; `windows/qemu` : le correctif
  QEMU ; `windows/site` : le site GitHub Pages.
- `scripts/windows-install.py` : installation par-dessus un libvirt en cours
  d'exécution.
- `src/network/netswitch.c` : le switch d'un réseau virtuel.
- Le reste est libvirt, avec les modifications pour Windows en place. Toutes
  les modifications depuis l'amont :
  `git diff $(git rev-list --max-parents=0 HEAD)`.

## Licence

Celle de libvirt : la bibliothèque sous LGPL 2.1 ou ultérieure, certains
outils sous GPL 2.0 ou ultérieure ; voir [COPYING](COPYING) et
[COPYING.LESSER](COPYING.LESSER). libvirt est un projet des développeurs de
libvirt : <https://libvirt.org>.
