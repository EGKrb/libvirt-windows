#!/bin/sh
# Installs the Linux VM of the LXC driver of libvirt for Windows: run by
# lxc-vm-setup.ps1 in Alpine Linux booted from the network, it installs
# Alpine with libvirt and its LXC driver on the disk of the VM (/dev/vda),
# with the SSH key of virtlxcd, then powers the VM off.
#
# SPDX-License-Identifier: LGPL-2.1-or-later

set -e

cfg=/sys/firmware/qemu_fw_cfg/by_name/opt/org.libvirt
key=$(cat $cfg/key/raw)
mirror=$(cat $cfg/mirror/raw)
release=$(cat $cfg/release/raw)

echo "lxcvm: repositories $mirror/$release"
printf '%s/%s/main\n%s/%s/community\n' "$mirror" "$release" "$mirror" "$release" \
    > /etc/apk/repositories
apk update

setup-hostname -n lxcvm
cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

# libvirt with its LXC driver, and what virtlxcd reaches it with
apk add libvirt-daemon libvirt-lxc libvirt-client openssh socat \
    dbus iptables ip6tables dnsmasq e2fsprogs
for s in networking sshd cgroups dbus libvirtd; do
    rc-update add $s default
done
rc-update add devfs sysinit 2>/dev/null || true

# cgroups v2 for the containers
sed -i 's/^#*rc_cgroup_mode=.*/rc_cgroup_mode="unified"/' /etc/rc.conf

# SSH: the key of virtlxcd only
sed -i -e 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' \
       -e 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' \
       /etc/ssh/sshd_config
mkdir -p /root/.ssh
echo "$key" > /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

# the system on the disk, with the console on the serial port
export ERASE_DISKS=/dev/vda
export KERNELOPTS="console=ttyS0,115200 quiet"
export BOOTLOADER=syslinux
setup-disk -m sys -s 0 /dev/vda

# what setup-disk does not copy from the running system
root=/mnt/lxcvm
mkdir -p $root
mount /dev/vda2 $root
for d in dev proc sys; do
    mount --bind /$d $root/$d
done
mkdir -p $root/root/.ssh
cp /root/.ssh/authorized_keys $root/root/.ssh/
chmod 700 $root/root/.ssh
chmod 600 $root/root/.ssh/authorized_keys
cp /etc/ssh/sshd_config $root/etc/ssh/sshd_config
cp /etc/network/interfaces $root/etc/network/interfaces
cp /etc/rc.conf $root/etc/rc.conf
for s in networking sshd cgroups dbus libvirtd; do
    chroot $root rc-update add $s default >/dev/null 2>&1 || true
done
# the LXC driver mounts a FUSE file system in containers
grep -qx fuse $root/etc/modules || echo fuse >> $root/etc/modules

# the default network of libvirt, as libvirt-daemon-config-network makes
# it elsewhere (another subnet than the default network of Windows)
mkdir -p $root/etc/libvirt/qemu/networks/autostart
cat > $root/etc/libvirt/qemu/networks/default.xml <<EOF
<network>
  <name>default</name>
  <forward mode='nat'/>
  <bridge name='virbr0' stp='on' delay='0'/>
  <ip address='192.168.124.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.124.2' end='192.168.124.254'/>
    </dhcp>
  </ip>
</network>
EOF
ln -sf ../default.xml $root/etc/libvirt/qemu/networks/autostart/default.xml

# the host key, for the known_hosts of virtlxcd
chroot $root ssh-keygen -A >/dev/null
echo "lxcvm-hostkey: $(cat $root/etc/ssh/ssh_host_ed25519_key.pub)"
for d in sys proc dev; do
    umount $root/$d
done
umount $root

echo "lxcvm: installed"
