# Makes the Linux VM of the LXC driver of libvirt for Windows (virtlxcd
# --setup): downloads Alpine Linux for the network boot, boots it in QEMU
# and installs it, with libvirt and its LXC driver, on the disk of the VM
# (lxc-vm-provision.sh), in LOCALSTATEDIR\lib\libvirt\lxc.
#
# SPDX-License-Identifier: LGPL-2.1-or-later

param(
    [string]$Qemu,
    [int]$DiskGB = 20,
    [int]$MemoryMB = 2048,
    [int]$Cpus = 2,
    [string]$Mirror = 'https://dl-cdn.alpinelinux.org/alpine',
    [string]$Release = 'latest-stable',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # much faster downloads
$prefix = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$state = Join-Path $prefix 'var\lib\libvirt\lxc'
$netboot = Join-Path $state 'netboot'
$disk = Join-Path $state 'lxcvm.qcow2'
$key = Join-Path $state 'id_ed25519'
New-Item -ItemType Directory -Force $netboot | Out-Null

if ((Test-Path $disk) -and -not $Force) {
    throw "$disk exists: the VM is made already (-Force makes it again)"
}

if (-not $Qemu) {
    $cmd = Get-Command qemu-system-x86_64.exe -ErrorAction SilentlyContinue
    if (-not $cmd) { throw 'qemu-system-x86_64.exe is not on PATH: give it with -Qemu' }
    $Qemu = $cmd.Source
}
$qemuImg = Join-Path (Split-Path $Qemu) 'qemu-img.exe'
$sshKeygen = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
if (-not (Test-Path $sshKeygen)) { throw 'ssh-keygen.exe (the OpenSSH client of Windows) is not there' }

# Alpine for the network boot
$url = "$Mirror/$Release/releases/x86_64/netboot"
foreach ($f in 'vmlinuz-virt', 'initramfs-virt', 'modloop-virt') {
    $out = Join-Path $netboot $f
    if ((Test-Path $out) -and -not $Force) { continue }
    Write-Host "downloading $url/$f"
    Invoke-WebRequest -UseBasicParsing -Uri "$url/$f" -OutFile $out
}

# the disk and the key of virtlxcd, readable by this user only
Remove-Item -Force $disk, $key, "$key.pub" -ErrorAction SilentlyContinue
& $qemuImg create -q -f qcow2 $disk "$($DiskGB)G"
if ($LASTEXITCODE) { throw 'qemu-img failed' }
& $sshKeygen -q -t ed25519 -N '""' -C libvirt-lxcvm -f $key
if ($LASTEXITCODE) { throw 'ssh-keygen failed' }
& icacls.exe $key /inheritance:r /grant:r "$($env:USERNAME):F" 'SYSTEM:F' '*S-1-5-32-544:F' | Out-Null

# the serial console of the VM on a port of this machine
$l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$l.Start(); $port = $l.LocalEndpoint.Port; $l.Stop()

$provision = Join-Path $PSScriptRoot 'lxc-vm-provision.sh'
$qargs = @(
    '-nodefaults', '-machine', 'q35', '-accel', 'whpx', '-accel', 'tcg',
    '-m', "$MemoryMB", '-smp', "$Cpus",
    '-kernel', (Join-Path $netboot 'vmlinuz-virt'),
    '-initrd', (Join-Path $netboot 'initramfs-virt'),
    '-append', "console=ttyS0 ip=dhcp alpine_repo=$Mirror/$Release/main modloop=$url/modloop-virt",
    '-drive', "file=$disk,if=virtio,format=qcow2",
    '-netdev', 'user,id=n0', '-device', 'virtio-net-pci,netdev=n0',
    '-device', 'virtio-rng-pci',
    '-fw_cfg', "name=opt/org.libvirt/key,file=$key.pub",
    '-fw_cfg', "name=opt/org.libvirt/mirror,string=$Mirror",
    '-fw_cfg', "name=opt/org.libvirt/release,string=$Release",
    '-fw_cfg', "name=opt/org.libvirt/provision,file=$provision",
    '-serial', "tcp:127.0.0.1:$($port),server=on,wait=on",
    '-display', 'none'
)
Write-Host "booting Alpine Linux in QEMU ($Qemu)"
$vm = Start-Process -PassThru -WindowStyle Hidden -FilePath $Qemu -ArgumentList ($qargs | ForEach-Object { if ($_ -match '[\s"]') { '"' + $_ + '"' } else { $_ } })

$client = $null
for ($i = 0; $i -lt 50 -and -not $client; $i++) {
    try { $client = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $port) } catch { Start-Sleep -Milliseconds 200 }
}
if (-not $client) { throw 'cannot reach the console of the VM' }
$stream = $client.GetStream()
$stream.ReadTimeout = 1000
$enc = [System.Text.Encoding]::UTF8
$text = [System.Text.StringBuilder]::new()
$buf = New-Object byte[] 65536
$log = Join-Path $prefix 'var\log\libvirt\lxc'
New-Item -ItemType Directory -Force $log | Out-Null
$logFile = Join-Path $log 'lxcvm-setup.log'

function Read-Until([string]$pattern, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if ($text.ToString() -match $pattern) { return $true }
        if ($vm.HasExited) { return $false }
        try {
            $n = $stream.Read($buf, 0, $buf.Length)
            if ($n -le 0) { return $false }
            $s = $enc.GetString($buf, 0, $n)
            [void]$text.Append($s)
            Add-Content -NoNewline -Path $logFile -Value $s
            Write-Host -NoNewline $s
        } catch [System.IO.IOException] { }
    }
    return $false
}
function Send-Line([string]$line) {
    $b = $enc.GetBytes("$line`n")
    $stream.Write($b, 0, $b.Length)
}

# the VM does not outlive a failure of this script
trap {
    if ($vm -and -not $vm.HasExited) { Stop-Process -Id $vm.Id -Force -ErrorAction SilentlyContinue }
    break
}

if (-not (Read-Until 'login:' 600)) { throw "Alpine did not boot (see $logFile)" }
Send-Line 'root'
if (-not (Read-Until ':~#' 60)) { throw "no shell (see $logFile)" }
[void]$text.Clear()
Send-Line 'modprobe qemu_fw_cfg && sh /sys/firmware/qemu_fw_cfg/by_name/opt/org.libvirt/provision/raw; echo LXCVM-RC=$?'
if (-not (Read-Until 'LXCVM-RC=\d+' 3600)) { throw "the installation did not end (see $logFile)" }
$out = $text.ToString()
$rc = [int]([regex]::Match($out, 'LXCVM-RC=(\d+)').Groups[1].Value)
$hostkey = [regex]::Match($out, 'lxcvm-hostkey: (ssh-ed25519 \S+)').Groups[1].Value
Send-Line 'poweroff'
$vm.WaitForExit(120000) | Out-Null
$client.Close()
if ($rc -ne 0 -or -not $hostkey) { throw "the installation failed (see $logFile)" }

# the host key of the VM, by the alias virtlxcd uses for it
Set-Content -Encoding ascii (Join-Path $state 'known_hosts') "libvirt-lxcvm $hostkey"
Set-Content -Encoding ascii (Join-Path $state 'lxcvm.conf') @"
[vm]
qemu=$($Qemu -replace '\\', '/')
memory=$MemoryMB
cpus=$Cpus
"@
Write-Host "`nThe VM of LXC is made: start sbin\virtlxcd.exe --daemon, then use lxc:///system"
