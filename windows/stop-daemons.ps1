# stop-daemons.ps1 PREFIX: stop the libvirt daemons and network switches
# that run from PREFIX, by their SIGTERM events (Local\libvirt-signal-PID-15)
#
# SPDX-License-Identifier: LGPL-2.1-or-later

param([Parameter(Mandatory)] [string] $Prefix)

$run = Join-Path $Prefix 'var\run'
$pidfiles = @(Get-ChildItem $run -Filter *.pid -File -ErrorAction SilentlyContinue) +
            @(Get-ChildItem (Join-Path $run 'libvirt\network') -Filter *.pid -File -ErrorAction SilentlyContinue)

foreach ($f in $pidfiles) {
    $p = (Get-Content $f.FullName -ErrorAction SilentlyContinue | Select-Object -First 1)
    if (-not $p) { continue }
    $p = $p.Trim()
    try {
        [System.Threading.EventWaitHandle]::OpenExisting("Local\libvirt-signal-$p-15").Set() | Out-Null
        "stopped $($f.BaseName) ($p)"
    } catch {
        # not running any more
    }
}
Start-Sleep 2
