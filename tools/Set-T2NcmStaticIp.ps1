#requires -RunAsAdministrator
# Set-T2NcmStaticIp.ps1
#
# Statically assigns 169.254.84.1/16 to the "Apple T2 USB NCM Network
# Adapter" interface (apple-t2-ncm.inf's AppleT2Ncm.DeviceDesc).
#
# WHY THIS EXISTS: T2NCM/driver/Tunnel.c's RX rewrite only has a real
# destination IPv4 once it has LEARNED the host's own address from an
# actual outbound tunnel frame (DeviceContext->TunnelLocalIpv4Valid) -
# until then it falls back to a hardcoded 169.254.84.1 (see driver.h's
# TunnelLocalIpv4 comment and Tunnel.c's own fallback block), which only
# works if that exact address is what the host is actually using. Right
# after a fresh install the adapter has NO IPv4 at all yet (Windows APIPA
# autoconfiguration is not instant, and this NCM link may not report
# media-connect promptly either) - so the very first Ipv4Tunnel connect
# attempt has nothing to bind/route from, is expected to fail, and the
# user has had to open Network Settings and add this address by hand
# (same instruction as the T2TouchIdBio GUI's own tunnel-mode message).
# This script automates exactly that one manual step at install time.
#
# Idempotent: safe to re-run (e.g. every InstallDriver.bat run) - does
# nothing if the address is already present, and does not disturb any
# OTHER address already on the adapter (in particular a real APIPA
# address the host may have picked up on its own in the meantime; the
# driver only needs a 169.254/16 address to exist, it does not care
# which one is used first).

[CmdletBinding()]
param(
    [string]$InterfaceDescriptionMatch = 'Apple T2 USB NCM*',
    [string]$StaticIp = '169.254.84.1',
    [int]$PrefixLength = 16,
    [int]$WaitSeconds = 30
)

$ErrorActionPreference = 'Stop'

# Best-effort: let the T2TouchIdBio UMDF host (LocalService) write the shared
# transport flag / last-known peer under HKLM\SOFTWARE\T2TouchId\Network (and
# the volatile Session subkey, which inherits this ACL). Without it those writes
# fail silently in the service. Never fatal.
try {
    $regPath = 'HKLM:\SOFTWARE\T2TouchId\Network'
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    # Create the PortCache subkey up front (inherits the ACL below) so the UMDF host's
    # first port save cannot fail with err 5 and leave every boot paying a full scan.
    foreach ($sub in 'PortCache') {
        $subPath = Join-Path $regPath $sub
        if (-not (Test-Path $subPath)) { New-Item -Path $subPath -Force | Out-Null }
    }
    $acl  = Get-Acl $regPath
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
        'NT AUTHORITY\LOCAL SERVICE', 'SetValue,CreateSubKey,Delete,ReadKey',
        'ContainerInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -Path $regPath -AclObject $acl
    Write-Host "Granted LocalService write access to $regPath"
} catch {
    Write-Warning "Could not set registry ACL on HKLM\SOFTWARE\T2TouchId\Network: $($_.Exception.Message)"
}

Write-Host "Waiting for '$InterfaceDescriptionMatch' to enumerate (up to ${WaitSeconds}s)..."
$adapter = $null
$deadline = (Get-Date).AddSeconds($WaitSeconds)
while ((Get-Date) -lt $deadline) {
    $adapter = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceDescription -like $InterfaceDescriptionMatch } |
        Select-Object -First 1
    if ($adapter) { break }
    Start-Sleep -Milliseconds 500
}

if (-not $adapter) {
    Write-Host "[WARNING] No adapter matching '$InterfaceDescriptionMatch' found within ${WaitSeconds}s."
    Write-Host "Skipping static IPv4 assignment - plug in / wake the T2 Mac side and re-run this script,"
    Write-Host "or add $StaticIp/$PrefixLength to the T2Ncm adapter manually in Network Settings."
    exit 0
}

Write-Host "Found adapter: $($adapter.Name) ($($adapter.InterfaceDescription)), ifIndex=$($adapter.ifIndex)"

$existing = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -eq $StaticIp }

if ($existing) {
    Write-Host "[OK] $StaticIp is already assigned to this adapter - nothing to do."
    exit 0
}

# Adapter may not have media-connect yet immediately after driver bind
# (no Mac plugged in / T2 asleep) - New-NetIPAddress still works on a
# disconnected interface in Windows, so this deliberately does not wait
# on link state, only on the adapter object existing.
try {
    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $StaticIp `
        -PrefixLength $PrefixLength -ErrorAction Stop | Out-Null
    Write-Host "[OK] Assigned $StaticIp/$PrefixLength to $($adapter.Name)."
} catch {
    Write-Host "[ERROR] Failed to assign $StaticIp/$PrefixLength to $($adapter.Name): $($_.Exception.Message)"
    Write-Host "Add it manually in Network Settings (same address the T2TouchIdBio GUI's tunnel-mode message recommends)."
    exit 1
}