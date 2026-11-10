# SPDX-License-Identifier: GPL-2.0-only
# Test-T2DriversCurrent.ps1 - are the drivers in this package exactly the ones that
# are installed and running? Used by Setup so that an update that only changes the
# control panel does not reinstall the drivers (and does not need a restart).
#
#   powershell -ExecutionPolicy Bypass -File Test-T2DriversCurrent.ps1 -PackageDir <dir>
#
# Exit code: 0 = all five driver packages are installed with this package's
# DriverVer AND every T2 device using them is started without a problem code;
# 1 = something differs (reinstall); 2 = could not tell (reinstall).
# CI stamps every build with its own DriverVer (date.time), so an equal version is
# the same build. Read-only.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackageDir
)

$ErrorActionPreference = 'Stop'

$packages = [ordered]@{
    'T2TouchIdTransport.inf'     = 'SEP'
    'apple-t2-composite.inf'     = 'NCM'
    'apple-t2-ncm.inf'           = 'NCM'
    'apple-t2-ncm-ctrl-stub.inf' = 'NCM'
    'T2TouchIdBio.inf'           = 'Bio'
}

function Get-InfDriverVersion {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $line = Select-String -LiteralPath $Path -Pattern '^\s*DriverVer\s*=' | Select-Object -First 1
    if (-not $line) { return $null }
    # DriverVer = mm/dd/yyyy,w.x.y.z [; comment]
    $value = ($line.Line -split '=', 2)[1]
    $value = ($value -split ';', 2)[0]
    $parts = $value -split ','
    if ($parts.Count -lt 2) { return $null }
    return $parts[1].Trim()
}

try {
    $installed = @{}
    foreach ($d in Get-WindowsDriver -Online) {
        $name = ($d.OriginalFileName -split '[\\/]')[-1]
        if ($packages.Contains($name)) {
            if (-not $installed.ContainsKey($name)) { $installed[$name] = @() }
            $installed[$name] += $d
        }
    }

    foreach ($inf in $packages.Keys) {
        $want = Get-InfDriverVersion (Join-Path (Join-Path $PackageDir $packages[$inf]) $inf)
        if (-not $want) {
            Write-Output "$inf : no DriverVer in the package - cannot tell"
            exit 2
        }
        $have = @()
        if ($installed.ContainsKey($inf)) { $have = @($installed[$inf] | ForEach-Object { $_.Version }) }
        if ($have.Count -eq 0) {
            Write-Output "$inf : not installed (package $want)"
            exit 1
        }
        if ($have.Count -ne 1 -or $have[0] -ne $want) {
            Write-Output "$inf : installed $($have -join ', '), package $want"
            exit 1
        }
        Write-Output "$inf : $want (same)"
    }

    # Same packages - but are they actually working? A device in an error state is
    # exactly what a reinstall is for.
    $devices = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object {
        $_.InstanceId -like 'PCI\VEN_106B&DEV_1802*' -or
        $_.InstanceId -like 'ROOT\BIOMETRIC\*' -or
        $_.FriendlyName -like '*T2*NCM*'
    })
    foreach ($dev in $devices) {
        if ($dev.Status -ne 'OK') {
            $code = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction SilentlyContinue).Data
            Write-Output "$($dev.InstanceId) : status $($dev.Status), problem code $code"
            exit 1
        }
    }
    $svc = Get-Service -Name 'T2SepBootstrap' -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Output 'T2SepBootstrap : service missing'
        exit 1
    }
    Write-Output "all driver packages current, $($devices.Count) device(s) OK"
    exit 0
} catch {
    Write-Output "could not tell: $($_.Exception.Message)"
    exit 2
}
