[CmdletBinding()]
param(
    [ValidateSet('Apply', 'Undo')]
    [string]$Action = 'Apply',

    [string]$BackupPath,

    # Opt-in: also enable the Microsoft-Windows-Biometrics/Analytic event
    # channel (8 MB) so the very first sign-in after the next restart is
    # captured. Off by default - the installer must not leave a verbose
    # diagnostic channel switched on. Collect-T2TouchIdFirstBootEvidence.ps1
    # turns it off again.
    [switch]$EnableAnalyticLog
)

$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-StringArrayValue {
    param($Value)
    if ($null -eq $Value) { return @() }
    return @($Value | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

if (-not (Test-Administrator)) {
    throw 'Open PowerShell as Administrator. No configuration was changed.'
}

$wbioKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\WbioSrvc'
$bootstrapKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\T2SepBootstrap'
$backupRoot = Join-Path $PSScriptRoot 'rollback'

if ($Action -eq 'Undo') {
    if ([string]::IsNullOrWhiteSpace($BackupPath)) {
        throw 'Specify the backup file printed when Apply completed. No configuration was changed.'
    }
    if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
        throw "Backup file was not found: $BackupPath. No configuration was changed."
    }

    $backup = Get-Content -LiteralPath $BackupPath -Raw | ConvertFrom-Json
    if ($backup.Service -ne 'WbioSrvc' -or $backup.DependencyAdded -ne 'T2SepBootstrap') {
        throw 'This is not a T2TouchIdBio WbioSrvc dependency backup. No configuration was changed.'
    }

    if ([bool]$backup.DependOnServiceExisted) {
        $restore = Get-StringArrayValue $backup.DependOnService
        Set-ItemProperty -LiteralPath $wbioKey -Name DependOnService -Type MultiString -Value $restore
    } else {
        Remove-ItemProperty -LiteralPath $wbioKey -Name DependOnService -ErrorAction SilentlyContinue
    }

    Write-Host 'Restored the original WbioSrvc service dependency configuration.'
    Write-Host 'Restart Windows once for the restored startup order to take effect.'
    exit 0
}

if (-not (Test-Path -LiteralPath $bootstrapKey)) {
    throw 'T2SepBootstrap is not installed. No configuration was changed.'
}

$bootstrap = Get-CimInstance Win32_Service -Filter "Name='T2SepBootstrap'" -ErrorAction Stop
if ($null -eq $bootstrap -or $bootstrap.StartMode -eq 'Disabled') {
    throw 'T2SepBootstrap is unavailable or disabled. No configuration was changed.'
}

$bootstrapDependencies = Get-StringArrayValue (Get-ItemProperty -LiteralPath $bootstrapKey -Name DependOnService -ErrorAction SilentlyContinue).DependOnService
if ($bootstrapDependencies -contains 'WbioSrvc') {
    throw 'T2SepBootstrap already depends on WbioSrvc. Adding the reverse dependency would create a startup cycle, so nothing was changed.'
}

$wbioItem = Get-Item -LiteralPath $wbioKey
$existingValue = $wbioItem.GetValue('DependOnService', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
$existing = @(Get-StringArrayValue $existingValue)
# Keep this as an array even when WbioSrvc currently has only RpcSs. PowerShell
# otherwise uses string concatenation and would turn two service names into one
# invalid name such as "RpcSsT2SepBootstrap".
$desired = [string[]]@((@($existing) + @('T2SepBootstrap')) | Select-Object -Unique)

if ($existing -contains 'T2SepBootstrap') {
    Write-Host 'WbioSrvc already depends on T2SepBootstrap. No configuration was changed.'
    Write-Host 'Restart Windows once before testing the first sign-in.'
    exit 0
}

New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupFile = Join-Path $backupRoot "T2TouchIdBio-WbioSrvc-dependency-$stamp.json"
[ordered]@{
    Created = Get-Date -Format o
    Service = 'WbioSrvc'
    DependencyAdded = 'T2SepBootstrap'
    DependOnServiceExisted = ($null -ne $existingValue)
    DependOnService = @($existing)
    BootstrapStartMode = $bootstrap.StartMode
    BootstrapState = $bootstrap.State
} | ConvertTo-Json | Set-Content -LiteralPath $backupFile -Encoding UTF8

Set-ItemProperty -LiteralPath $wbioKey -Name DependOnService -Type MultiString -Value $desired
$appliedRaw = (Get-Item -LiteralPath $wbioKey).GetValue('DependOnService', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
$applied = @(Get-StringArrayValue $appliedRaw)
if ($applied -notcontains 'T2SepBootstrap') {
    throw "The dependency could not be verified. Restore file: $backupFile"
}

if ($EnableAnalyticLog) {
    # The Analytic channel is disabled by default. Enabling it before the restart
    # captures the WBF calls made during the very first sign-in without modifying
    # the driver or removing any enrolled fingerprint.
    & "$env:WINDIR\System32\wevtutil.exe" sl 'Microsoft-Windows-Biometrics/Analytic' /e:true /ms:8388608
    if ($LASTEXITCODE -ne 0) {
        if ($null -ne $existingValue) {
            Set-ItemProperty -LiteralPath $wbioKey -Name DependOnService -Type MultiString -Value ([string[]]$existing)
        } else {
            Remove-ItemProperty -LiteralPath $wbioKey -Name DependOnService -ErrorAction SilentlyContinue
        }
        throw "The diagnostic channel could not be enabled, so the original dependency was restored. Backup file: $backupFile"
    }
}

Write-Host 'Applied first-boot service ordering (WbioSrvc now depends on T2SepBootstrap).'
Write-Host 'WbioSrvc will now wait for T2SepBootstrap to report Running; that occurs after the SEP unlock sequence.'
Write-Host "Rollback file: $backupFile"
Write-Host 'Takes effect after the next restart. Keep PIN/password sign-in available while testing.'
if ($EnableAnalyticLog) { Write-Host 'Analytic log enabled; run Collect-T2TouchIdFirstBootEvidence.ps1 after the first sign-in.' }
