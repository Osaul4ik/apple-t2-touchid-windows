# SPDX-License-Identifier: GPL-2.0-only
# Collect-T2Diagnostics.ps1 - everything needed to look at a T2 Touch ID problem,
# in one zip, without DebugView or any other tool.
#
#   powershell -ExecutionPolicy Bypass -File Collect-T2Diagnostics.ps1 [-OutputDirectory DIR]
#
# Run as Administrator. Read-only: it changes nothing on the machine.
#
# What goes in:
#   * the logs the components write themselves (%ProgramData%\T2TouchId\*.log and
#     Logs\ - the driver / CLI / bootstrap file log, see protocol/BridgeXpc/Log.h);
#   * t2touchid.exe status / transport-status / ncmstatus / network --no-scan;
#   * Test Mode / Secure Boot state, OS version;
#   * the T2 devices (status, problem codes, driver versions), our driver packages,
#     T2SepBootstrap + WbioSrvc, the T2 network adapter (addresses, neighbors);
#   * registry: HKLM\SOFTWARE\T2TouchId (minus nothing secret - see below), T2TouchIdBio;
#   * event logs since 3 days: System entries of our services/drivers,
#     Microsoft-Windows-Biometrics/Operational, Application errors of WUDFHost;
#   * the T2 parts of setupapi.dev.log.
#
# What never goes in: sep-vault.bin, user.kb or any other file of the vault, and no
# password - the zip is safe to attach to an issue (it does contain hardware IDs,
# MAC addresses and link-local IPv6 addresses of the internal T2 link).
[CmdletBinding()]
param(
    [string]$OutputDirectory = [Environment]::GetFolderPath('Desktop')
)

$ErrorActionPreference = 'Continue'

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this from an elevated PowerShell (as Administrator).'
    exit 1
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$work = Join-Path ([IO.Path]::GetTempPath()) "T2TouchId-diagnostics-$stamp"
New-Item -ItemType Directory -Path $work -Force | Out-Null
$dataDir = Join-Path $env:ProgramData 'T2TouchId'
$since = (Get-Date).AddDays(-3)

function Save-Text {
    param([string]$Name, [scriptblock]$Block)
    $path = Join-Path $work $Name
    try {
        $out = & $Block 2>&1 | Out-String -Width 4096
    } catch {
        $out = "FAILED: $($_.Exception.Message)"
    }
    Set-Content -LiteralPath $path -Value $out -Encoding UTF8
    Write-Host "  $Name"
}

function Find-Cli {
    $candidates = @(
        (Join-Path $PSScriptRoot 't2touchid.exe'),
        (Join-Path (Split-Path $PSScriptRoot -Parent) 't2touchid.exe'),
        (Join-Path ${env:ProgramFiles} 'T2 Touch ID\t2touchid.exe')
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }
    return $null
}

# Runs the CLI with a hard time limit (a hung command must not hang the collector).
function Invoke-Cli {
    param([string]$Cli, [string]$Arguments, [int]$TimeoutSec = 60)
    $psi = [Diagnostics.ProcessStartInfo]::new($Cli, $Arguments)
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    $stdout = $p.StandardOutput.ReadToEndAsync()
    $stderr = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch { }
        return "TIMED OUT after $TimeoutSec s`n" + $stdout.Result + $stderr.Result
    }
    return "exit code $($p.ExitCode)`n" + $stdout.Result + $stderr.Result
}

Write-Host "Collecting T2 Touch ID diagnostics..."

# ---- logs written by the components ----------------------------------------
$logsOut = Join-Path $work 'logs'
New-Item -ItemType Directory -Path $logsOut -Force | Out-Null
if (Test-Path -LiteralPath $dataDir) {
    Get-ChildItem -LiteralPath $dataDir -Filter '*.log' -File -ErrorAction SilentlyContinue |
        Copy-Item -Destination $logsOut -ErrorAction SilentlyContinue
    $fileLogs = Join-Path $dataDir 'Logs'
    if (Test-Path -LiteralPath $fileLogs) {
        Get-ChildItem -LiteralPath $fileLogs -Filter '*.log' -File -ErrorAction SilentlyContinue |
            Copy-Item -Destination $logsOut -ErrorAction SilentlyContinue
    }
    Save-Text 'programdata-listing.txt' {
        # Names and sizes only - the vault itself is never copied.
        Get-ChildItem -LiteralPath $dataDir -Recurse -Force -ErrorAction SilentlyContinue |
            Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize
    }
}
Write-Host "  logs\ ($((Get-ChildItem $logsOut -File).Count) file(s))"

# ---- the CLI's own view ------------------------------------------------------
$cli = Find-Cli
if ($cli) {
    Save-Text 'cli-status.txt'           { Invoke-Cli $cli 'status' 30 }
    Save-Text 'cli-transport-status.txt' { Invoke-Cli $cli 'transport-status' 15 }
    Save-Text 'cli-ncmstatus.txt'        { Invoke-Cli $cli 'ncmstatus' 15 }
    Save-Text 'cli-network.txt'          { Invoke-Cli $cli 'network --no-scan' 30 }
} else {
    Save-Text 'cli-missing.txt' { 't2touchid.exe not found next to this script or in Program Files\T2 Touch ID' }
}

# ---- boot configuration ------------------------------------------------------
Save-Text 'system.txt' {
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, LastBootUpTime | Format-List
    Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model | Format-List
    'SystemStartOptions: ' + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control').SystemStartOptions
    try { 'Secure Boot: ' + (Confirm-SecureBootUEFI) } catch { 'Secure Boot: not available (' + $_.Exception.Message + ')' }
    ''
    '--- bcdedit /enum {current} ---'
    & "$env:SystemRoot\System32\bcdedit.exe" /enum '{current}'
}

# ---- devices, drivers, services ---------------------------------------------
Save-Text 'devices.txt' {
    $patterns = 'VEN_106B&DEV_1802', 'VID_05AC&PID_8600', 'T2TouchId', 'T2Ncm', 'ROOT\BIOMETRIC'
    Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        $id = $_.InstanceId
        $patterns | Where-Object { $id -like "*$_*" }
    } | ForEach-Object {
        $dev = $_
        $props = 'DEVPKEY_Device_DriverInfPath', 'DEVPKEY_Device_DriverVersion', 'DEVPKEY_Device_ProblemCode'
        $p = @{}
        foreach ($k in $props) {
            $p[$k] = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName $k -ErrorAction SilentlyContinue).Data
        }
        [pscustomobject]@{
            InstanceId = $dev.InstanceId
            Name = $dev.FriendlyName
            Status = $dev.Status
            Problem = $p['DEVPKEY_Device_ProblemCode']
            Inf = $p['DEVPKEY_Device_DriverInfPath']
            Version = $p['DEVPKEY_Device_DriverVersion']
        }
    } | Format-List
}
Save-Text 'driver-packages.txt' {
    $ours = 'T2TouchIdTransport.inf', 'apple-t2-composite.inf', 'apple-t2-ncm.inf', 'apple-t2-ncm-ctrl-stub.inf', 'T2TouchIdBio.inf'
    Get-WindowsDriver -Online -ErrorAction SilentlyContinue |
        Where-Object { $ours -contains [IO.Path]::GetFileName($_.OriginalFileName) } |
        Select-Object Driver, OriginalFileName, Version, Date, ProviderName | Format-List
}
Save-Text 'services.txt' {
    foreach ($s in 'T2SepBootstrap', 'WbioSrvc') {
        "--- $s ---"
        & "$env:SystemRoot\System32\sc.exe" queryex $s
        & "$env:SystemRoot\System32\sc.exe" qc $s
    }
    'WbioSrvc DependOnService: ' + ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WbioSrvc' -Name DependOnService -ErrorAction SilentlyContinue).DependOnService -join ', ')
}

# ---- the T2 network link ------------------------------------------------------
Save-Text 'network.txt' {
    $nics = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceDescription -like '*T2*' -or $_.InterfaceDescription -like '*NCM*' }
    foreach ($n in $nics) {
        $n | Format-List Name, InterfaceDescription, ifIndex, Status, MacAddress, LinkSpeed
        Get-NetIPAddress -InterfaceIndex $n.ifIndex -ErrorAction SilentlyContinue | Format-Table -AutoSize
        Get-NetNeighbor -InterfaceIndex $n.ifIndex -ErrorAction SilentlyContinue | Format-Table -AutoSize
        Get-NetAdapterBinding -Name $n.Name -ErrorAction SilentlyContinue | Format-Table -AutoSize
    }
    '--- other adapters (VPNs etc.) ---'
    Get-NetAdapter -ErrorAction SilentlyContinue | Format-Table -AutoSize Name, InterfaceDescription, Status
}

# ---- registry -------------------------------------------------------------------
foreach ($key in 'HKLM\SOFTWARE\T2TouchId', 'HKLM\SOFTWARE\T2TouchIdBio') {
    $file = Join-Path $work ("reg-" + ($key -replace '[\\:]', '_') + '.txt')
    & "$env:SystemRoot\System32\reg.exe" export $key $file /y 2>&1 | Out-Null
    if (Test-Path -LiteralPath $file) { Write-Host "  $(Split-Path $file -Leaf)" }
}

# ---- event logs ----------------------------------------------------------------
Save-Text 'events-system.txt' {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $since } -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Message -match 'T2|WbioSrvc|Biometric|WUDF' -or
            $_.ProviderName -match 'Kernel-PnP|UserPnp|WUDF|DriverFrameworks'
        } | Select-Object -First 2000 TimeCreated, ProviderName, Id, LevelDisplayName, Message | Format-List
}
Save-Text 'events-biometrics.txt' {
    Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Biometrics/Operational'; StartTime = $since } -ErrorAction SilentlyContinue |
        Select-Object -First 2000 TimeCreated, Id, LevelDisplayName, Message | Format-List
}
Save-Text 'events-application.txt' {
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $since; Level = 1, 2 } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'WUDFHost|T2TouchId|T2Sep|t2touchid' } |
        Select-Object -First 500 TimeCreated, ProviderName, Id, Message | Format-List
}

# ---- driver installation -------------------------------------------------------
Save-Text 'setupapi-t2.txt' {
    $log = Join-Path $env:SystemRoot 'INF\setupapi.dev.log'
    if (Test-Path -LiteralPath $log) {
        $lines = Get-Content -LiteralPath $log -ErrorAction SilentlyContinue
        $keep = [Collections.Generic.List[string]]::new()
        $inSection = $false
        foreach ($l in $lines) {
            if ($l.StartsWith('>>>')) { $inSection = ($l -match 'T2|106B|05AC|BIOMETRIC') }
            if ($inSection) { $keep.Add($l) }
        }
        $keep | Select-Object -Last 4000
    }
}

# ---- zip -------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}
$zip = Join-Path $OutputDirectory "T2TouchId-diagnostics-$stamp.zip"
Compress-Archive -Path (Join-Path $work '*') -DestinationPath $zip -Force
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "Saved: $zip"
Write-Output $zip
