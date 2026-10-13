[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as Administrator. No configuration was changed.'
}

$targetId = 'ROOT\BIOMETRIC\0000'
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$destination = Join-Path $PSScriptRoot "T2TouchId-firstboot-evidence-$stamp.txt"

function Get-PropertyData {
    param([string]$KeyName)
    $property = Get-PnpDeviceProperty -InstanceId $targetId -KeyName $KeyName -ErrorAction SilentlyContinue
    if ($null -eq $property) { return $null }
    return $property.Data
}

$device = Get-PnpDevice -InstanceId $targetId -ErrorAction SilentlyContinue
$driverInf = Get-PropertyData 'DEVPKEY_Device_DriverInfPath'
$driverVersion = Get-PropertyData 'DEVPKEY_Device_DriverVersion'
$problemCode = Get-PropertyData 'DEVPKEY_Device_ProblemCode'
$wbioDependencies = @((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\WbioSrvc' -Name DependOnService -ErrorAction SilentlyContinue).DependOnService)
$bootstrap = Get-CimInstance Win32_Service -Filter "Name='T2SepBootstrap'" -ErrorAction SilentlyContinue

$report = [System.Collections.Generic.List[string]]::new()
$report.Add("Collected: $(Get-Date -Format o)")
$report.Add("Boot: $($boot.ToString('o'))")
$report.Add('')
$report.Add('=== Touch ID device ===')
$report.Add("Status: $($device.Status)")
$report.Add("Driver INF: $driverInf")
$report.Add("Driver version: $driverVersion")
$report.Add("Problem code: $problemCode")
$report.Add('')
$report.Add('=== Startup ordering ===')
$report.Add("WbioSrvc dependencies: $($wbioDependencies -join ', ')")
$report.Add("T2SepBootstrap: state=$($bootstrap.State); start mode=$($bootstrap.StartMode)")
$report.Add('')

foreach ($logName in @('Microsoft-Windows-Biometrics/Operational', 'Microsoft-Windows-Biometrics/Analytic')) {
    $report.Add("=== $logName since boot (full XML) ===")
    try {
        if ($logName -eq 'Microsoft-Windows-Biometrics/Analytic') {
            # Analytic/debug channels only support forward (oldest-first)
            # enumeration. Filter the resulting events by this boot afterwards.
            $events = @(Get-WinEvent -LogName $logName -Oldest -ErrorAction Stop |
                Where-Object { $_.TimeCreated -ge $boot })
        } else {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = $logName; StartTime = $boot } -ErrorAction Stop)
        }
        if ($events.Count -eq 0) {
            $report.Add('(no events)')
        } else {
            foreach ($event in $events) {
                $report.Add($event.ToXml())
                $report.Add('')
            }
        }
    } catch {
        $report.Add("Could not read this log: $($_.Exception.Message)")
    }
    $report.Add('')
}

# Keep the verbose channel enabled only for this diagnostic boot. It has
# already been read into this report, so it is safe to turn it off now.
& "$env:WINDIR\System32\wevtutil.exe" sl 'Microsoft-Windows-Biometrics/Analytic' /e:false
if ($LASTEXITCODE -eq 0) {
    $report.Add('Biometrics Analytic logging was disabled after collection.')
} else {
    $report.Add('Biometrics Analytic logging could not be disabled; run wevtutil sl Microsoft-Windows-Biometrics/Analytic /e:false as Administrator.')
}
$report.Add('')

$report.Add('=== SEP bootstrap log tail ===')
if (Test-Path -LiteralPath 'C:\LogSEP.txt' -PathType Leaf) {
    $report.AddRange([string[]](Get-Content -LiteralPath 'C:\LogSEP.txt' -Tail 100))
} else {
    $report.Add('C:\LogSEP.txt was not found.')
}

$report | Set-Content -LiteralPath $destination -Encoding UTF8
Write-Host "Evidence saved to: $destination"
Get-Content -LiteralPath $destination
