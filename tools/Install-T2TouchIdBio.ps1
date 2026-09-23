#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$InfPath
)

$ErrorActionPreference = 'Stop'
$HardwareId = 'root\T2TouchIdBio'

# $PSScriptRoot can be empty (it was, in a param() default, on the target box), so
# resolve the default here: script folder, else the current directory.
if (-not $InfPath) {
    $root = $PSScriptRoot
    if (-not $root -and $MyInvocation.MyCommand.Path) {
        $root = Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    if (-not $root) {
        $root = (Get-Location).Path
    }

    # This script lives in <package>\Inst; the driver folders (Bio\, SEP\,
    # NCM\) are siblings of Inst, i.e. one level up.
    $root = Split-Path -Parent $root

    $InfPath = Join-Path $root 'Bio\T2TouchIdBio.inf'
}

$inf = (Resolve-Path -LiteralPath $InfPath).Path
$dir = Split-Path -Parent $inf
foreach ($f in 'T2TouchIdBio.dll', 'T2TouchIdBio.cat') {
    if (-not (Test-Path -LiteralPath (Join-Path $dir $f))) {
        throw "$f is missing next to the INF ($dir). Use the whole CI package folder."
    }
}
if (Select-String -LiteralPath $inf -Pattern '\$ARCH\$|\$UMDFVERSION\$' -Quiet) {
    throw 'INF is not stamped (still contains $ARCH$ or $UMDFVERSION$). Run StampInf first.'
}

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class T2BioSetup
{
    const int DICD_GENERATE_ID = 0x00000001;
    const int SPDRP_HARDWAREID = 0x00000001;
    const int DIF_REMOVE = 0x00000005;
    const int DIF_REGISTERDEVICE = 0x00000019;
    const int INSTALLFLAG_FORCE = 0x00000001;
    static readonly IntPtr InvalidHandle = new IntPtr(-1);

    [StructLayout(LayoutKind.Sequential)]
    struct SP_DEVINFO_DATA
    {
        public int cbSize;
        public Guid ClassGuid;
        public int DevInst;
        public IntPtr Reserved;
    }

    [DllImport("setupapi.dll", SetLastError = true)]
    static extern IntPtr SetupDiCreateDeviceInfoList(ref Guid classGuid, IntPtr hwndParent);

    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool SetupDiCreateDeviceInfoW(IntPtr set, string name, ref Guid classGuid,
        string description, IntPtr hwndParent, int creationFlags, ref SP_DEVINFO_DATA data);

    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool SetupDiSetDeviceRegistryPropertyW(IntPtr set, ref SP_DEVINFO_DATA data,
        int property, byte[] buffer, int size);

    [DllImport("setupapi.dll", SetLastError = true)]
    static extern bool SetupDiCallClassInstaller(int installFunction, IntPtr set, ref SP_DEVINFO_DATA data);

    [DllImport("setupapi.dll", SetLastError = true)]
    static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);

    [DllImport("newdev.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool UpdateDriverForPlugAndPlayDevicesW(IntPtr hwndParent, string hardwareId,
        string fullInfPath, int installFlags, out bool rebootRequired);

    static void Fail(string what)
    {
        int err = Marshal.GetLastWin32Error();
        throw new Win32Exception(err, what + " failed, Win32/SetupAPI error 0x" + err.ToString("X8"));
    }

    // Creates a new root device node with the given hardware ID (does not check
    // for an existing one - the caller does that).
    public static void CreateNode(string classGuidText, string className, string hardwareId)
    {
        Guid cls = new Guid(classGuidText);
        IntPtr set = SetupDiCreateDeviceInfoList(ref cls, IntPtr.Zero);
        if (set == InvalidHandle) Fail("SetupDiCreateDeviceInfoList");

        SP_DEVINFO_DATA data = new SP_DEVINFO_DATA();
        data.cbSize = Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
        bool created = false;
        try
        {
            if (!SetupDiCreateDeviceInfoW(set, className, ref cls, null, IntPtr.Zero,
                    DICD_GENERATE_ID, ref data))
                Fail("SetupDiCreateDeviceInfo");
            created = true;

            // REG_MULTI_SZ: the ID plus the extra terminating NUL.
            byte[] hwid = Encoding.Unicode.GetBytes(hardwareId + "\0\0");
            if (!SetupDiSetDeviceRegistryPropertyW(set, ref data, SPDRP_HARDWAREID, hwid, hwid.Length))
                Fail("SetupDiSetDeviceRegistryProperty(HARDWAREID)");

            if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, set, ref data))
                Fail("SetupDiCallClassInstaller(DIF_REGISTERDEVICE)");
            created = false; // registered: from here on the node is real
        }
        catch
        {
            // Do not leave a half-created, unregistered node behind.
            if (created) SetupDiCallClassInstaller(DIF_REMOVE, set, ref data);
            throw;
        }
        finally
        {
            SetupDiDestroyDeviceInfoList(set);
        }
    }

    // Stages the package and binds it to the node(s) with this hardware ID.
    public static bool BindDriver(string hardwareId, string fullInfPath)
    {
        bool reboot;
        if (!UpdateDriverForPlugAndPlayDevicesW(IntPtr.Zero, hardwareId, fullInfPath,
                INSTALLFLAG_FORCE, out reboot))
            Fail("UpdateDriverForPlugAndPlayDevices");
        return reboot;
    }
}
'@

function Get-BioNode {
    Get-PnpDevice -ErrorAction SilentlyContinue |
        Where-Object { $_.HardwareID -contains $HardwareId }
}

$existing = @(Get-BioNode)
if ($existing.Count -eq 0) {
    Write-Host "Creating root device node ($HardwareId)..."
    [T2BioSetup]::CreateNode('{53D29EF7-377C-4D14-864B-EB3A85769359}', 'Biometric', $HardwareId)
} else {
    Write-Host "Device node already exists ($($existing[0].InstanceId)); re-applying driver only."
}

Write-Host "Installing driver from $inf ..."
$reboot = [T2BioSetup]::BindDriver($HardwareId, $inf)

Write-Host ''
foreach ($d in @(Get-BioNode)) {
    $problem = (Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction SilentlyContinue).Data
    Write-Host ("{0}  Status={1}  ProblemCode={2}" -f $d.InstanceId, $d.Status, $problem)
}
if ($reboot) { Write-Host 'Windows asks for a reboot to finish.' }
Write-Host 'If ProblemCode is not 0: look at C:\Windows\INF\setupapi.dev.log (search T2TouchIdBio) and the'
Write-Host 'DriverFrameworks-UserMode/Operational event log.'