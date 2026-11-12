; ============================================================================
;  T2TouchId.iss
;  Installer for Apple T2 Touch ID for Windows: the four driver packages
;  (SEP transport, T2 composite + NCM network, Windows Hello sensor) and,
;  optionally, the T2 Touch ID control panel (T2TouchID_GUI.exe + the
;  t2touchid.exe CLI).
;
;  Modeled on wellspring-ptp's WellspringControlCenter.iss (RC1): same
;  "what to install" page, same red "do NOT restart my PC" checkbox, same
;  in-process (already elevated) driver install - no .bat, no second UAC
;  prompt, no self-relaunch.
;
;  Install (CurStepChanged / ssPostInstall), in this order:
;    0. Refuse early (nothing changed) when Secure Boot is on; offer to keep the
;       drivers as they are when this exact build is installed and working
;       (Test-T2DriversCurrent.ps1) - an app-only update then needs no restart.
;    1. Stop WbioSrvc and T2SepBootstrap so the engine adapter DLL and
;       T2SepBootstrap.exe (both copied by the INFs into System32) can be
;       replaced on an upgrade instead of being queued for a reboot.
;    2. bcdedit /set testsigning on (always - see InstallDriver.bat for why
;       parsing bcdedit's Yes/No is unreliable). A failed set is NOT fatal
;       when Test Mode is already on (SystemStartOptions of the running boot,
;       or element 16000049 of the default BCD entry); otherwise setup stops
;       and shows bcdedit's own message.
;    3. Import every .cer of the package (Inst\, else SEP/NCM/Bio) into LocalMachine
;       Root and TrustedPublisher (certutil, Import-Certificate as fallback), checked
;       by thumbprint - BEFORE services or Test Mode are touched; no .cer = clear
;       error, nothing changed.
;    4. Check every INF / script is present BEFORE anything is removed.
;    5. Remove previously published packages of our five INFs (matched by
;       OriginalFileName through Get-WindowsDriver, so it is locale-proof).
;    6. pnputil /add-driver /install: T2TouchIdTransport, apple-t2-composite
;       (+ /scan-devices), apple-t2-ncm, apple-t2-ncm-ctrl-stub.
;    7. Set-T2NcmStaticIp.ps1 (LocalService ACL on HKLM\SOFTWARE\T2TouchId\
;       Network + 169.254.84.1/16 on the NCM adapter; best effort).
;    8. Install-T2TouchIdBio.ps1 (root\T2TouchIdBio node + UMDF driver).
;    9. Set-T2TouchIdWbioStartupDependency.ps1 (WbioSrvc waits for
;       T2SepBootstrap at boot; best effort).
;   10. Lock down %ProgramData%\T2TouchId (sep-vault.bin is read by a
;       SYSTEM service; standard users must not be able to plant it).
;   11. /scan-devices, start T2SepBootstrap + WbioSrvc, restart Windows
;       (automatically unless the red checkbox was ticked).
;  Every command's output is appended to %ProgramData%\T2TouchId\install.log.
;
;  Uninstall (always everything, no choice page - same as Wellspring):
;    WbioSrvc dependency undone -> WbioSrvc stopped -> T2SepBootstrap
;    stopped and deleted -> root\T2TouchIdBio node removed -> the five
;    packages removed -> System32 leftovers (co-installer, bootstrap exe,
;    engine adapter) and the sensor's WinBio database deleted -> WbioSrvc
;    started again -> rescan. Then: ask about Test Mode, about settings
;    (HKLM\SOFTWARE\T2TouchId*), and separately about the encrypted keybag
;    sep-vault.bin (default: keep).
;
;  Unattended: /VERYSILENT /SUPPRESSMSGBOXES installs the drivers (+ GUI)
;  without any prompt (every message box goes through SuppressibleMsgBox, a
;  plain MsgBox would block a silent install forever); add /NORESTART to stop
;  the automatic restart. A silent uninstall keeps sep-vault.bin and leaves
;  Test Mode on.
;
;  Build (Inno Setup 6.x), from the repo root, after the CI package exists:
;     ISCC.exe installer\T2TouchId.iss /DMyAppVersion=1.2026.1110.1200 ^
;              /DPackageDir=<path>\apple-t2-touchid
;  PackageDir is the folder the CI workflow uploads (Ciapplet2touchid.yml,
;  "Assemble apple-t2-touchid folder"): SEP\, NCM\, Bio\, Inst\,
;  T2TouchID_GUI\. checks\ and *.pdb are not packed.
; ============================================================================

#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif

#ifndef PackageDir
  #define PackageDir "..\dist\apple-t2-touchid"
#endif

#define MyAppName "T2 Touch ID"
#define MyAppExeName "T2TouchID_GUI.exe"
#define MyCliExeName "t2touchid.exe"
#define MyAppPublisher "Osaul4ik"
#define MyAppURL "https://github.com/Osaul4ik/apple-t2-touchid-windows"
; Fixed GUID - never change it between releases, or an upgrade is no longer
; recognized as an update of the existing install. "{{" = literal "{".
#define MyAppId "{{5B7F2C4E-9A31-4D8E-B6E2-7C1F0A3D9E21}"

; WinBio database id from T2TouchIdBio.inf [Strings] DatabaseId - keep in sync.
#define WinBioDatabaseId "{B039A555-3EEC-475A-ABBD-3AA5C5F550DA}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
DefaultDirName={autopf}\T2TouchID
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
DisableWelcomePage=no
DisableDirPage=auto
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
OutputBaseFilename=T2TouchID-Setup-{#MyAppVersion}
OutputDir=output
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
PrivilegesRequired=admin
SetupLogging=yes
CloseApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Control panel + CLI + libplist runtime DLLs. Skipped for "Drivers only".
Source: "{#PackageDir}\T2TouchID_GUI\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "*.pdb"; Check: InstallGui
; Diagnostics helpers, kept after install (support / first-boot evidence).
Source: "{#PackageDir}\Inst\Collect-T2TouchIdFirstBootEvidence.ps1"; DestDir: "{app}\Tools"; Flags: ignoreversion; Check: InstallGui
Source: "{#PackageDir}\Inst\Collect-T2Diagnostics.ps1"; DestDir: "{app}\Tools"; Flags: ignoreversion; Check: InstallGui

; Driver packages + install scripts: extracted to Setup's own {tmp} only for
; the duration of the install (Inno deletes {tmp} when Setup exits), never
; copied under {app}. checks\ (SARIF/PREfast logs) and symbols are not packed.
Source: "{#PackageDir}\SEP\*"; DestDir: "{tmp}\pkg\SEP"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "checks\*,*.pdb"
Source: "{#PackageDir}\NCM\*"; DestDir: "{tmp}\pkg\NCM"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "checks\*,*.pdb"
Source: "{#PackageDir}\Bio\*"; DestDir: "{tmp}\pkg\Bio"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "checks\*,*.pdb"
Source: "{#PackageDir}\Inst\*"; DestDir: "{tmp}\pkg\Inst"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "*.bat"

[Icons]
; All users, no Start Menu subfolder (same as Wellspring).
Name: "{commonprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Check: InstallGui

[Code]

const
  GuiProcessName = '{#MyAppExeName}';
  CliProcessName = '{#MyCliExeName}';
  LB_GETITEMHEIGHT = $01A1;
  SB_VERT = 1;
  ERROR_SUCCESS_REBOOT_REQUIRED = 3010;
  ERROR_NO_MORE_ITEMS = 259;

function SendMessage(hWnd: Longint; Msg: Longint; WParam: Longint;
  LParam: Longint): Longint;
  external 'SendMessageA@user32.dll stdcall';
function ShowScrollBar(hWnd: Longint; wBar: Longint; bShow: Boolean): Boolean;
  external 'ShowScrollBar@user32.dll stdcall';

var
  InstallChoicePage: TInputOptionWizardPage;
  NoAutoRebootCheckBox: TNewCheckBox;
  RebootNeeded: Boolean;
  DriverInstallOk: Boolean;
  LogFile: String;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// S ready to sit inside a PowerShell '...' literal ({tmp} is under the user
// profile, so a user name like O'Brien would otherwise end the literal).
function PsQuote(const S: String): String;
begin
  Result := S;
  StringChangeEx(Result, '''', '''''', True);
end;

function DataDir(): String;
begin
  Result := ExpandConstant('{commonappdata}\T2TouchId');
end;

procedure LogLine(const S: String);
begin
  Log(S);
  if LogFile <> '' then
    SaveStringToFile(LogFile, GetDateTimeString('yyyy-mm-dd hh:nn:ss', '-', ':') +
      '  ' + S + #13#10, True);
end;

procedure SetStatus(const S: String);
begin
  LogLine('== ' + S);
  if not IsUninstaller then
    WizardForm.StatusLabel.Caption := S
  else
    UninstallProgressForm.StatusLabel.Caption := S;
end;


// Runs a command, appends its output to the install log AND returns it, so a
// failure can be shown to the user instead of a guess.
function RunCaptured(const Exe, Args: String; var ResultCode: Integer;
  var Output: String): Boolean;
var
  OutFile: String;
  Raw: AnsiString;
begin
  Output := '';
  OutFile := ExpandConstant('{tmp}\cmd-output.txt');
  DeleteFile(OutFile);
  LogLine('> "' + Exe + '" ' + Args);
  // chcp 65001: console programs write UTF-8, decoded below - otherwise their
  // localized (e.g. Cyrillic) OEM-codepage text ended up as "?????" in the log.
  Result := Exec(ExpandConstant('{cmd}'),
    '/S /C "chcp 65001 >nul & "' + Exe + '" ' + Args + ' > "' + OutFile + '" 2>&1"', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode);
  if not Result then
  begin
    LogLine('  could not launch (' + SysErrorMessage(ResultCode) + ')');
    Exit;
  end;
  if LoadStringFromFile(OutFile, Raw) then
  begin
    Output := Trim(UTF8Decode(Raw));
    if (Output = '') and (Trim(String(Raw)) <> '') then
      Output := Trim(String(Raw)); // not UTF-8 after all: keep it as it is
  end;
  DeleteFile(OutFile);
  if Output <> '' then
    LogLine('  ' + Output);
  LogLine('  exit code ' + IntToStr(ResultCode));
end;

// Runs Exe with Args; its output goes to the install log. Returns False only when
// the process could not be launched; the exit code is handed back in ResultCode.
// The output is captured into {tmp} first and appended to the log afterwards -
// never redirected into the log file by cmd: a log that cannot be written (locked,
// broken ACL) must not stop cmd from running the command itself (it would refuse
// with exit code 1, which looked like the command failing).
function RunLogged(const Exe, Args: String; var ResultCode: Integer): Boolean;
var
  Output: String;
begin
  Result := RunCaptured(Exe, Args, ResultCode, Output);
end;

function RunPowerShell(const Command: String; var ResultCode: Integer): Boolean;
begin
  Result := RunLogged(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + Command + '"',
    ResultCode);
end;

function RunPowerShellFile(const ScriptPath, ScriptArgs: String; var ResultCode: Integer): Boolean;
begin
  Result := RunLogged(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ScriptPath + '" ' + ScriptArgs,
    ResultCode);
end;

procedure RunIgnore(const Exe, Args: String);
var
  ResultCode: Integer;
begin
  RunLogged(Exe, Args, ResultCode);
end;


// Test Mode of the RUNNING boot: the loader writes the effective options to
// SystemStartOptions (" ... TESTSIGNING ..."). Locale-independent, unlike the
// Yes/No that bcdedit prints.
function TestSigningActiveNow(): Boolean;
var
  Opts: String;
begin
  Result := RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control',
              'SystemStartOptions', Opts) and
            (Pos('TESTSIGNING', Uppercase(Opts)) > 0);
end;

// Test Mode STORED in the BCD for the next boot, read from the mounted BCD hive:
// boot manager {9dea862c-...} -> default entry (23000003) -> element 16000049
// (BcdLibraryBoolean_AllowPrereleaseSignatures = "testsigning") == 1.
// False when anything along the way cannot be read.
function TestSigningStoredInBcd(): Boolean;
var
  Def: String;
  Data: AnsiString;
begin
  Result := False;
  if not RegQueryStringValue(HKLM,
       'BCD00000000\Objects\{9dea862c-5cdd-4e70-acc1-f32b344d4795}\Elements\23000003',
       'Element', Def) then
    Exit;
  if not RegQueryBinaryValue(HKLM,
       'BCD00000000\Objects\' + Def + '\Elements\16000049', 'Element', Data) then
    Exit;
  Result := (Length(Data) > 0) and (Ord(Data[1]) <> 0);
end;

// UEFI Secure Boot as Windows sees it. With it on, Windows ignores testsigning and
// the test-signed drivers cannot load (Code 52), whatever bcdedit says.
function SecureBootEnabled(): Boolean;
var
  V: Cardinal;
begin
  Result := RegQueryDWordValue(HKLM, 'SYSTEM\CurrentControlSet\Control\SecureBoot\State',
              'UEFISecureBootEnabled', V) and (V <> 0);
end;

function SecureBootHelpText(): String;
begin
  Result := 'On a Mac with the T2 chip: restart holding Command-R (macOS Recovery), open ' +
    'Utilities > Startup Security Utility and set Secure Boot to "No Security". ' +
    'Then start Windows and run this setup again.';
end;

// Turns Test Mode on. Not an error when it is already on: "bcdedit /set" can
// fail on a machine that is already in Test Mode (BitLocker / firmware policy /
// a BCD store bcdedit cannot open), and the old code then aborted the install
// although nothing needed to change.
function EnsureTestSigning(var Details: String): Boolean;
var
  ResultCode: Integer;
  Output: String;
  ActiveNow, Stored: Boolean;
begin
  Details := '';
  ActiveNow := TestSigningActiveNow();
  Stored := TestSigningStoredInBcd();
  LogLine('testsigning: running boot=' + IntToStr(Ord(ActiveNow)) +
          ', stored for next boot=' + IntToStr(Ord(Stored)));

  // Still (re)apply it: an explicit "testsigning No" must be overwritten.
  if RunCaptured(ExpandConstant('{sys}\bcdedit.exe'), '/set testsigning on',
       ResultCode, Output) and (ResultCode = 0) then
  begin
    Result := True;
    Exit;
  end;
  Details := Output;

  // Second form: some BCD layouts only accept an explicit {current}.
  if RunCaptured(ExpandConstant('{sys}\bcdedit.exe'), '/set {current} testsigning on',
       ResultCode, Output) and (ResultCode = 0) then
  begin
    Result := True;
    Exit;
  end;
  if Output <> '' then
    Details := Output;

  Stored := TestSigningStoredInBcd();
  if Stored or ActiveNow then
  begin
    LogLine('WARNING: bcdedit could not set testsigning, but Test Mode is already on ' +
            '(running boot=' + IntToStr(Ord(ActiveNow)) + ', stored=' + IntToStr(Ord(Stored)) +
            ') - continuing.');
    Result := True;
    Exit;
  end;
  Result := False;
end;

function ServiceExists(const Name: String): Boolean;
begin
  Result := RegKeyExists(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Services\' + Name);
end;

// sc.exe output is localized, its numeric STATE code is not: 1 = STOPPED.
procedure StopServiceAndWait(const Name: String);
var
  ResultCode, I: Integer;
begin
  if not ServiceExists(Name) then
    Exit;
  RunIgnore(ExpandConstant('{sys}\sc.exe'), 'stop ' + Name);
  for I := 1 to 30 do
  begin
    if Exec(ExpandConstant('{cmd}'),
         '/S /C "' + ExpandConstant('{sys}\sc.exe') + ' query ' + Name +
         ' | ' + ExpandConstant('{sys}\findstr.exe') + ' /r /c:"STATE *: *1 ""',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then
      Exit;
    Sleep(500);
  end;
  LogLine('  ' + Name + ' did not report STOPPED within 15 s');
end;

// WbioSrvc has dependents on some systems; net stop /y stops them too.
procedure StopBiometricService;
begin
  SetStatus('Stopping Windows Biometric Service...');
  RunIgnore(ExpandConstant('{sys}\net.exe'), 'stop WbioSrvc /y');
end;

procedure StartBiometricService;
begin
  RunIgnore(ExpandConstant('{sys}\net.exe'), 'start WbioSrvc');
end;

// pnputil: 0 = ok, 3010 = ok but restart needed, 259 = staged, no matching
// device right now (e.g. the NCM function is not enumerated yet). Anything
// else is a real failure.
function PnpAddDriver(const Inf: String; Fatal: Boolean): Boolean;
var
  ResultCode: Integer;
begin
  Result := False;
  if not RunLogged(ExpandConstant('{sys}\pnputil.exe'), '/add-driver "' + Inf + '" /install', ResultCode) then
  begin
    SuppressibleMsgBox('Could not launch pnputil.exe.', mbError, MB_OK, IDOK);
    Exit;
  end;
  if (ResultCode = 0) or (ResultCode = ERROR_SUCCESS_REBOOT_REQUIRED) or
     (ResultCode = ERROR_NO_MORE_ITEMS) then
  begin
    Result := True;
    if ResultCode = ERROR_SUCCESS_REBOOT_REQUIRED then
      RebootNeeded := True;
    Exit;
  end;
  if Fatal then
    SuppressibleMsgBox('pnputil failed to install ' + ExtractFileName(Inf) + ' (code ' +
      IntToStr(ResultCode) + ').' + #13#10#13#10 +
      'Details: ' + LogFile + #13#10 +
      'and C:\Windows\INF\setupapi.dev.log', mbError, MB_OK, IDOK)
  else
    LogLine('  (non-fatal) ' + ExtractFileName(Inf) + ' failed with ' + IntToStr(ResultCode));
end;

// Removes every published Driver Store package that came from the INF named
// InfName, whatever oemNN.inf number it got. Get-WindowsDriver is used instead
// of parsing `pnputil /enum-drivers`, whose labels are localized.
procedure RemovePackagesByInf(const InfName, ListTag: String);
var
  ResultCode, I: Integer;
  ListFile, Name: String;
  OldDrivers: TArrayOfString;
begin
  ListFile := ExpandConstant('{tmp}\t2touchid_') + ListTag + '.txt';
  if FileExists(ListFile) then
    DeleteFile(ListFile);

  if (not RunPowerShell(
        'Get-WindowsDriver -Online | ' +
        'Where-Object { $_.OriginalFileName -like ''*\' + InfName + ''' } | ' +
        'Select-Object -ExpandProperty Driver | ' +
        'Set-Content -Path ''' + PsQuote(ListFile) + ''' -Encoding ascii', ResultCode))
     or (ResultCode <> 0) or (not FileExists(ListFile)) then
    Exit;

  if not LoadStringsFromFile(ListFile, OldDrivers) then
    Exit;

  for I := 0 to GetArrayLength(OldDrivers) - 1 do
  begin
    Name := Trim(OldDrivers[I]);
    if Name = '' then
      Continue;
    SetStatus('Removing ' + InfName + ' (' + Name + ')...');
    // /uninstall also detaches it from every device using it; /force skips
    // the "in use" prompt. Failure of one package is not fatal.
    RunLogged(ExpandConstant('{sys}\pnputil.exe'), '/delete-driver ' + Name + ' /uninstall /force',
      ResultCode);
  end;
end;

// Order matters: children before parents - the NCM function drivers before
// the composite they sit on, the Touch ID sensor before the SEP transport it
// talks to.
procedure RemoveAllDriverPackages;
begin
  RemovePackagesByInf('apple-t2-ncm-ctrl-stub.inf', 'ncm_ctrl');
  RemovePackagesByInf('apple-t2-ncm.inf', 'ncm');
  RemovePackagesByInf('T2TouchIdBio.inf', 'bio');
  RemovePackagesByInf('T2TouchIdTransport.inf', 'sep');
  RemovePackagesByInf('apple-t2-composite.inf', 'composite');
end;

// The sensor is a ROOT-enumerated node; deleting its package leaves the node
// behind as an "Unknown device", so remove the node itself.
procedure RemoveBioRootNodes;
var
  ResultCode: Integer;
begin
  SetStatus('Removing the Touch ID sensor device node...');
  RunPowerShell(
    'Get-PnpDevice -ErrorAction SilentlyContinue | ' +
    'Where-Object { $_.HardwareID -contains ''root\T2TouchIdBio'' } | ' +
    'ForEach-Object { & pnputil.exe /remove-device $_.InstanceId }', ResultCode);
end;

// Through the Service Control Manager (sc config), not only the registry: the SCM
// reads DependOnService at boot, so a registry-only edit left WbioSrvc depending
// on the just-deleted T2SepBootstrap until the next restart - "net start WbioSrvc"
// then failed with 1075 and Windows Hello stayed down. sc config updates both.
procedure UndoWbioDependency;
var
  ResultCode: Integer;
begin
  SetStatus('Removing the WbioSrvc -> T2SepBootstrap start dependency...');
  RunPowerShell(
    '$k=''HKLM:\SYSTEM\CurrentControlSet\Services\WbioSrvc''; ' +
    '$v=(Get-Item -LiteralPath $k).GetValue(''DependOnService'',$null,' +
    '[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); ' +
    'if($v -and ($v -contains ''T2SepBootstrap'')){ ' +
    '$n=[string[]]@($v | Where-Object { $_ -ne ''T2SepBootstrap'' }); ' +
    '$d=if($n.Count -gt 0){ $n -join ''/'' } else { ''/'' }; ' +
    '& sc.exe config WbioSrvc depend= $d; exit $LASTEXITCODE }', ResultCode);
  if ResultCode <> 0 then
    LogLine('WARNING: sc config WbioSrvc depend= failed (' + IntToStr(ResultCode) +
            ') - Windows Hello may only start again after a restart');
end;

// sep-vault.bin is read by T2SepBootstrap (LocalSystem). The default
// ProgramData ACL lets any user create a subfolder and own it, so a folder
// created by a standard user BEFORE install would let that user replace the
// vault the SYSTEM service parses. So the folder is reset on every install:
//
// %ProgramData%\T2TouchId: SYSTEM + Administrators full, Users read - so the logs
// (install.log, uninstall.log, coinstaller.log, Logs\*.log) open in Notepad without
// elevation; the vault file alone is SYSTEM + Administrators only (it is DPAPI
// LocalMachine, i.e. readable = decryptable by any local process).
//
// The ACL is set on the FOLDER only and reaches the files by inheritance. Setup
// 1.2026.1110.x applied "(OI)(CI)" grants recursively (/T) after /inheritance:r:
// inheritance flags do not apply to files, so every file was left with an EMPTY
// DACL - nobody could read or write install.log any more (and the next Setup's
// commands, whose output is appended to it, failed). This routine repairs that:
// it is safe to run on any state of the folder and runs at the start and at the
// end of every install.
procedure SecureDataDir;
var
  FindRec: TFindRec;
  Dir, Name, Path: String;
begin
  Dir := DataDir();
  ForceDirectories(Dir);
  ForceDirectories(Dir + '\Logs');
  // Administrators own everything, so the ACLs below can always be rewritten.
  RunIgnore(ExpandConstant('{sys}\icacls.exe'), '"' + Dir + '" /setowner *S-1-5-32-544 /T /C /Q');
  // The folder: explicit, protected, inheritable to files and subfolders. No /T.
  RunIgnore(ExpandConstant('{sys}\icacls.exe'),
    '"' + Dir + '" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F ' +
    '*S-1-5-32-545:(OI)(CI)RX /C /Q');
  // Logs\: plus modify for LocalService (the UMDF driver writes its log there).
  RunIgnore(ExpandConstant('{sys}\icacls.exe'),
    '"' + Dir + '\Logs" /reset /C /Q');
  RunIgnore(ExpandConstant('{sys}\icacls.exe'),
    '"' + Dir + '\Logs" /grant *S-1-5-19:(OI)(CI)M /C /Q');
  RunIgnore(ExpandConstant('{sys}\icacls.exe'),
    '"' + Dir + '\Logs\*" /reset /T /C /Q');
  // portcache.ini: written by old versions only (the port cache is in the registry).
  DeleteFile(Dir + '\portcache.ini');
  // Every file of the folder: the vault gets its own protected ACL directly (never
  // an inherited "Users read" first), everything else goes back to inheriting.
  if FindFirst(Dir + '\*', FindRec) then
  begin
    try
      repeat
        Name := FindRec.Name;
        Path := Dir + '\' + Name;
        if (FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY) <> 0 then
          Continue;
        if Pos('sep-vault', Lowercase(Name)) = 1 then
          RunIgnore(ExpandConstant('{sys}\icacls.exe'),
            '"' + Path + '" /inheritance:r /grant:r *S-1-5-18:F *S-1-5-32-544:F /C /Q')
        else
          RunIgnore(ExpandConstant('{sys}\icacls.exe'), '"' + Path + '" /reset /C /Q');
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

// Uninstall: make the logs readable / writable again before logging (see
// SecureDataDir), without touching anything else.
procedure RepairLogAccess;
var
  FindRec: TFindRec;
  Dir: String;
begin
  Dir := DataDir();
  RunIgnore(ExpandConstant('{sys}\icacls.exe'), '"' + Dir + '" /setowner *S-1-5-32-544 /T /C /Q');
  RunIgnore(ExpandConstant('{sys}\icacls.exe'),
    '"' + Dir + '" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F ' +
    '*S-1-5-32-545:(OI)(CI)RX /C /Q');
  if FindFirst(Dir + '\*.log', FindRec) then
  begin
    try
      repeat
        RunIgnore(ExpandConstant('{sys}\icacls.exe'), '"' + Dir + '\' + FindRec.Name + '" /reset /C /Q');
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
  if DirExists(Dir + '\Logs') then
    RunIgnore(ExpandConstant('{sys}\icacls.exe'), '"' + Dir + '\Logs\*" /reset /T /C /Q');
end;

procedure AddCertificatesIn(const Dir: String; var Certs: TArrayOfString; var Count: Integer);
var
  FindRec: TFindRec;
begin
  if FindFirst(Dir + '*.cer', FindRec) then
  begin
    try
      repeat
        if (FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY) = 0 then
        begin
          SetArrayLength(Certs, Count + 1);
          Certs[Count] := Dir + FindRec.Name;
          Count := Count + 1;
          LogLine('certificate found: ' + Dir + FindRec.Name);
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

// The package's driver certificate(s): Inst\ (where CI puts the one .cer), else
// next to the drivers (a hand-made package may keep the WDK's exported .cer there).
function FindPackageCertificates(var Certs: TArrayOfString): Integer;
var
  Pkg: String;
begin
  Result := 0;
  SetArrayLength(Certs, 0);
  Pkg := ExpandConstant('{tmp}\pkg\');
  AddCertificatesIn(Pkg + 'Inst\', Certs, Result);
  if Result = 0 then
  begin
    AddCertificatesIn(Pkg + 'SEP\', Certs, Result);
    AddCertificatesIn(Pkg + 'NCM\', Certs, Result);
    AddCertificatesIn(Pkg + 'Bio\', Certs, Result);
  end;
end;

// "a.ps1, b.cer, ..." - what IS in a folder, for an error message.
function ListFolder(const Dir: String): String;
var
  FindRec: TFindRec;
begin
  Result := '';
  if FindFirst(Dir + '*', FindRec) then
  begin
    try
      repeat
        if (FindRec.Name <> '.') and (FindRec.Name <> '..') then
        begin
          if Result <> '' then Result := Result + ', ';
          Result := Result + FindRec.Name;
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
  if Result = '' then Result := '(empty or missing)';
end;

// Puts one certificate into LocalMachine\<Store> and checks it is there.
// certutil first: built into Windows, no PowerShell module involved. Then
// PowerShell's Import-Certificate (what InstallCert.bat uses). The output of both
// goes into Details for the error message.
function ImportCertificateInto(const CertPath, Store: String; var Details: String): Boolean;
var
  ResultCode: Integer;
  Output, Thumb: String;
begin
  Result := False;
  if RunCaptured(ExpandConstant('{sys}\certutil.exe'), '-f -addstore ' + Store + ' "' + CertPath + '"',
       ResultCode, Output) and (ResultCode = 0) then
    Result := True
  else
  begin
    Details := 'certutil -addstore ' + Store + ' (exit ' + IntToStr(ResultCode) + '): ' + Output;
    if RunCaptured(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
         '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Import-Certificate -FilePath ''' +
         PsQuote(CertPath) + ''' -CertStoreLocation Cert:\LocalMachine\' + Store + ' | Out-Null"',
         ResultCode, Output) and (ResultCode = 0) then
      Result := True
    else
      Details := Details + #13#10 + 'Import-Certificate (exit ' + IntToStr(ResultCode) + '): ' + Output;
  end;
  if not Result then Exit;
  // A DER .cer's SHA-1 is the certificate's thumbprint: look it up in the store.
  // (A base64 .cer hashes differently - then the import result has to do.)
  Thumb := GetSHA1OfFile(CertPath);
  if RunCaptured(ExpandConstant('{sys}\certutil.exe'), '-store ' + Store + ' ' + Thumb,
       ResultCode, Output) and (ResultCode = 0) then
    LogLine('certificate ' + Thumb + ' present in LocalMachine\' + Store)
  else
    LogLine('note: thumbprint ' + Thumb + ' not confirmed in LocalMachine\' + Store +
            ' (base64 .cer, or certutil unavailable) - import reported success');
end;

function IsDotNet8DesktopRuntimeInstalled(): Boolean;
var
  FindRec: TFindRec;
  BaseDir: String;
begin
  Result := False;
  BaseDir := ExpandConstant('{commonpf64}\dotnet\shared\Microsoft.WindowsDesktop.App');
  if DirExists(BaseDir) and FindFirst(BaseDir + '\8.*', FindRec) then
  begin
    Result := True;
    FindClose(FindRec);
  end;
end;

// Apple T2 SEP PCI function (T2TouchIdTransport.inf: PCI\VEN_106B&DEV_1802).
// Read from the PnP enum key directly: no PowerShell needed this early.
function T2SepDevicePresent(): Boolean;
var
  Keys: TArrayOfString;
  I: Integer;
begin
  Result := False;
  if not RegGetSubkeyNames(HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Enum\PCI', Keys) then
    Exit;
  for I := 0 to GetArrayLength(Keys) - 1 do
    if Pos('VEN_106B&DEV_1802', Uppercase(Keys[I])) = 1 then
    begin
      Result := True;
      Exit;
    end;
end;

// ---------------------------------------------------------------------------
// Wizard
// ---------------------------------------------------------------------------

procedure InitializeWizard();
begin
  InstallChoicePage := CreateInputOptionPage(wpWelcome,
    'Select Installation Type',
    'What would you like to install?',
    'Select one option, then click Next to continue.',
    True, False);
  InstallChoicePage.Add('Drivers + T2 Touch ID control panel (recommended)');
  InstallChoicePage.Add('Drivers only');
  InstallChoicePage.SelectedValueIndex := 0;

  // Shrink the list to its two rows (Inno sizes it to the whole page), using
  // the control's real row height, and hide the empty scrollbar - same fix
  // as WellspringControlCenter.iss.
  InstallChoicePage.CheckListBox.Height :=
    InstallChoicePage.CheckListBox.Items.Count *
    SendMessage(InstallChoicePage.CheckListBox.Handle, LB_GETITEMHEIGHT, 0, 0);
  ShowScrollBar(InstallChoicePage.CheckListBox.Handle, SB_VERT, False);

  NoAutoRebootCheckBox := TNewCheckBox.Create(WizardForm);
  NoAutoRebootCheckBox.Parent := InstallChoicePage.Surface;
  NoAutoRebootCheckBox.Left := InstallChoicePage.CheckListBox.Left;
  NoAutoRebootCheckBox.Top := InstallChoicePage.CheckListBox.Top +
    InstallChoicePage.CheckListBox.Height + ScaleY(8);
  NoAutoRebootCheckBox.Width := InstallChoicePage.CheckListBox.Width;
  NoAutoRebootCheckBox.Height := ScaleY(42);
  NoAutoRebootCheckBox.Caption := 'I understand what I''m doing and I do NOT want my PC restarted automatically';
  NoAutoRebootCheckBox.Font.Color := clRed;
end;

function InstallGui(): Boolean;
begin
  // 0 = drivers + control panel, 1 = drivers only
  Result := InstallChoicePage.SelectedValueIndex = 0;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = InstallChoicePage.ID then
  begin
    if InstallGui() and (not IsDotNet8DesktopRuntimeInstalled()) then
      SuppressibleMsgBox('.NET 8 Desktop Runtime was not found.' + #13#10 +
        'The T2 Touch ID control panel needs it to start. Install it from ' +
        'https://dotnet.microsoft.com/download/dotnet/8.0 ("Desktop Runtime"). ' +
        'The drivers do not need it - setup will continue.',
        mbInformation, MB_OK, IDOK);

    if NoAutoRebootCheckBox.Checked then
      SuppressibleMsgBox(
        'The drivers will be installed, but your PC will NOT be restarted automatically.' + #13#10#13#10 +
        'Touch ID will not work until you restart Windows yourself.',
        mbInformation, MB_OK, IDOK)
    else
      SuppressibleMsgBox(
        'Installing the drivers requires a restart to finish.' + #13#10#13#10 +
        'Setup will restart your computer automatically after installation.',
        mbInformation, MB_OK, IDOK);
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not T2SepDevicePresent() then
    Result := SuppressibleMsgBox(
      'No Apple T2 Secure Enclave device (PCI\VEN_106B&DEV_1802) was found on this computer.' + #13#10#13#10 +
      'These drivers only work on Intel Macs with the Apple T2 chip running Windows. ' +
      'Continue anyway?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES;
end;

procedure KillRunningApps;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM "' + GuiProcessName + '" /T',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM "' + CliProcessName + '" /T',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(400);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  KillRunningApps;
  Result := '';
end;

// ---------------------------------------------------------------------------
// Driver install
// ---------------------------------------------------------------------------

function RequireFile(const Path: String): Boolean;
begin
  Result := FileExists(Path);
  if not Result then
  begin
    LogLine('missing: ' + Path);
    SuppressibleMsgBox('A required file is missing from this installer:' + #13#10 + Path + #13#10#13#10 +
      'Nothing was removed or changed. Rebuild the package and try again.', mbError, MB_OK, IDOK);
  end;
end;

function InstallDriversNow(): Boolean;
var
  ResultCode, I, CertCount: Integer;
  Pkg, Details: String;
  Certs, Required: TArrayOfString;
begin
  Result := False;
  Pkg := ExpandConstant('{tmp}\pkg\');

  // 4. Validate first: nothing below may run on an incomplete package.
  Required := [
    'SEP\T2TouchIdTransport.inf', 'SEP\T2TouchIdTransport.sys', 'SEP\T2TouchIdTransport.cat',
    'SEP\T2SepBootstrap.exe', 'SEP\T2SepCoInstaller.dll',
    'NCM\apple-t2-composite.inf', 'NCM\apple-t2-ncm.inf', 'NCM\apple-t2-ncm-ctrl-stub.inf',
    'NCM\T2Ncm.sys', 'NCM\T2NcmCtrl.sys',
    'Bio\T2TouchIdBio.inf', 'Bio\T2TouchIdBio.dll', 'Bio\T2TouchIdBio.cat',
    'Bio\T2TouchIdEngineAdapter.dll',
    'Inst\Install-T2TouchIdBio.ps1'];
  for I := 0 to GetArrayLength(Required) - 1 do
    if not RequireFile(Pkg + Required[I]) then
      Exit;

  // 0a. Secure Boot: Test Mode cannot work under it. Checked before anything is
  //     touched, so the user gets the real reason instead of a bcdedit error.
  if SecureBootEnabled() and (not TestSigningActiveNow()) then
  begin
    LogLine('Secure Boot is enabled and Test Mode is not active - driver install not started');
    SuppressibleMsgBox('Secure Boot is turned on.' + #13#10 + #13#10 +
      'With Secure Boot, Windows does not allow Test Mode, so the T2 Touch ID drivers ' +
      '(test-signed) cannot load.' + #13#10 + #13#10 + SecureBootHelpText() + #13#10 + #13#10 +
      'Nothing was changed.', mbError, MB_OK, IDOK);
    Exit;
  end;

  // 0b. This exact build already installed and working? Then the drivers stay as
  //     they are: an update that only changes the control panel needs no restart.
  //     (CI gives every build its own DriverVer; see Test-T2DriversCurrent.ps1.)
  if FileExists(Pkg + 'Inst\Test-T2DriversCurrent.ps1') then
  begin
    SetStatus('Checking the installed drivers...');
    if RunPowerShellFile(Pkg + 'Inst\Test-T2DriversCurrent.ps1',
         '-PackageDir "' + RemoveBackslash(Pkg) + '"', ResultCode) and (ResultCode = 0) then
    begin
      if SuppressibleMsgBox('The drivers in this setup are already installed and working (same build).' + #13#10 + #13#10 +
           'Keep them as they are? No restart is needed then.' + #13#10 +
           'Choose No to reinstall them anyway.', mbConfirmation, MB_YESNO, IDYES) = IDYES then
      begin
        LogLine('drivers unchanged (same build, devices OK) - driver reinstall skipped');
        SecureDataDir; // folders / ACLs of this version (Logs\)
        SetStatus('The drivers are up to date.');
        RebootNeeded := False;
        Result := True;
        Exit;
      end;
      LogLine('drivers unchanged, reinstall requested anyway');
    end;
  end;

  // 3. Certificate(s) - before anything on the machine is changed (services,
  //    Test Mode): without the certificate the drivers cannot be installed at all.
  CertCount := FindPackageCertificates(Certs);
  if CertCount = 0 then
  begin
    LogLine('no .cer in the package; Inst\ holds: ' + ListFolder(Pkg + 'Inst\'));
    SuppressibleMsgBox('The driver certificate (.cer) is missing from this installer.' + #13#10 + #13#10 +
      'The drivers are signed with it; without it Windows refuses to install them. ' +
      'This happens with a package built without the signing secrets (CERT / CERT_PWD).' + #13#10 + #13#10 +
      'Looked in: ' + Pkg + 'Inst\ (and SEP\, NCM\, Bio\)' + #13#10 +
      'Inst\ contains: ' + ListFolder(Pkg + 'Inst\') + #13#10 + #13#10 +
      'Nothing was changed. Log: ' + LogFile, mbError, MB_OK, IDOK);
    Exit;
  end;
  for I := 0 to CertCount - 1 do
  begin
    SetStatus('Importing certificate ' + ExtractFileName(Certs[I]) + '...');
    if (not ImportCertificateInto(Certs[I], 'Root', Details)) or
       (not ImportCertificateInto(Certs[I], 'TrustedPublisher', Details)) then
    begin
      SuppressibleMsgBox('Failed to import the driver certificate ' + ExtractFileName(Certs[I]) + '.' + #13#10 + #13#10 +
        Details + #13#10 + #13#10 +
        'Driver installation was NOT started - nothing was removed. Log: ' + LogFile, mbError, MB_OK, IDOK);
      Exit;
    end;
  end;

  // 1. Release files the INFs are about to replace in System32.
  StopBiometricService;
  SetStatus('Stopping T2SepBootstrap...');
  StopServiceAndWait('T2SepBootstrap');

  // 2. Test Mode.
  SetStatus('Enabling Windows Test Mode...');
  if not EnsureTestSigning(Details) then
  begin
    SuppressibleMsgBox('Could not enable Test Mode (bcdedit /set testsigning on).' + #13#10 + #13#10 +
      'bcdedit said:' + #13#10 + Details + #13#10 + #13#10 +
      'If Secure Boot is on, it must be turned off first. ' + SecureBootHelpText() + #13#10 + #13#10 +
      'Driver installation was NOT completed - nothing was removed.' + #13#10 +
      'Log: ' + LogFile, mbError, MB_OK, IDOK);
    StartBiometricService;
    Exit;
  end;

  // 5. Old packages (only now that the new ones are known to be installable).
  SetStatus('Checking for previous driver versions...');
  RemoveAllDriverPackages;

  // 6. Driver packages.
  SetStatus('Installing Apple T2 SEP transport...');
  if not PnpAddDriver(Pkg + 'SEP\T2TouchIdTransport.inf', True) then Exit;

  SetStatus('Installing Apple T2 composite...');
  if not PnpAddDriver(Pkg + 'NCM\apple-t2-composite.inf', True) then Exit;
  RunIgnore(ExpandConstant('{sys}\pnputil.exe'), '/scan-devices');

  SetStatus('Installing Apple T2 NCM network adapter...');
  if not PnpAddDriver(Pkg + 'NCM\apple-t2-ncm.inf', True) then Exit;
  if not PnpAddDriver(Pkg + 'NCM\apple-t2-ncm-ctrl-stub.inf', True) then Exit;

  // 7. NCM static IPv4 + registry ACL (best effort).
  if FileExists(Pkg + 'Inst\Set-T2NcmStaticIp.ps1') then
  begin
    SetStatus('Configuring the Apple T2 NCM adapter (up to 30 s)...');
    RunPowerShellFile(Pkg + 'Inst\Set-T2NcmStaticIp.ps1', '', ResultCode);
  end;

  // 8. Windows Hello sensor (root node + UMDF driver).
  SetStatus('Installing the Touch ID (Windows Hello) sensor...');
  if (not RunPowerShellFile(Pkg + 'Inst\Install-T2TouchIdBio.ps1',
        '-InfPath "' + Pkg + 'Bio\T2TouchIdBio.inf"', ResultCode)) or (ResultCode <> 0) then
  begin
    SuppressibleMsgBox('Installing the Touch ID sensor driver failed (code ' + IntToStr(ResultCode) + ').' + #13#10#13#10 +
      'The SEP and NCM drivers were installed. Details: ' + LogFile, mbError, MB_OK, IDOK);
    StartBiometricService;
    Exit;
  end;

  // The co-installer of T2TouchIdTransport.inf creates T2SepBootstrap; check
  // it really did - without it the SEP is never unlocked at boot.
  if not ServiceExists('T2SepBootstrap') then
    SuppressibleMsgBox('The T2SepBootstrap service was not created by the SEP driver package.' + #13#10 +
      'Touch ID will stay unavailable after restart. See ' + DataDir() + '\coinstaller.log.',
      mbError, MB_OK, IDOK)
  else if FileExists(Pkg + 'Inst\Set-T2TouchIdWbioStartupDependency.ps1') then
  begin
    // 9. First-boot ordering (best effort).
    SetStatus('Ordering Windows Biometric Service after T2SepBootstrap...');
    RunPowerShellFile(Pkg + 'Inst\Set-T2TouchIdWbioStartupDependency.ps1', '', ResultCode);
  end;

  // 10. Data folder ACL.
  SetStatus('Securing ' + DataDir() + '...');
  SecureDataDir;

  // 11. Bring everything up.
  SetStatus('Refreshing devices...');
  RunIgnore(ExpandConstant('{sys}\pnputil.exe'), '/scan-devices');
  if ServiceExists('T2SepBootstrap') then
    RunIgnore(ExpandConstant('{sys}\sc.exe'), 'start T2SepBootstrap');
  StartBiometricService;

  SetStatus('Drivers installed. Setup will close and the computer will restart shortly...');
  RebootNeeded := True;
  Result := True;
end;

// Inno's own /NORESTART only governs restarts Inno itself would do; this
// script restarts Windows by itself (shutdown.exe), so honor the switch here
// too - an unattended deployment must never get an unexpected reboot.
function NoRestartRequested(): Boolean;
var
  I: Integer;
begin
  Result := NoAutoRebootCheckBox.Checked;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), '/NORESTART') = 0 then
      Result := True;
end;

function RebootStepText(): String;
begin
  if NoRestartRequested() then
    Result := '  5. Leave the restart to you - Touch ID works only after Windows restarts.'
  else
    Result := '  5. Automatically close Setup and restart the computer.';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    ForceDirectories(DataDir());
    LogFile := DataDir() + '\install.log';
    // Repair the folder / log ACLs first (an older Setup could leave the logs
    // unreadable and unwritable, see SecureDataDir), then log.
    SecureDataDir;
    LogLine('==== T2 Touch ID setup {#MyAppVersion} ====');

    if SuppressibleMsgBox(
      'Install the T2 Touch ID drivers now?' + #13#10#13#10 +
      'This will:' + #13#10 +
      '  1. Enable Windows Test Mode (testsigning).' + #13#10 +
      '  2. Import the driver certificate into Trusted Root and Trusted Publishers.' + #13#10 +
      '  3. Replace any previous version of the drivers.' + #13#10 +
      '  4. Install the SEP transport, NCM network and Touch ID sensor drivers' + #13#10 +
      '     and restart Windows Biometric Service.' + #13#10 +
      RebootStepText() + #13#10#13#10 +
      'Save any open work before continuing.',
      mbConfirmation, MB_YESNO, IDYES) = IDYES then
    begin
      DriverInstallOk := InstallDriversNow();
      if not DriverInstallOk then
      begin
        RebootNeeded := False;
        LogLine('driver install did not complete');
      end;
    end
    else
      LogLine('driver install declined by the user');
  end;

  if (CurStep = ssDone) and RebootNeeded and (not NoRestartRequested()) then
  begin
    // /t 0: no countdown, no "your PC will restart" notification to dismiss.
    Exec(ExpandConstant('{sys}\shutdown.exe'), '/r /t 0 /f', '', SW_HIDE, ewNoWait, ResultCode);
    WizardForm.Tag := 1;
    WizardForm.Close;
  end;
end;

// Skip the Finished page (and its "launch" option) when Setup is about to
// restart the PC - the drivers are not usable before that restart anyway.
function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = wpFinished) and RebootNeeded and (not NoRestartRequested());
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpFinished) and (not DriverInstallOk) then
    WizardForm.FinishedLabel.Caption := WizardForm.FinishedLabel.Caption + #13#10#13#10 +
      'The drivers were NOT installed. Run Setup again to install them.';
end;

// ---------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------

procedure DeleteFileReport(const Path: String);
begin
  if FileExists(Path) then
  begin
    if DeleteFile(Path) then
      LogLine('deleted ' + Path)
    else
      LogLine('could NOT delete ' + Path + ' (in use?)');
  end;
end;

procedure RemoveDriversNow;
var
  ResultCode: Integer;
begin
  KillRunningApps;

  // Dependency first: once T2SepBootstrap is deleted, a leftover dependency
  // would stop WbioSrvc from starting at all (error 1075) and take every
  // other biometric device down with it.
  UndoWbioDependency;
  StopBiometricService;

  // Created by the co-installer, not by an INF AddService: pnputil never
  // deletes it.
  SetStatus('Removing the T2SepBootstrap service...');
  StopServiceAndWait('T2SepBootstrap');
  if ServiceExists('T2SepBootstrap') then
    RunIgnore(ExpandConstant('{sys}\sc.exe'), 'delete T2SepBootstrap');

  RemoveBioRootNodes;
  SetStatus('Removing driver packages...');
  RemoveAllDriverPackages;

  // Copied to fixed System32 locations by the INFs (DIRID 11).
  SetStatus('Removing leftover files...');
  DeleteFileReport(ExpandConstant('{sys}\T2SepCoInstaller.dll'));
  DeleteFileReport(ExpandConstant('{sys}\WinBioPlugIns\T2TouchIdEngineAdapter.dll'));
  if DirExists(ExpandConstant('{sys}\T2SepBootstrap')) then
    DelTree(ExpandConstant('{sys}\T2SepBootstrap'), True, True, True);

  // The sensor's WinBio database: records in it only name a macOS user id
  // for this sensor and are meaningless without it.
  RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Services\WbioSrvc\Databases\{#WinBioDatabaseId}');
  // Not through ExpandConstant: it would read the GUID's braces as a constant.
  DeleteFileReport(ExpandConstant('{sys}') + '\WinBioDatabase\' + '{#WinBioDatabaseId}' + '.DAT');

  RunIgnore(ExpandConstant('{sys}\pnputil.exe'), '/scan-devices');
  StartBiometricService;

  if SuppressibleMsgBox(
    'Disable Windows Test Mode (testsigning)?' + #13#10 +
    'Answer No if another test-signed driver on this PC (for example the Wellspring ' +
    'trackpad driver) still needs it.',
    mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES then
    RunLogged(ExpandConstant('{sys}\bcdedit.exe'), '/set testsigning off', ResultCode);
end;

procedure MaybeDeleteSettings;
var
  VaultPath: String;
begin
  if SuppressibleMsgBox(
    'Delete T2 Touch ID settings?' + #13#10 +
    'HKLM\SOFTWARE\T2TouchId and HKLM\SOFTWARE\T2TouchIdBio (logging switches, ' +
    'network/port cache, sensor options).',
    mbConfirmation, MB_YESNO, IDYES) = IDYES then
  begin
    RegDeleteKeyIncludingSubkeys(HKLM64, 'SOFTWARE\T2TouchId');
    RegDeleteKeyIncludingSubkeys(HKLM64, 'SOFTWARE\T2TouchIdBio');
    RegDeleteKeyIncludingSubkeys(HKLM32, 'SOFTWARE\T2TouchId');
    RegDeleteKeyIncludingSubkeys(HKLM32, 'SOFTWARE\T2TouchIdBio');
  end;

  VaultPath := DataDir() + '\sep-vault.bin';
  if FileExists(VaultPath) then
  begin
    if SuppressibleMsgBox(
      'Also delete the encrypted macOS keybag (sep-vault.bin)?' + #13#10#13#10 +
      'Keep it if you plan to reinstall - otherwise you will have to import ' +
      'user.kb and the password again.',
      mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES then
    begin
      LogFile := '';
      DelTree(DataDir(), True, True, True);
    end;
  end
  else
  begin
    LogFile := '';
    DelTree(DataDir(), True, True, True);
  end;
end;

function InitializeUninstall(): Boolean;
begin
  KillRunningApps;
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    ForceDirectories(DataDir());
    LogFile := DataDir() + '\uninstall.log';
    RepairLogAccess; // see SecureDataDir
    LogLine('==== T2 Touch ID uninstall ====');
    RemoveDriversNow;
  end;
  if CurUninstallStep = usPostUninstall then
    MaybeDeleteSettings;
end;
