@echo off
setlocal EnableExtensions

title T2 TouchID for Windows - Driver Installer

rem ============================================================
rem Require Administrator
rem ============================================================

net session >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] This installer must be run as Administrator.
    echo.
    echo Right-click InstallDriver.bat and select "Run as administrator".
    echo.
    pause
    exit /b 1
)


rem ============================================================
rem Enable Windows Test Mode (required for unsigned drivers)
rem ============================================================

echo [0/7] Enabling Test Mode (bcdedit testsigning)...
echo.

rem Always (re)apply it. The previous check grepped "bcdedit /enum" for the
rem word "testsigning", which ALSO matches "testsigning   No" - an entry that
rem had been explicitly turned off was reported as "already enabled", the set
rem was skipped and the drivers then failed to load (Code 52) after reboot.
rem Setting it again when it is already on is a harmless no-op, and the value
rem itself cannot be parsed reliably (Yes/No is localized).
bcdedit /set testsigning on
if errorlevel 1 (
    echo.
    echo [ERROR] Failed to enable Test Mode.
    echo.
    echo Possible reasons:
    echo   - Secure Boot is enabled in firmware.
    echo   - This script is not running as Administrator.
    echo.
    echo Disable Secure Boot or enable Test Mode manually, then re-run this installer.
    echo.
    pause
    exit /b 1
)
echo [OK] Test Mode enabled. Restart Windows after installation if it was not on already.

echo.

rem ============================================================
rem Base directory
rem ============================================================

set "ROOT=%~dp0"

echo.
echo ============================================================
echo        T2 TouchID for Windows - Driver Installer
echo ============================================================
echo.
echo Root:
echo %ROOT%
echo.

rem ============================================================
rem 1. Install certificate
rem ============================================================

echo [1/7] Installing certificates...
echo.

if not exist "%ROOT%Inst\InstallCert.bat" (
    echo [ERROR] InstallCert.bat not found:
    echo %ROOT%Inst\InstallCert.bat
    echo.
    pause
    exit /b 1
)

call "%ROOT%Inst\InstallCert.bat"

if errorlevel 1 (
    echo.
    echo [ERROR] InstallCert.bat failed.
    echo.
    pause
    exit /b 1
)

echo.
echo [OK] Certificates installed.
echo.

rem ============================================================
rem 2. Install SEP T2TouchIdTransport
rem ============================================================

echo [2/7] Installing SEP T2TouchIdTransport...
echo.

if not exist "%ROOT%SEP\T2TouchIdTransport.inf" (
    echo [ERROR] INF not found:
    echo %ROOT%SEP\T2TouchIdTransport.inf
    echo.
    pause
    exit /b 1
)

pnputil /add-driver "%ROOT%SEP\T2TouchIdTransport.inf" /install
call :PNPUTIL_RESULT

if errorlevel 1 (
    echo.
    echo [ERROR] Failed to install T2TouchIdTransport.
    echo.
    pause
    exit /b 1
)

echo.
echo [OK] T2TouchIdTransport installed.
echo.

rem ============================================================
rem 3. Install NCM composite and refresh device list
rem ============================================================

echo [3/7] Installing Apple T2 composite...
echo.

if not exist "%ROOT%NCM\apple-t2-composite.inf" (
    echo [ERROR] INF not found:
    echo %ROOT%NCM\apple-t2-composite.inf
    echo.
    pause
    exit /b 1
)

pnputil /add-driver "%ROOT%NCM\apple-t2-composite.inf" /install
call :PNPUTIL_RESULT

if errorlevel 1 (
    echo.
    echo [ERROR] Failed to install apple-t2-composite.
    echo.
    pause
    exit /b 1
)

echo.
echo [OK] apple-t2-composite installed.
echo.
echo Refreshing device list...

pnputil /scan-devices

if errorlevel 1 (
    echo.
    echo [WARNING] Device rescan returned an error.
    echo Continuing...
    echo.
)

echo.
echo [OK] Device list refreshed.
echo.

rem ============================================================
rem 4. Install NCM drivers
rem ============================================================

echo [4/7] Installing Apple T2 NCM drivers...
echo.

if not exist "%ROOT%NCM\apple-t2-ncm.inf" (
    echo [ERROR] INF not found:
    echo %ROOT%NCM\apple-t2-ncm.inf
    echo.
    pause
    exit /b 1
)

if not exist "%ROOT%NCM\apple-t2-ncm-ctrl-stub.inf" (
    echo [ERROR] INF not found:
    echo %ROOT%NCM\apple-t2-ncm-ctrl-stub.inf
    echo.
    pause
    exit /b 1
)

echo Installing apple-t2-ncm.inf...
pnputil /add-driver "%ROOT%NCM\apple-t2-ncm.inf" /install
call :PNPUTIL_RESULT

if errorlevel 1 (
    echo.
    echo [ERROR] Failed to install apple-t2-ncm.inf.
    echo.
    pause
    exit /b 1
)

echo.
echo Installing apple-t2-ncm-ctrl-stub.inf...
pnputil /add-driver "%ROOT%NCM\apple-t2-ncm-ctrl-stub.inf" /install
call :PNPUTIL_RESULT

if errorlevel 1 (
    echo.
    echo [ERROR] Failed to install apple-t2-ncm-ctrl-stub.inf.
    echo.
    pause
    exit /b 1
)

echo.
echo [OK] NCM drivers installed.
echo.

rem ============================================================
rem 5. Assign the static IPv4 tunnel address to the T2Ncm adapter
rem ============================================================
rem Without this, the adapter has no IPv4 address at all right after a
rem fresh install (Windows APIPA autoconfig is not instant, and this NCM
rem link may not report media-connect promptly either) - the first
rem Ipv4Tunnel connect attempt then has nothing to bind/route from and
rem fails until 169.254.84.1 is added by hand in Network Settings. This
rem step automates that one manual step; see Set-T2NcmStaticIp.ps1's own
rem header comment for the full rationale. Best-effort: a failure here
rem (e.g. Mac not plugged in yet, adapter not enumerated within 30s) does
rem not abort the install - the script itself logs what to do instead.

echo [5/7] Assigning static IPv4 to Apple T2 NCM adapter...
echo.

if not exist "%ROOT%Inst\Set-T2NcmStaticIp.ps1" (
    echo [WARNING] Inst\Set-T2NcmStaticIp.ps1 not found next to this installer - skipping.
    echo Add 169.254.84.1 to the T2Ncm adapter manually in Network Settings if IPv4 tunnel mode is needed.
    echo.
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass ^
        -File "%ROOT%Inst\Set-T2NcmStaticIp.ps1"
    echo.
)

rem ============================================================
rem 6. Install T2 Touch ID Bio driver
rem ============================================================

echo [6/7] Installing T2 Touch ID biometric driver...
echo.

if not exist "%ROOT%Inst\Install-T2TouchIdBio.ps1" (
    echo [ERROR] PowerShell installer not found:
    echo %ROOT%Inst\Install-T2TouchIdBio.ps1
    echo.
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass ^
    -File "%ROOT%Inst\Install-T2TouchIdBio.ps1"

if errorlevel 1 (
    echo.
    echo [ERROR] Install-T2TouchIdBio.ps1 failed.
    echo.
    pause
    exit /b 1
)


rem ============================================================
rem 7. First-boot ordering: WbioSrvc waits for T2SepBootstrap
rem ============================================================
rem T2SepBootstrap only reports Running after the SEP unlock sequence has
rem finished. Making Windows Biometric Service depend on it stops WBF from
rem creating the Touch ID unit before the SEP is ready, which is what made
rem the first fingerprint scan after a restart get no reaction. The script
rem keeps the existing dependency list, writes a rollback JSON and is
rem idempotent. Best-effort: a failure does not abort the install (the
rem sensor then simply behaves as before). Undone by remove-t2-drivers.bat.

echo [7/7] Ordering Windows Biometric Service after T2SepBootstrap...
echo.

if not exist "%ROOT%Inst\Set-T2TouchIdWbioStartupDependency.ps1" (
    echo [WARNING] Inst\Set-T2TouchIdWbioStartupDependency.ps1 not found - skipping.
    echo.
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass ^
        -File "%ROOT%Inst\Set-T2TouchIdWbioStartupDependency.ps1"
    if errorlevel 1 (
        echo [WARNING] Could not set the WbioSrvc startup dependency - continuing without it.
    )
    echo.
)

rem ============================================================
rem Refresh devices
rem ============================================================

echo Refreshing device list...
pnputil /scan-devices
echo [OK] 


rem ============================================================
rem Restart WbioSrvc
rem ============================================================

net stop WbioSrvc
net start WbioSrvc
echo [OK] 


echo.
echo ============================================================
echo              INSTALLATION COMPLETE
echo ============================================================
echo.
echo If Test Mode was just enabled, restart Windows before using the drivers.
echo.
pause
exit /b 0

rem ============================================================
rem :PNPUTIL_RESULT - maps the pnputil exit code to 0/1.
rem pnputil /add-driver /install returns 3010 (ERROR_SUCCESS_REBOOT_REQUIRED)
rem when the package installed fine but a device needs a restart to switch to
rem it - typical when upgrading over an already-installed version. That used
rem to abort the whole install as "[ERROR] Failed to install".
rem 259 (ERROR_NO_MORE_ITEMS) = package staged, no matching device present
rem right now (e.g. NCM function not enumerated yet) - also not a failure.
rem ============================================================
:PNPUTIL_RESULT
if "%ERRORLEVEL%"=="0" exit /b 0
if "%ERRORLEVEL%"=="3010" (
    echo [INFO] pnputil: installed, a restart is required to finish.
    set "REBOOT_REQUIRED=1"
    exit /b 0
)
if "%ERRORLEVEL%"=="259" (
    echo [INFO] pnputil: package staged, no matching device present right now.
    exit /b 0
)
exit /b 1
