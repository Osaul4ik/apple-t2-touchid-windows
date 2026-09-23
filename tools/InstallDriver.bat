@echo off
setlocal EnableExtensions

title T2 Touch ID Driver Installer

rem ============================================================
rem Require Administrator
rem ============================================================

net session >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] This installer must be run as Administrator.
    echo.
    echo Right-click Install.bat and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

rem ============================================================
rem Base directory
rem ============================================================

set "ROOT=%~dp0"

echo.
echo ============================================================
echo          T2 Touch ID Driver Installer
echo ============================================================
echo.
echo Root:
echo %ROOT%
echo.

rem ============================================================
rem 1. Install certificate
rem ============================================================

echo [1/5] Installing certificates...
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

echo [2/5] Installing SEP T2TouchIdTransport...
echo.

if not exist "%ROOT%SEP\T2TouchIdTransport.inf" (
    echo [ERROR] INF not found:
    echo %ROOT%SEP\T2TouchIdTransport.inf
    echo.
    pause
    exit /b 1
)

pnputil /add-driver "%ROOT%SEP\T2TouchIdTransport.inf" /install

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

echo [3/5] Installing Apple T2 composite...
echo.

if not exist "%ROOT%NCM\apple-t2-composite.inf" (
    echo [ERROR] INF not found:
    echo %ROOT%NCM\apple-t2-composite.inf
    echo.
    pause
    exit /b 1
)

pnputil /add-driver "%ROOT%NCM\apple-t2-composite.inf" /install

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

echo [4/5] Installing Apple T2 NCM drivers...
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
rem 5. Install T2 Touch ID Bio driver
rem ============================================================

echo [5/5] Installing T2 Touch ID biometric driver...
echo.

if not exist "%ROOT%Install-T2TouchIdBio.ps1" (
    echo [ERROR] PowerShell installer not found:
    echo %ROOT%Install-T2TouchIdBio.ps1
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

echo.
echo ============================================================
echo              INSTALLATION COMPLETE
echo ============================================================
echo.
pause
exit /b 0
