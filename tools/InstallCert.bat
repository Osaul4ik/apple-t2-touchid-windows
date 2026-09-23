```bat
@echo off
setlocal

rem %1 = driver base name (no extension), optional.
rem Falls back to the default driver name.
set "DRVNAME=%~1"
if "%DRVNAME%"=="" set "DRVNAME=AmtPtpDeviceUsbKm"

rem ------------------------------------------------------------
rem Find any .cer certificate in the same folder as this script
rem ------------------------------------------------------------
set "CERT="

for %%F in ("%~dp0*.cer") do (
    if not defined CERT set "CERT=%%~fF"
)

rem ------------------------------------------------------------
rem Request Administrator privileges if needed
rem ------------------------------------------------------------
net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator privileges...

    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process -FilePath '%~f0' -ArgumentList '%DRVNAME%' -WorkingDirectory '%~dp0' -Verb RunAs"

    exit /b 0
)

rem ------------------------------------------------------------
rem Check certificate
rem ------------------------------------------------------------
if not defined CERT (
    echo.
    echo [ERROR] No .cer certificate found in:
    echo "%~dp0"
    echo.
    pause
    exit /b 1
)

echo.
echo Found certificate:
echo "%CERT%"
echo.

rem ------------------------------------------------------------
rem Import into Trusted Root
rem ------------------------------------------------------------
echo Importing certificate into Trusted Root...

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Import-Certificate -FilePath '%CERT%' -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null"

if errorlevel 1 (
    echo.
    echo [ERROR] Failed to import the certificate into Trusted Root.
    echo.
    pause
    exit /b 1
)

rem ------------------------------------------------------------
rem Import into Trusted Publishers
rem ------------------------------------------------------------
echo Importing certificate into Trusted Publishers...

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Import-Certificate -FilePath '%CERT%' -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null"

if errorlevel 1 (
    echo.
    echo [ERROR] Failed to import the certificate into Trusted Publishers.
    echo.
    pause
    exit /b 1
)

echo.
echo ==========================================
echo Certificate imported successfully.
echo ==========================================
echo.

pause
exit /b 0
```
