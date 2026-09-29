@echo off
setlocal EnableDelayedExpansion

:: ============================================================================
:: remove-t2-drivers.bat
:: Removes Apple T2 driver packages from the Windows Driver Store, in a fixed
:: order, matching by each INF's OriginalFileName (not by whatever "oemNN.inf"
:: number Windows happens to have assigned it). Then clears the registry
:: settings written by the drivers and by the T2 Touch ID GUI.
::
:: Driver order:
::   1. apple-t2-ncm-ctrl-stub.inf   (Apple T2 USB NCM Control Interface)
::   2. apple-t2-ncm.inf             (Apple T2 USB NCM Network Adapter)
::   3. T2TouchIdBio.inf             (Apple T2 Touch ID / Windows Hello sensor)
::   4. T2TouchIdTransport.inf       (Apple T2 SEP Mailbox)
::   5. apple-t2-composite.inf       (Apple T2 Controller - Composite)
::
:: Registry cleanup (both the 64-bit and the 32-bit registry view):
::   HKLM\SOFTWARE\T2TouchId      (Network, Session, Logging, Gui settings)
::   HKLM\SOFTWARE\T2TouchIdBio   (ShortVerify, BirVariant, LockOnDisplayOff, PostResumeSettleMs)
::
:: Not touched: %ProgramData%\T2TouchId\sep-vault.bin (your encrypted keybag,
:: so a later reinstall does not need a new import) and installed certificates.
::
:: Requires: Administrator privileges (pnputil /delete-driver needs elevation).
:: ============================================================================

:: --- Require elevation -------------------------------------------------
net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo This script must be run as Administrator.
    pause
    exit /b 1
)

set "LISTFILE=%TEMP%\t2_driver_removal_list.txt"

echo ============================================================
echo  Apple T2 driver removal
echo ============================================================
echo.

call :REMOVE_INF "apple-t2-ncm-ctrl-stub.inf" "Apple T2 USB NCM Control Interface"
call :REMOVE_INF "apple-t2-ncm.inf"           "Apple T2 USB NCM Network Adapter"
call :REMOVE_INF "T2TouchIdBio.inf"           "Apple T2 Touch ID (Windows Hello sensor)"
call :REMOVE_INF "T2TouchIdTransport.inf"     "Apple T2 SEP Mailbox"
call :REMOVE_INF "apple-t2-composite.inf"     "Apple T2 Controller (Composite)"

echo.
echo Rescanning devices...
pnputil.exe /scan-devices >nul 2>&1

:: Registry is cleaned after the drivers are gone, so a driver that is still
:: unloading cannot write its settings back.
echo.
echo --- Registry ---
call :REMOVE_REG "HKLM\SOFTWARE\T2TouchId"
call :REMOVE_REG "HKLM\SOFTWARE\T2TouchIdBio"

if exist "%LISTFILE%" del /f /q "%LISTFILE%" >nul 2>&1

echo.
echo ============================================================
echo  Done.
echo  Kept: %ProgramData%\T2TouchId\sep-vault.bin ^(encrypted keybag^)
echo ============================================================
pause
exit /b 0

:: ============================================================================
:: :REMOVE_INF <inf-name> <friendly-name>
:: Finds every published Driver Store package whose OriginalFileName matches
:: *<inf-name> (via Get-WindowsDriver, English-locale-safe) and deletes each
:: one with pnputil /delete-driver ... /uninstall /force.
:: ============================================================================
:REMOVE_INF
set "INF_NAME=%~1"
set "FRIENDLY=%~2"

echo.
echo --- %FRIENDLY%  (%INF_NAME%) ---

if exist "%LISTFILE%" del /f /q "%LISTFILE%" >nul 2>&1

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "Get-WindowsDriver -Online | Where-Object { $_.OriginalFileName -like '*%INF_NAME%' } | Select-Object -ExpandProperty Driver | Set-Content -Path '%LISTFILE%' -Encoding ascii"

if not exist "%LISTFILE%" (
    echo   No published package found for %INF_NAME%.
    goto :EOF
)

set "FOUND=0"
for /f "usebackq delims=" %%D in ("%LISTFILE%") do (
    set "OEM=%%D"
    if not "!OEM!"=="" (
        set "FOUND=1"
        echo   Removing !OEM! ...
        pnputil.exe /delete-driver "!OEM!" /uninstall /force
    )
)

if "!FOUND!"=="0" (
    echo   No published package found for %INF_NAME%.
)

goto :EOF

:: ============================================================================
:: :REMOVE_REG <hklm-key>
:: Deletes the key and everything under it (including the volatile Session
:: subkey) from both registry views. A missing key is not an error.
:: ============================================================================
:REMOVE_REG
call :REMOVE_REG_VIEW "%~1" 64
call :REMOVE_REG_VIEW "%~1" 32
goto :EOF

:REMOVE_REG_VIEW
reg query "%~1" /reg:%~2 >nul 2>&1
if errorlevel 1 (
    echo   Not present: %~1 [%~2-bit view]
    goto :EOF
)
reg delete "%~1" /f /reg:%~2 >nul 2>&1
if errorlevel 1 (
    echo   FAILED to delete: %~1 [%~2-bit view]
) else (
    echo   Deleted: %~1 [%~2-bit view]
)
goto :EOF