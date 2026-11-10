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
:: Also removed: the T2SepBootstrap service, the root\T2TouchIdBio device
:: node, the System32 files the INFs copy outside the Driver Store
:: (T2SepCoInstaller.dll, T2SepBootstrap\, WinBioPlugIns engine adapter) and
:: the sensor's WinBio database registration.
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

rem Undo the WbioSrvc -> T2SepBootstrap startup dependency (added by
rem InstallDriver.bat step 7/7) before the drivers go away, so Windows
rem Biometric Service never waits on a service that no longer does its job.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "$k='HKLM:\SYSTEM\CurrentControlSet\Services\WbioSrvc'; $v=(Get-Item -LiteralPath $k).GetValue('DependOnService',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); if($v -and ($v -contains 'T2SepBootstrap')){ $n=[string[]]@($v | Where-Object { $_ -ne 'T2SepBootstrap' }); if($n.Count -gt 0){ Set-ItemProperty -LiteralPath $k -Name DependOnService -Type MultiString -Value $n } else { Remove-ItemProperty -LiteralPath $k -Name DependOnService }; Write-Host 'Removed T2SepBootstrap from WbioSrvc dependencies.' } else { Write-Host 'WbioSrvc has no T2SepBootstrap dependency - nothing to undo.' }"
echo.

rem Windows Biometric Service holds T2TouchIdEngineAdapter.dll (WinBioPlugIns)
rem loaded and has an open session on the Touch ID unit. Stop it before the
rem Bio package and the engine DLL go away; it is started again at the end so
rem any other biometric device keeps working.
echo Stopping Windows Biometric Service...
net stop WbioSrvc /y >nul 2>&1

rem T2SepBootstrap is created by T2SepCoInstaller.dll (not by an INF
rem AddService), so pnputil /delete-driver never removes it. Without this the
rem service stayed AUTO_START after removal and waited 60 s for a transport
rem device that no longer exists on every boot.
echo Stopping and deleting the T2SepBootstrap service...
sc.exe stop T2SepBootstrap >nul 2>&1
call :WAIT_SERVICE_STOPPED T2SepBootstrap
sc.exe delete T2SepBootstrap >nul 2>&1
echo.

rem The Touch ID sensor is a ROOT-enumerated node (Install-T2TouchIdBio.ps1).
rem Deleting its driver package leaves the node behind as an "Unknown device"
rem with no driver; remove the node itself first.
echo Removing the root\T2TouchIdBio device node(s)...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.HardwareID -contains 'root\T2TouchIdBio' } | ForEach-Object { Write-Host ('  ' + $_.InstanceId); & pnputil.exe /remove-device $_.InstanceId | Out-Null }"
echo.

call :REMOVE_INF "apple-t2-ncm-ctrl-stub.inf" "Apple T2 USB NCM Control Interface"
call :REMOVE_INF "apple-t2-ncm.inf"           "Apple T2 USB NCM Network Adapter"
call :REMOVE_INF "T2TouchIdBio.inf"           "Apple T2 Touch ID (Windows Hello sensor)"
call :REMOVE_INF "T2TouchIdTransport.inf"     "Apple T2 SEP Mailbox"
call :REMOVE_INF "apple-t2-composite.inf"     "Apple T2 Controller (Composite)"

echo.
echo --- Files outside the Driver Store ---
rem Copied by the INFs to fixed System32 locations (DIRID 11), which
rem pnputil /delete-driver does not clean up.
call :DEL_FILE "%SystemRoot%\System32\T2SepCoInstaller.dll"
call :DEL_FILE "%SystemRoot%\System32\WinBioPlugIns\T2TouchIdEngineAdapter.dll"
if exist "%SystemRoot%\System32\T2SepBootstrap\" (
    rd /s /q "%SystemRoot%\System32\T2SepBootstrap" >nul 2>&1
    if exist "%SystemRoot%\System32\T2SepBootstrap\" (
        echo   FAILED to delete: %SystemRoot%\System32\T2SepBootstrap
    ) else (
        echo   Deleted: %SystemRoot%\System32\T2SepBootstrap
    )
)

rem WBF database registered by T2TouchIdBio.inf ([T2TouchIdBio_DatabaseAddReg])
rem and its auto-created file. The records in it only name a macOS user id for
rem this sensor and are useless without it.
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc\Databases\{B039A555-3EEC-475A-ABBD-3AA5C5F550DA}" /f >nul 2>&1
call :DEL_FILE "%SystemRoot%\System32\WinBioDatabase\{B039A555-3EEC-475A-ABBD-3AA5C5F550DA}.DAT"

echo.
echo Rescanning devices...
pnputil.exe /scan-devices >nul 2>&1

echo Starting Windows Biometric Service again...
net start WbioSrvc >nul 2>&1

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
echo.

rem ------------------------------------------------------------
rem Optional: disable Windows Test Mode
rem ------------------------------------------------------------
set "TESTMODE_ON=0"
bcdedit /enum | findstr /i "testsigning" >nul
if not errorlevel 1 set "TESTMODE_ON=1"

if "%TESTMODE_ON%"=="0" (
    echo Test Mode does not appear to be enabled. Nothing more to do.
    echo.
    pause
    exit /b 0
)

:ASK_TESTMODE
echo Test Mode is currently enabled on this PC.
echo Drivers that need it have been removed.
echo.
set /p "ANSWER=Disable Test Mode now? [Yes/No]: "
if /i "%ANSWER%"=="Yes" goto DISABLE_TESTMODE
if /i "%ANSWER%"=="No" (
    echo.
    echo Test Mode left enabled.
    echo.
    pause
    exit /b 0
)
echo.
echo Please type Yes or No.
echo.
goto ASK_TESTMODE

:DISABLE_TESTMODE
echo.
echo Disabling Test Mode...
bcdedit /set testsigning off
if errorlevel 1 (
    echo.
    echo [ERROR] Failed to disable Test Mode.
    echo Possible reasons: Secure Boot, or not running as Administrator.
    echo.
    pause
    exit /b 1
)
echo.
echo Test Mode has been DISABLED.
echo Restart Windows for the change to take effect.
echo.
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

:: ============================================================================
:: :DEL_FILE <path>  - best-effort delete with a one-line report.
:: ============================================================================
:DEL_FILE
if not exist "%~1" goto :EOF
del /f /q "%~1" >nul 2>&1
if exist "%~1" (
    echo   FAILED to delete ^(in use? reboot and re-run^): %~1
) else (
    echo   Deleted: %~1
)
goto :EOF

:: ============================================================================
:: :WAIT_SERVICE_STOPPED <name> - waits up to ~15 s for a service to stop.
:: sc query output is localized except for the numeric state, so match the
:: "STATE : 1" (SERVICE_STOPPED) code, not the text.
:: ============================================================================
:WAIT_SERVICE_STOPPED
set /a "_WAIT=0"
:WAIT_SERVICE_LOOP
sc.exe query "%~1" >nul 2>&1
if errorlevel 1 goto :EOF
sc.exe query "%~1" | findstr /r /c:"STATE *: *1 " >nul
if not errorlevel 1 goto :EOF
if %_WAIT% GEQ 15 goto :EOF
set /a "_WAIT+=1"
timeout /t 1 /nobreak >nul
goto WAIT_SERVICE_LOOP
