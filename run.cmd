@echo off
:: Run as Admin and execute PowerShell script

set "SCRIPT_DIR=%~dp0"

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% == 0 goto :RUN_SCRIPT

:: Request UAC elevation
echo Requesting administrator privileges...
powershell.exe -Command "Start-Process cmd.exe -ArgumentList '/c cd /d \"%SCRIPT_DIR%\" && %~nx0' -Verb RunAs"
exit /b

:RUN_SCRIPT
cd /d "%SCRIPT_DIR%"
echo [+] Current directory: %cd%
echo [*] Starting run.ps1 as SYSTEM...
powershell.exe -ExecutionPolicy Bypass -File ".\run.ps1"

echo.
echo [INFO] Press Enter to exit...
pause >nul