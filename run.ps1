# run.ps1
# Automated launch of Invoke-RunAsSystem from current directory
# Console window will remain open after execution

$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"

# Check for administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Administrator privileges required. Requesting elevation via UAC..."
    try {
        Start-Process powershell.exe "-File `"$PSCommandPath`"" -Verb RunAs -WindowStyle Normal
    } catch {
        Write-Error "Elevation cancelled or blocked."
        Read-Host "Press Enter to exit..."
        exit
    }
    exit
}

# Path to the script
$ScriptPath = ".\Invoke-RunAsSystem.ps1"
if (-not (Test-Path $ScriptPath)) {
    Write-Error "File 'Invoke-RunAsSystem.ps1' not found in the current directory!"
    Read-Host "Press Enter to exit..."
    exit
}

# Load the function
try {
    . $ScriptPath
    Write-Host "[+] Function 'Invoke-RunAsSystem' loaded successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to load script: $($_.Exception.Message)"
    Read-Host "Press Enter to exit..."
    exit
}

# Start SYSTEM session
Write-Host "[*] Starting session as SYSTEM..." -ForegroundColor Cyan
Invoke-RunAsSystem

# Prevent window from closing
Write-Host "`n[INFO] Session ended. The window will remain open." -ForegroundColor Yellow
Read-Host "Press Enter to close the window"