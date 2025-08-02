# RunAsSystem

Run commands or get an interactive shell as **NT AUTHORITY\SYSTEM**  
Simple, self-contained privilege escalation from Administrator to SYSTEM.

---

## 🚀 Quick Start

1. **Run as Administrator**:  
   Right-click on `run.cmd` → **"Run as administrator"**

2. Confirm UAC prompt.

3. You'll get an interactive PowerShell session running as:  
   `NT AUTHORITY\SYSTEM`

---

## 🔧 What You Can Change

- **Target process** (default: `winlogon.exe`)  
  → Edit the code to use `lsass.exe`, `services.exe`, etc.

- **Launched command** (default: `powershell.exe`)  
  → Change `cmdLine` in code to:
    - `cmd.exe`  
    - `C:\\temp\\reverse.exe`  
    - `whoami /priv`

- **Build type**  
  → Console app (visible) or subsystem:windows (hidden)

---

## 💥 How It Works

1. Enables `SeDebugPrivilege` (needed to access system processes)  
2. Finds PID of `winlogon.exe`  
3. Opens its token (which runs as SYSTEM)  
4. Duplicates token and spawns new process with it  
5. Boom — you’re SYSTEM

---

## ⚠️ Notes

- Requires **Administrator rights**  
- Works on Windows 7, 8, 10, 11, Server  
- May be flagged by AV — this is **not a stealth tool**  
- Built with `cl.exe` (Visual Studio or Build Tools)

---

## 📂 Files

- `Invoke-TokenImpersonation.cpp` — core logic (C++)  
- `run.cmd` — builds and runs the exploit  
- `resource.rc` — optional icon/version (if used)

---

> 💀 You have the power. Use it wisely.
