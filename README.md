# RunAsSystem

> **"There’s more than one way to become SYSTEM."**

Two distinct techniques to escalate from **Administrator → NT AUTHORITY\SYSTEM**:
- 🔹 **Token Impersonation** — steal a SYSTEM token (C++, C#, PowerShell)
- 🔹 **Service-based Execution** — abuse SCM to run code as SYSTEM (`run.cmd`, `run.ps1`)

Choose your path. Both lead to the top.

---

## 🧩 Two Methods. One Goal.

### 1. Token Impersonation (Advanced, stealthy)
> *"I don’t run as SYSTEM — I become it."*

Uses `SeDebugPrivilege` to:
1. Find `winlogon.exe` (or similar SYSTEM process)
2. Open its access token
3. Duplicate it as a primary token
4. Spawn a new process via `CreateProcessWithTokenW`

✅ Runs as pure SYSTEM  
✅ No service traces  
❌ May be blocked by EDR (token manipulation)

**Files:**
- `Invoke-TokenImpersonation.cpp`
- `Invoke-TokenImpersonation.cs`
- `Invoke-TokenImpersonation.ps1`

---

### 2. Service-Based Execution (Simple, reliable)
> *"Let Windows run my code for me — as SYSTEM."*

Uses built-in `sc.exe` (Service Control) to:
1. Create a temporary service
2. Set its command to your payload
3. Start it → runs as `NT AUTHORITY\SYSTEM`
4. Delete itself

✅ Works almost everywhere  
✅ No direct API abuse  
✅ Harder to block without breaking Windows  
❌ Leaves logs (`Event ID 7045`, service creation)

**Files:**
- `run.cmd` — creates service, runs payload, cleans up
- `run.ps1` — PowerShell version of the same

> Example:  
> ```cmd
> sc create RunAsSystem binPath= "cmd /c whoami > C:\temp\out.txt" type= own type= interact
> sc start RunAsSystem
> sc delete RunAsSystem
> ```

---

## 🚀 Quick Start

### 🔹 Method 1: Token Impersonation (C++ — Recommended)
```cmd
run.cmd
