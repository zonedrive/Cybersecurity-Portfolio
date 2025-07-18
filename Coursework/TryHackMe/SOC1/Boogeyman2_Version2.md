# Boogeyman 2 — Memory Forensics CTF Writeup (Portfolio Edition)

**Note:** This is a TryHackMe Lab CTF.

URL: [https://tryhackme.com/room/boogeyman2]

---

## == START OF INVESTIGATION ==

### Independent Phase: Initial Recon & Execution Flow

**Scenario:** A phishing campaign led to a staged malware infection. My goal was to trace the execution, identify the payload stages, extract malicious binaries, and uncover C2 infrastructure.

* **Phishing Email From:** `[REDACTED_EMAIL]`
* **Victim Email:** `[REDACTED_EMAIL]`

**Malicious Attachment**

* Filename: `Resume_WesleyTaylor.doc` (renamed to `Malware.doc`)
* SHA256: `52c4384a0b9e248b95804352ebec6c5b`

Tool used:

```bash
olevba Malware.doc
```

**Revealed Stage 2 Payload URL**:

```
https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png
```

> Notably, this is a disguised `.exe` file behind a `.png` extension.

**Macro executed via:** `wscript.exe`
**Stage 2 Payload Path:** `C:\ProgramData\update.js`

---

## Volatility 3 Forensic Analysis (Independent Phase)

Memory image used: `WKSTN-2961.raw`

### Plugins used:

```bash
vol -f WKSTN-2961.raw windows.pstree.PsTree
vol -f WKSTN-2961.raw windows.psscan.PsScan
vol -f WKSTN-2961.raw windows.pslist.PsList
vol -f WKSTN-2961.raw windows.strings.Strings
```

### Key Findings:

* PID of `wscript.exe`: **4260**
* Parent process: `WINWORD.EXE` (PID: 1124)
* `windows.strings.Strings` plugin wasn’t fruitful initially

### Honest Note:

> I originally answered question 10 by pasting the answer from question 5 and accidentally "autocorrected" `.png` to `.exe`. It turned out correct, but I wasn’t satisfied. So I paused and researched how to *properly* find the answer. That process is documented below.

---

## Research Phase: Digging Deeper

```bash
vol -f WKSTN-2961.raw windows.filescan | grep -i update
```

Found: `update[1].exe`

Dumped the suspicious file:

```bash
vol -f WKSTN-2961.raw windows.dumpfiles --virtaddr 0xe58f8928f8b0
```

File verification and inspection:

```bash
file 'file.0xe58f8928f8b0...update[1].exe.dat'
cat 'file.0xe58f8928f8b0...update[1].exe.dat'
```

Unfortunately, this didn't show useful content.
So I pivoted to string searches:

```bash
strings WKSTN-2961.raw | grep boogeymanisback.lol
```

**Discovered:**

```
https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe
```

---

## 👁️ C2 and Persistence Discovery

### C2 Discovery

```bash
vol -f WKSTN-2961.raw windows.netscan.NetScan
```

* **C2 IP/Port:** `128.199.95.189:8080`
* **Malicious Binary:** `updater.exe` (PID: 6216)
* **Path:** `C:\Windows\Tasks\Updater.exe`

### Additional IOC

```
\Users\[REDACTED_USER]\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc
```

---

## Persistence Mechanism (Researched)

Tried various searches:

```bash
vol -f WKSTN-2961.raw windows.filescan | grep -i "schedule"
```

Identified relevant Windows Task Scheduler path:

```
\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler
```

Discovered event IDs 106 (task creation) and 140 (task update) might help, but no plugin found to extract them directly.

Eventually:

```bash
strings WKSTN-2961.raw | grep schtasks
```

**Found Persistence Mechanism:**

```powershell
schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR "powershell.exe -NonI -W hidden -c 'IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))'"
```

---

## == END OF INVESTIGATION ==

```
C:\Windows\Tasks\Updater.exe
HKCU:\Software\Microsoft\Windows\CurrentVersion\debug
```

---

## Lessons Learned

* **Validate Guesses:** Accidental correctness isn’t understanding. I corrected myself by seeking the right tools.
* **Volatility Plugin Depth:** `filescan` and `dumpfiles` offer strong binary hunting capability.
* **`.strings` Can Save the Day:** Sometimes simple string searches yield faster results than parsing plugin outputs.
* **C2 Hunting:** Recurring ports and filenames (like `updater.exe` and port `8080`) can signal threat actor habits.
* **Persistence:** Attackers love to bury payloads in scheduled tasks and registry keys. Check both.
* **Walkthroughs as Compass, Not Crutch:** When used to guide your own execution, they strengthen—not weaken—your learning.

---

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
