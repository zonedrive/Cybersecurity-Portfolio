# Boogeyman 3 Investigation Report

---

## Overview

This investigation was conducted as part of the "Boogeyman 3" challenge on TryHackMe. The scenario simulates a ransomware attack involving malicious document execution, scheduled task persistence, credential dumping, lateral movement, and domain-wide compromise. The investigation was performed using the ELK Stack and involved detecting malicious artifacts across host logs and PowerShell command executions.

---

## Tools Used

* Elastic Stack (Kibana via Winlogbeat logs)
* CyberChef
* VirusTotal (for external lookup)
* PowerShell command reference

---

## Key Findings

### 1. Initial Access

* Malicious file: `ProjectFinancialSummary_Q3.pdf.hta`
* Execution chain: `mshta.exe` spawned `powershell.exe` to run the HTA payload
* Initial stage PID: **6392**

### 2. File Implantation

* Payload delivery via PowerShell executing xcopy:

```powershell
"C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\[[Redacted]]\AppData\Local\Temp\review.dat
```

### 3. DLL Execution

* Rundll32 used to execute malicious DLL:

```powershell
"C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer
```

* C2 URL found: `hxxp://cdn[.]bananapeelparty[.]net:80`

### 4. Persistence Mechanism

* Scheduled Task: **Review**
* Execution command:

```powershell
powershell.exe -Command New-ScheduledTask ... rundll32.exe execution daily at 06:00
```

### 5. Command and Control (C2)

* Host IP: **10\[.]10\[.]155\[.]159**
* Remote C2 IP and port: **165\[.]232\[.]170\[.]151:80**

### 6. Privilege Escalation (UAC Bypass)

* Technique used: **fodhelper.exe**
* MITRE ATT\&CK ID: **T1548.002** (Bypass User Account Control)

### 7. Credential Dumping Utility

* Tool used: **mimikatz**
* GitHub source: `hxxps://github[.]com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip`

### 8. Extracted Credentials

* NTLM Hash:

```
itadmin:F84769D250EB95EB2D7D8B4A1C5613F2
```

* Username & Password:

```
QUICKLOGISTICS\allan.smith:Tr!ckyP@ssw0rd987
```

### 9. Lateral Movement

* Attacker pivoted from: **WKSTN-0051**
* To: **WKSTN-1327**

### 10. Remote Execution

* Malicious command executed via parent process: **wsmprovhost.exe**
* Secondary access method observed via: `mmc.exe`, `eventvwr.msc`

### 11. Secondary Credential Dump

* Admin hash extracted:

```
administrator:00f80f2538dcb54e7adc715c0e7091ec
```

### 12. Domain Controller (DC) Access

* Hostname: **DC01**
* DCSync attack observed using **mimikatz**
* Additional user targeted: **backupda**

### 13. Ransomware Deployment

* Final payload retrieved from:

```
hxxp://ff[.]sillytechninja[.]io/ransomboogey[.]exe
```

---

## MITRE ATT\&CK Techniques Observed

* T1059: Command and Scripting Interpreter
* T1053.005: Scheduled Task/Job: Scheduled Task
* T1105: Ingress Tool Transfer
* T1548.002: Bypass User Account Control
* T1003.001: Credential Dumping: LSASS Memory
* T1021.002: Remote Services: SMB/Windows Admin Shares
* T1203: Exploitation for Client Execution
* T1003.006: DCSync

---

## Indicators of Compromise (IOCs)

| Type | Value                                                  |
| ---- | ------------------------------------------------------ |
| File | ProjectFinancialSummary\_Q3.pdf.hta                    |
| IP   | 165\[.]232\[.]170\[.]151                               |
| Host | DC01, WKSTN-1327                                       |
| Hash | F84769D250EB95EB2D7D8B4A1C5613F2                       |
| URL  | hxxp\://cdn\[.]bananapeelparty\[.]net:80               |
| URL  | hxxp\://ff\[.]sillytechninja\[.]io/ransomboogey\[.]exe |

---

## Lessons Learned

* Attack chains often begin with highly obfuscated file formats and system-native utilities like `mshta.exe`.
* Scheduled Tasks remain a persistent and undetected method of maintaining access.
* PowerShell logging and wildcard filtering in Kibana are invaluable for identifying encoded payloads and command chains.
* UAC bypass techniques such as `fodhelper.exe` are actively abused and should be monitored via parent-child process chains.
* Lateral movement via harvested credentials must be monitored across hosts using event.code + hostname pairing.
* DCSync activity should raise immediate red flags on domain controllers.

---

**End of Report**
