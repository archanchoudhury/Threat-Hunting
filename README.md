# Threat Hunting- Ransomware Operations

## What is Special About Ransomware?
- Many TTPs are the same as any other attack
- Some TTPs are unique to ransomware
- It's never late to dive into the trench- Remember [Revil](https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/)?

## What is common?
- RaaS(Ransomware-as-a-Service), Advanced groups, cartels- [MAZE](https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html), [Ryuk](https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/), [REvil/Sodinokibi](https://blogs.blackberry.com/en/2019/07/threat-spotlight-sodinokibi-ransomware), [SamSam](https://blogs.blackberry.com/en/2016/03/threat-spotlight-samsa-samsam-ransomware-vs-cylanceprotect);
- Starting point- Crendential Harvesting / Phishing
- Never rely on Simple Backup Recovery Strategies
- Banking Trojan- Emotet & Trickbot
- RDP
- Network appliance/service(Cisco, Citrix, F5, Fortigate, Palo) vulnerabilities.
- They exfiltrate data- So identify **dwell time**

## Ransomware Attack Flow
- They mostly follow APT based attack cycle.
![phases](Images/human-operated-ransomware.jpg)
[Credit](https://www.helpnetsecurity.com/2020/04/30/ransomware-campaigns/) 

## Enrich your Logging First-
- Do you know what you’re currently logging?
- Do you know what you’re not logging?
- Are you augmenting your logs?
- EventLogs- Security, System, PowerShell, Sysmon, Defender, WMI
- Command Line Auditing

### Your References-
- [Windows Logging Cheat Sheet](https://www.malwarearchaeology.com/s/Windows-Logging-Cheat-Sheet_ver_Feb_2019.pdf)
- [Windows ATT&CK Logging Cheat Sheet](https://www.malwarearchaeology.com/s/Windows-ATTCK_Logging-Cheat-Sheet_ver_Sept_2018.pdf)
- [Windows Advanced Logging Cheat Sheet](https://www.malwarearchaeology.com/s/Windows-Advanced-Logging-Cheat-Sheet_ver_Feb_2019_v12.pdf)
- [Windows Sysmon Logging Cheat Sheet](https://www.malwarearchaeology.com/s/Windows-Sysmon-Logging-Cheat-Sheet_Jan_2020-g7sl.pdf)

## Hunting fundamentals

| Category   | Source | Comments |
| -------- | ---------- |---------- |
| Command Line     | Sysmon.evtx     | EventCode=1 | 
| Command Line of Process Execution | Security.evtx       | EventCode=4688 |


| Category   | Source | Comments |
| -------- | ---------- |---------- |
| PowerShell     | Microsoft-Windows-PowerShell%4Operational.evtx     | 4103, 4104 – Script Block logging Logs suspicious scripts by default in PS v5 Logs all scripts if configured |

### Defense Enumeration
- PowerShell/WMI to list out installed AV/Firewall tools
  - ```Select * FROM (AntivirusProduct | FirewallProduct | AntiSpywareProduct)```
  - ```(WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiSpywareProduct Get displayname /format:csv)```
  - ```(WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntivirusProduct Get displayname /format:csv)```
  - ```(WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path FirewallProduct Get displayname /format:csv)```
  - ```wmic process list```
  
- SC.exe execution to list out installed services
  - ```sc query```
  
### Your References
- [WMI logging](https://isc.sans.edu/forums/diary/Keep+an+Eye+on+Your+WMI+Logs/25012/)
- [sc and commandline](https://www.hexacorn.com/blog/2020/08/20/sc-and-its-quirky-cmd-line-args/)

### Disable Defense

| Category   | Source | Comments |
| -------- | ---------- |---------- |
| Services | System.evtx | EventCode=7036 – Service started or stopped, EventCode=7040 – Start type changed |
| Process Exit | Security.evtx | EventCode=4689 YMMV |
| Process Exit | Sysmon | EventCode=5 |
| Service Delete | Sysmon | EventCode=13 |
| Registry | Microsoft-Windows-Sysmon/Operational | EventCode=12, EventCode=13, \HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions |
| Registry | Microsoft-Windows-Windows Defender/Operational | Event ID= 5001, Event ID= 5007 |
| Task Manager | Microsoft-Windows-Sysmon/Operational | EventCode=12-14 |

- Delete Services
  - ```sc delete MpsSvc```

- Kill Processes (Killing any service which is related to security tools)
  - ```CMD/PSH: wmic process “where name like ‘%WinDefend%’” delete```
  - ```Taskkill /IM ccSvcHst.exe ```

- Stop services
  - ```sc stop wuauserv```
  - ```Sc pause MpsSvc```
  - ```net stop SharedAccess```

- PowerShell Execution
  - ```PowerShell Set-MpPreference -DisableRealtimeMonitoring true)```
  - ```PowerShell Add-MpPreference -ExclusionExtension ".exe"```
  - ```PowerShell Set-MpPreference -DisableBehaviorMonitoring true```
  - ```PowerShell Add-MpPreference -ExclusionPath C:```

- Disable Task Manager
  - ```reg.exe add 
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\
System /v DisableTaskMgr /t REG_DWORD /d 1 /f```
- Disable/Corrupt Windows Firewall Rules
  - ```netsh ipsec static set policy name=Bastards assign=y```
  - ```netsh firewall set opmode mode=disable```
  - ```net stop SharedAccess```
  - ```netsh Advfirewall set allprofiles state off```
  
### AntiForensics

| Category   | Source | Comments |
| -------- | ---------- |---------- |
| Clear Event Logs | Security.evtx | EventCode=1102, Security event logs cleared |
| Clear Event Logs | Clear Event Logs | EventCode=104, Any event log was cleared |

- Clear Event Logs
  - ```wevtutil.exe cl Security```
  - ```wevtutil.exe cl Application```
  - ```wevtutil.exe cl System```
  - ```FOR /F “delims=” %%I IN (‘WEVTUTIL EL’) DO (WEVTUTIL CL “%%I”)```
  
- Delete USN journal
  - ```fsutil usn deletejournal /D C:"```
  - ```wevtutil cl Setup & wevtutil cl System & wevtutil cl Security & wevtutil cl 
Application & fsutil usn deletejournal /D %c:```

### Disable Recovery

| Category   | Source | Comments |
| -------- | ---------- |---------- |
| Registry | Microsoft-Windows-Sysmon/Operational | EventCode=12-14 |
| Services | System.evtx | EventCode=7036, 7040, 7045 |

- Disable Windows Auto Startup Repair
  - ```shutdown /r /f /t 00```
  - ```bcdedit /set recoveryenabled no```
  - ```bcdedit /set bootstatuspolicy ignoreallfailures```

- Enforce reboot in safemode
  - ```shutdown /r /f /t 00```
  - ```bcdedit.exe /set safeboot minimal```
  - ```reg add 
HKLM\System\CurrentControlSet\Control\SafeBoot\Minimal\HACKER-service```

### Destroy Backups

| Category   | Source | Comments |
| -------- | ---------- |---------- |
| PowerShell | Microsoft-Windows-PowerShell%4Operational.evtx | Event ID= 4103, 4104 |

- PowerShell
  - ```PowerShell Get-WmiObject Win32_ShadowCopy | Remove-WmiObject```
  - ```PowerShell Get-WmiObject Win32_ShadowCopy | % { _.Delete() }```
  - ```Get-WmiObject Win32_Shadowcopy | ForEach-Object {_.Delete();}```
  - ```Get-ComputerRestorePoint | delete-ComputerRestorePoint```

- Vssadmin.exe
  - ```vssadmin.exe delete shadows /All /Quiet```
  - ```vssadmin.exe resize shadowstorage /for=D: /on=D: /maxsize=401MB```

- Deleting backups via wbadmin
  - ```wbadmin delete catalog -quiet```
  - ```wbadmin DELETE SYSTEMSTATEBACKUP```
  - ```wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest```
  
- Deleting backups with del
  - ```del /s /f /q c:*.VHD c:*.bac c:*.bak c:*.wbcat c:*.bkf c:Backup*.* c:ackup*.* 
c:*.set c:*.win c:*.dsk```

## Hunting for Emotet

- Downloaders often download Emotet as 2-3 digit EXE names: ```.*[\\\/]\d{2,3}\.exe```
- Stage 1 often drops PE files with 8-10 digit names into Windows directory: ```.:\\Windows\\[0-9]{8,10}\.exe```

## Hunting for Trickbot

- Any file got dropped into system ending with 64: 
  - ```.:\\Users\\.+\\AppData\\(Roaming|Local)\\.+\\.+\\.+(32|64)(dll)?\.dll```
- Check for settings.ini files: 
```.:\\Users\\.+\\AppData\\(Roaming|Local)\\.+\\.+\\settings\.ini```

## Hunting for Emotet + Trickbot

- Suspicious EXEs in %APPDATA% 
  - ```.:\\Users\\.+\\AppData\\(Roaming|Local)\\.*\.exe```
- Monitor for EXEs dropped into %ProgramData%, SysWOW64, and Public
  - ```.:\\ProgramData\\.+\.exe```
  - ```.:\\Windows\\SysWOW64\\.*\.exe```
  - ```.:\\Users\\Public\\.*\.exe```
- Monitor for EXE files with 5-10 alpha characters as the filename in the below directories
  - ```.:\\Users\\Public\\[A-Za-z]{5,10}\.exe```
- Odd %UserProfile% locations
  - ```%USERPROFILE%\\(Videos|Music|Pictures)\\.+\.exe```
- Check for services with all-digit names
  - ```\d{8,10} or \d+```

## Hunting for RDP
- 1 external IP to many of your IPs on port 3389
  - ```dest_port=3389 | stats dc(dest_ip) AS DestCount by src_ip | where DestCount > X```
  
- 4624 Logon Type 10s with multiple usernames from 1 IP
  - ```EventID=4624 LogonType=10 | stats dc(TargetUserName) AS UserCount by IpAddress | where UserCount > X ```
  
- GeoIP connections from outside of your operating countries to port 3389
