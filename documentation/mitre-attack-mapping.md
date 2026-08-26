# MITRE ATT&CK Mapping — Cerber Ransomware Incident

**Host:** we8105desk (initial infection) → we9041srv (fileshare, lateral spread)
**Account:** bob.smith
**Date:** 2016-08-24

| Observed Behavior | Evidence | ATT&CK Technique | Tactic | Confidence |
|---|---|---|---|---|
| Initial execution of `121214.tmp` from a D:\ working directory | Sysmon EventID=1 | Not mapped — insufficient evidence to confirm delivery mechanism (leading hypothesis: removable media, unconfirmed) | Initial Access | Low — observation only, no technique assigned |
| Malware renames itself to mimic legitimate Windows binaries (osk.exe, explorer.exe) | Sysmon EventID=1, file paths outside normal system locations | T1036 – Masquerading | Defense Evasion | High — directly observed |
| Repeated self-relaunch resulting in Medium→High integrity change | Sysmon EventID=1, IntegrityLevel field | Not mapped — exact escalation mechanism not captured in available telemetry | Privilege Escalation | Low — integrity change observed, mechanism unconfirmed |
| Command-line execution via cmd.exe /C START | Sysmon EventID=1 | T1059.003 – Command and Scripting Interpreter: Windows Command Shell | Execution | High — directly observed |
| Deletion of Volume Shadow Copies | Sysmon EventID=1 (`vssadmin delete shadows`, `wmic shadowcopy delete`) | T1490 – Inhibit System Recovery | Impact | High — directly observed |
| Boot recovery disabled via bcdedit | Sysmon EventID=1 | T1490 – Inhibit System Recovery | Impact | High — directly observed |
| C2 beaconing to external IPs over non-standard port | Suricata alerts, Sysmon EventID=3 | T1071 – Application Layer Protocol | Command and Control | High — directly observed |
| DNS lookup for onion-style domain | Suricata alerts | T1071.004 – DNS | Command and Control | High — directly observed |
| Files encrypted, ransom note dropped in 640 folders on fileshare | WinEventLog:Security, Sysmon EventID=1 | T1486 – Data Encrypted for Impact | Impact | High — notes confirmed directly; underlying encryption inferred from notes + Cerber signature match |
| Self-deletion of payload after execution | Sysmon EventID=1 | T1070.004 – File Deletion | Defense Evasion | High — directly observed |

**Methodology note:** Techniques are mapped only where evidence directly supports a specific ATT&CK technique. Two behaviors are documented as "Not mapped" rather than assigning a technique ID that best fits, since available telemetry did not conclusively identify the underlying mechanism for either.
