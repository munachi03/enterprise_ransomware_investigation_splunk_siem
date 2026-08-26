# Indicators of Compromise (IOCs) — Cerber Ransomware Incident

**Host:** we8105desk (initial infection) → we9041srv (fileshare, lateral spread)
**Account:** bob.smith
**Date:** 2016-08-24

## Network Indicators

| Indicator | Type | Where Observed | Why Relevant |
|---|---|---|---|
| 85.93.0.0 | IP (C2) | Suricata alerts; Sysmon EventID=3 (Image=osk.exe) | Cerber C2 checkin destination, port 6892/UDP |
| 85.93.4.54 | IP (C2) | Suricata alerts (ICMP unreachable); Sysmon EventID=3 | Cerber C2 checkin destination — returned unreachable-host response |
| 85.93.43.236 | IP (C2) | Suricata alerts (ICMP unreachable); Sysmon EventID=3 | Cerber C2 checkin destination — same as above |
| 6892/UDP | Port | Suricata alerts; Sysmon EventID=3 | Non-standard port used for all C2 checkin traffic |
| Onion-domain DNS lookup | DNS pattern | Suricata alerts (Cerber Onion Domain Lookup); resolved via 192.168.250.20 | Fallback C2 resolution attempt via Tor-style domain |

## Host Indicators

| Indicator | Type | Where Observed | Why Relevant |
|---|---|---|---|
| `C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\121214.tmp` | File path | Sysmon EventID=1 (we8105desk) | Initial dropper — first observed execution of the core payload |
| `C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-...}\osk.exe` | File path | Sysmon EventID=1 (we8105desk) | Core payload, renamed — masquerades as Windows On-Screen Keyboard; final C2-beaconing instance |
| `C:\Windows\SysWOW64\explorer.exe` | File path | Sysmon EventID=1 (we8105desk) | Masquerading intermediate stage — impersonates legitimate Windows shell |
| `C:\Windows\SysWOW64\QqJXZrBKCk72XzRgZs\AdapterTroubleshooter.exe` | File path | Sysmon EventID=1 (we8105desk) | Masquerading intermediate stage — used for Medium→High integrity self-relaunch |
| `# DECRYPT MY FILES #.html / .txt / .url / .vbs` | Filenames | WinEventLog:Security (we9041srv); Sysmon EventID=1 (we8105desk) | Ransom note dropped in 640 folders on fileshare + displayed locally on victim host |

## File Hashes

| File(s) | SHA1 | MD5 | Notes |
|---|---|---|---|
| `121214.tmp` / `osk.exe` (core payload) | `C8F3F0A33EFE38E9296EF79552C4CADF6CF0BDE6` | `EE0828A4E4C195D97313BFC7D4B531F1` | Same binary, renamed/copied across execution stages — 7 total occurrences (4× osk.exe, 3× 121214.tmp), hash unchanged throughout |
| `SysWOW64\explorer.exe` (fake) | `89A175A12BC20104770D0EF83E553F8B0E06274B` | `40D777B7A95E00593EB1568C68514493` | Distinct binary — masquerading intermediate stage |
| `AdapterTroubleshooter.exe` | `B7202CF005748D0815A2F8B0BD1B2E681CB6C5E2` | `BDFABEDACD6F18B5EFB14B7529F3ED3E` | Distinct binary — consistent hash across both Medium and High integrity relaunches |

## Accounts / Hosts

| Indicator | Type | Where Observed | Why Relevant |
|---|---|---|---|
| we8105desk (192.168.250.100) | Host | All sourcetypes | Patient-zero workstation |
| we9041srv | Host | WinEventLog:Security | Fileshare server — lateral spread target |
| bob.smith | Account | All sourcetypes | Account under which entire attack chain executed |

## Ruled Out

- **Administrator@192.168.69.103** — accessed we9041srv around the same time as the ransom notes were dropped, but this is an already existing pattern: the same account/IP shows up every ~15 minutes going back to August 10, well before the incident. Treated as routine scheduled activity (likely a monitoring or backup job), not part of the attack.
