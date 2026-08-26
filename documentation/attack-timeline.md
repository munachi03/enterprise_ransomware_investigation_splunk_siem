# Attack Timeline — Cerber Ransomware Incident

**Host affected:** we8105desk (workstation) → we9041srv (fileshare server)
**User account:** bob.smith
**Date:** 2016-08-24
**All times below are Splunk `_time` (local display time)**

| Time | Host | User | Activity | Evidence | Interpretation |
|---|---|---|---|---|---|
| 17:48:21 | we8105desk | bob.smith | `121214.tmp` launched via `cmd /C START`, CurrentDirectory=`D:\` | Sysmon EventID=1 | **Initial execution** — leading hypothesis: removable media (D:\ working directory); not confirmed via device-connect logs |
| 17:48:29 | we8105desk | bob.smith | `121214.tmp` relaunches itself | Sysmon EventID=1 | Self-relaunch begins |
| 17:48:41 | we8105desk | bob.smith | `121214.tmp` spawns `osk.exe`, then self-deletes (taskkill+del) | Sysmon EventID=1 | Payload handoff + anti-forensics (stage 1 cleanup) |
| 17:48:50 – 17:49:01 | we8105desk | bob.smith | `osk.exe` relaunches itself, then spawns fake `SysWOW64\explorer.exe` | Sysmon EventID=1 | Continued self-relaunch chain |
| 17:49:03 | we8105desk | bob.smith | Fake explorer.exe spawns `AdapterTroubleshooter.exe` (Medium), relaunches at **High integrity** | Sysmon EventID=1 | **Privilege escalation** via self-relaunch (Medium→High) |
| 17:49:11 | we8105desk | bob.smith | Final `osk.exe` (the C2-beaconing instance) launched | Sysmon EventID=1 | Payload fully staged |
| 17:49:23–17:49:24 | we8105desk | bob.smith | `vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit` ×2 | Sysmon EventID=1 | Anti-recovery: shadow copies + boot recovery disabled |
| 17:49:24 onward | we8105desk | (osk.exe process) | C2 beaconing to 85.93.0.0 / 85.93.4.54 / 85.93.43.236 (port 6892) | Suricata alerts + Sysmon EventID=3 | Cerber C2 checkin (matches Suricata alert time exactly) |
| 18:04:33–18:15:11 | we9041srv (fileshare) | bob.smith (via we8105desk) | Ransom notes dropped across 640 folders on `\\*\fileshare` | WinEventLog:Security | **Confirmed spread** — encryption/impact phase |
| 18:15:11–18:15:12 | we8105desk | bob.smith | Local ransom note opened (notepad, wscript, iexplore) | Sysmon EventID=1 | Victim-facing note displayed **immediately after** fileshare sweep completed |
| 18:15:12–18:15:25 | we8105desk | (osk.exe process) | Final onion-domain DNS lookup attempts | Suricata alerts | Final C2 attempt, matches last 2 Suricata alerts |
| 18:15:29 | we8105desk | bob.smith | `osk.exe` self-deletes (taskkill+del) | Sysmon EventID=1 | Final anti-forensics cleanup |

**Total incident duration (initial execution → final self-cleanup): ~27 minutes** (17:48:21 → 18:15:29)
