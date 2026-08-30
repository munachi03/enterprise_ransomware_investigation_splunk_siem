# Splunk Detections: Cerber Ransomware Incident

Three detections built from what this investigation found. I kept these intentionally simple, which includes a plain search plus a table, so someone with limited Splunk experience could read the query, understand what it's doing, and replicate it by themselves. These were built specifically from the BOTSv1 dataset and are meant to show the detection logic I used during this investigation rather than act as a production ready detection rule.

---

## Detection 1: Shadow Copy Deletion (Anti-Recovery)

**Objective:** Detect a common ransomware precursor, deletion of Windows Volume Shadow Copies, which removes the victim's built-in recovery option before encryption begins.

```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
("vssadmin.exe" OR "wmic.exe") ("delete shadows" OR "shadowcopy delete")
| spath output=EventID path=Event.System.EventID
| where EventID=1
| spath
| table _time, host, Event.EventData.Data{@Name}, Event.EventData.Data
```

**Logic:** Searches Sysmon process creation events for `vssadmin.exe` or `wmic.exe` being used with shadow copy deletion arguments.

**Expected behavior:** Should almost never fire in normal operations since legitimate shadow copy deletion is rare and typically deliberate.

**False positives:** IT admins manually clearing disk space via shadow copy cleanup, or backup software that occasionally invokes this legitimately. Worth building an allowlist of known admin accounts/hosts if this gets noisy.

**ATT&CK mapping:** T1490, Inhibit System Recovery

**Investigation/pivot:** If this fires, check the parent process, then look for subsequent `bcdedit` activity, then check for mass file modification on any shares that host can reach.

---

## Detection 2: Suspicious Execution of System-Named Binaries

**Objective:** Surface any process execution whose filename matches a common Windows system binary (`osk.exe`, `explorer.exe`), so an analyst can manually check whether it ran from its legitimate location. Also flag any execution of `AdapterTroubleshooter.exe`, since this is not a real Windows utility. Its filename was invented by the malware to look legitimate, so any occurrence of it at all is worth investigating.

```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| spath output=EventID path=Event.System.EventID
| where EventID=1
| spath
| search Event.EventData.Data="*\osk.exe*" OR Event.EventData.Data="*\explorer.exe*" OR Event.EventData.Data="*\AdapterTroubleshooter.exe*"
| table _time, host, Event.EventData.Data
```

**Logic:** Simple keyword search for the filenames in the raw process creation data. No path validation logic is built in. This is a triage query, meant to be manually reviewed rather than used as a high confidence auto alert.

**Expected behavior:** For `osk.exe` and `explorer.exe`, check each result's path against the known good location. `osk.exe` should normally be in `C:\Windows\System32\`, and `explorer.exe` should normally be in `C:\Windows\`. Anything outside those paths is suspicious. For `AdapterTroubleshooter.exe`, there is no legitimate Windows path to compare against. Any result at all should be treated as suspicious.

**False positives:** Legitimate uses of `osk.exe` and `explorer.exe` from their correct paths will also show up here. That's expected, since this is a manual review query rather than a high-confidence auto-fire alert. `AdapterTroubleshooter.exe` should have no legitimate false positives.

**ATT&CK mapping:** T1036, Masquerading

**Investigation/pivot:** For any result where the path doesn't match the legitimate location, or any `AdapterTroubleshooter.exe` result at all, check the ParentImage and any network connections (Sysmon Event ID 3) tied to that ProcessGuid.

---

## Detection 3: C2 Beaconing to Known-Bad Infrastructure

**Objective:** Detect Suricata alerts associated with known trojan or command and control traffic so an analyst can quickly see which internal hosts are talking to known malicious infrastructure.

```spl
index=botsv1 sourcetype=suricata alert.category="A Network Trojan was detected"
| table _time, src_ip, dest_ip, dest_port, alert.signature
```

**Logic:** Simple filter on Suricata's alert category for network trojan detections. It relies on Suricata's own signature matching, with no additional custom logic.

**Expected behavior:** Should rarely fire in normal operations. Any hit is worth investigating.

**False positives:** Low, since this relies on curated IDS signatures rather than heuristics. Signature false positives do happen occasionally with any IDS.

**ATT&CK mapping:** T1071, Application Layer Protocol (Command and Control)

**Investigation/pivot:** Pivot from `src_ip` to Sysmon Event ID 3 on that host to find the process responsible, then use the ProcessGuid to trace the process back through Sysmon Event ID 1 and identify where the process originated.
