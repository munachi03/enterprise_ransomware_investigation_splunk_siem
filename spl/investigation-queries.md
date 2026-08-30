# Investigation Queries

Key SPL queries I used during this investigation, organized by what each one was used for. These are the queries that produced the findings documented in `attack-timeline.md` and `iocs.md`.

The queries are grouped by the stage of the investigation rather than the order they were run. During the investigation I often went back and reran earlier queries as new evidence was found.

---

## Alert Triage

**Find alerts matching a known threat signature:**

```spl
index=botsv1 sourcetype=suricata alert.signature="*Cerber*"
| table _time, src_ip, dest_ip, dest_port, alert.signature, alert.category
| sort _time
```

**Detect known trojan/C2 category alerts:**

```spl
index=botsv1 sourcetype=suricata alert.category="A Network Trojan was detected"
| table _time, src_ip, dest_ip, dest_port, alert.signature
```

---

## Identifying the Host from an IP Address

**Search Sysmon for an IP to find which host it belongs to:**

```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "<IP address>"
| table _time, host, Event.System.EventID
| head 10
```

---

## Checking Sysmon Coverage for a Host

**See which Sysmon Event IDs exist for the host and how often they appear:**

```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host="<hostname>"
| spath output=EventID path=Event.System.EventID
| stats count by EventID
```

---

## Tracing Process Execution (Sysmon Event ID 1)

**Pull process creation events for a host in a time window:**

```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host="<hostname>"
earliest="MM/DD/YYYY:HH:MM:SS" latest="MM/DD/YYYY:HH:MM:SS"
| spath output=EventID path=Event.System.EventID
| where EventID=1
| spath
| table _time,
