# Incident Assessment — Cerber Ransomware Incident

**Host:** we8105desk (workstation) → we9041srv (fileshare server)
**Account:** bob.smith
**Date:** 2016-08-24

## What happened?

A ransomware infection (Cerber) executed on workstation we8105desk, escalated its own privileges, disabled Windows recovery mechanisms, communicated with external command-and-control infrastructure, and spread to a network fileshare, dropping ransom notes across 640 folders.

## How did it happen?

The infection chain began with execution of `121214.tmp` from a D:\ working directory — circumstantially consistent with removable media as the delivery method, though this is not conclusively confirmed (no explicit USB device-connection log was reviewed). The malware then underwent a rapid self-relaunch sequence, disguising itself under legitimate-sounding Windows filenames (osk.exe, explorer.exe, AdapterTroubleshooter.exe) while escalating from Medium to High integrity.

## What systems/accounts were affected?

Workstation we8105desk (primary infection) and fileshare server we9041srv (640 folders impacted). Single user account: bob.smith.

## What did the attacker/malware accomplish?

Deleted shadow copies and disabled boot recovery (blocking easy remediation), established C2 communication, encrypted/impacted files across a shared network drive, displayed a ransom note, and self-deleted its payload — a complete ransomware lifecycle within approximately 27 minutes.

## How confident are we?

High confidence on the chain from initial payload execution through C2 beaconing, privilege escalation, anti-recovery actions, and fileshare spread — all directly observed in Sysmon and Suricata telemetry with consistent, corroborating hashes and timestamps. Lower confidence on the true initial delivery vector (USB is the leading hypothesis, not confirmed) and on the precise privilege-escalation mechanism (integrity-level change observed, exact technique not captured).

## What evidence supports the conclusion?

Sysmon process-creation telemetry (EventID=1) tracing the full execution and self-relaunch chain with consistent file hashes across renamed instances; Sysmon network-connection telemetry (EventID=3) and Suricata IDS alerts corroborating the same C2 IPs, port, and timestamps; WinEventLog:Security records confirming ransom-note propagation across 640 fileshare folders within an 11-minute window. Full supporting detail is documented in `attack-timeline.md` and `iocs.md`.
