# Incident Assessment — Cerber Ransomware Incident

**Host:** we8105desk (workstation) → we9041srv (fileshare server)
**Account:** bob.smith
**Date:** 2016-08-24

## Summary

This investigation found that a Cerber ransomware infection started on we8105desk under the bob.smith account. The malware escalated its privileges, disabled Windows recovery features, contacted external command-and-control (C2) servers, and eventually spread to the network fileshare on we9041srv, where ransom notes were dropped across 640 folders.

## Initial Access

The first observed execution was `121214.tmp`, launched from the `D:\` working directory. This suggests the malware may have been run from removable media. I didn't check for USB device connection logs in this investigation, so I can't confirm this. Removable media is the leading hypothesis based on the D:\ path alone, not a confirmed finding.

## Affected Systems

The attack involved two systems:

- **we8105desk** – the initially infected workstation
- **we9041srv** – the network fileshare server where the ransomware impacted shared folders

All activity was carried out using the bob.smith user account.

## Attack Impact

After execution, the malware repeatedly relaunched itself under different filenames that resembled legitimate Windows processes, including `osk.exe`, `explorer.exe`, and `AdapterTroubleshooter.exe`. The process was first seen running with Medium integrity and later with High integrity, indicating that privilege escalation occurred.

Once elevated, the malware deleted Volume Shadow Copies, modified boot recovery settings, established outbound communication with its command-and-control infrastructure, encrypted files on the network fileshare, displayed a ransom note to the victim, and finally deleted its own executable. Encrypting the network fileshare significantly increased the impact because files used by multiple users became unavailable.

From the first observed execution to the final self-deletion, the attack lasted approximately 27 minutes.

## Assessment

Based on the available logs, I have high confidence in the attack timeline from the initial execution through privilege escalation, command-and-control communication, anti-recovery actions, and the impact on the fileshare. These events were consistently observed across Sysmon,
