# Incident Assessment — Cerber Ransomware Incident

**Host:** we8105desk (workstation) → we9041srv (fileshare server)
**Account:** bob.smith
**Date:** 2016-08-24

## Summary

This investigation found that a Cerber ransomware infection started on we8105desk under the bob.smith account. During the attack, the malware escalated its privileges, disabled Windows recovery features, communicated with external command-and-control (C2) servers, and spread to the network fileshare on we9041srv, where ransom notes were dropped across approximately 640 folders.

## Initial Access

The first observed execution was `121214.tmp`, launched from the `D:\` working directory. This suggests the malware may have been run from removable media. I couldn't confirm this, though, since the dataset didn't include USB device connection logs. Based on the available evidence, removable media is the leading hypothesis, not a confirmed finding.

## Affected Systems

The attack involved two systems:

- **we8105desk** – the initially infected workstation
- **we9041srv** – the network fileshare server where the ransomware impacted shared folders

All activity was carried out using the bob.smith user account.

## Attack Impact

After execution, the malware repeatedly relaunched itself under different filenames that resembled legitimate Windows processes, including `osk.exe`, `explorer.exe`, and `AdapterTroubleshooter.exe`. During this process, it moved from Medium integrity to High integrity.

Once elevated, the malware deleted Volume Shadow Copies, modified boot recovery settings, established outbound communication with its command-and-control infrastructure, encrypted files on the network fileshare, displayed a ransom note to the victim, and finally deleted its own executable.

From the first observed execution to the final self-deletion, the attack lasted approximately 27 minutes.

## Assessment

Based on the available logs, I have high confidence in the attack timeline from the initial execution through privilege escalation, command-and-control communication, anti-recovery actions, and the impact on the fileshare. These events were consistently observed across Sysmon, Suricata, and Windows Security logs.

I have lower confidence in the initial delivery method, since there was no USB device telemetry available. Likewise, while the integrity level clearly changed from Medium to High, the dataset doesn't reveal the exact technique used to achieve the privilege escalation.

## Supporting Evidence

The investigation relied on multiple log sources that supported one another:

- **Sysmon Event ID 1** was used to reconstruct the malware execution chain, including the repeated self-relaunches and renamed executables.
- **Sysmon Event ID 3 and Suricata alerts** confirmed outbound communication with the same C2 IP addresses over UDP port 6892 at matching timestamps.
- **Windows Security logs** confirmed that ransom notes were written across approximately 640 folders on the network fileshare during the impact phase.

The complete attack timeline is documented in `attack-timeline.md`, and the indicators of compromise are documented in `iocs.md`.
