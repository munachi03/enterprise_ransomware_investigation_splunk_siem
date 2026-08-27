# Incident Response Recommendations — Cerber Ransomware Incident

**Host:** we8105desk (workstation) → we9041srv (fileshare server)
**Account:** bob.smith
**Date:** 2016-08-24

These recommendations are based on what this investigation actually found. Where a recommendation is standard incident response practice rather than something tied to a specific finding, I've noted that.

## Containment

- **Isolate we8105desk from the network immediately.** This host had confirmed, active C2 communication with three external IPs.
- **Disable the bob.smith account or reset its credentials pending the investigation.** This account was used throughout the entire attack, including the spread to the fileshare.
- **Verify that ransomware activity has stopped on we9041srv.** Approximately 640 folders were already confirmed impacted, so it's important to confirm that no additional files are still being modified.

## Eradication

- **Remove the known-malicious binaries from we8105desk by hash.** The three confirmed hashes are documented in `iocs.md`.
- **Do a full artifact sweep of we8105desk**, not just a check for the specific files this investigation found. That means scanning for other copies of the known hashes, plus checking common persistence locations (Registry Run keys, scheduled tasks, and the Startup folder). Even though this investigation didn't find persistence, I only traced the specific process chains the evidence led me to, not the whole host.
- **Re-image we8105desk instead of trying to clean it manually.** The malware relaunched itself repeatedly under different names, so there's a possibility that malicious artifacts remain. Re-imaging is standard practice for this type of incident, not something I confirmed directly.
- **Check whether any other hosts show the same file hashes or contacted the same C2 IPs.** This investigation only looked at we8105desk because that's where the alert pointed. It wasn't a full environment-wide sweep.

## Recovery

- **Restore the affected fileshare folders from backup.** The workstation's own shadow copies were deleted by the malware, so check whether we9041srv has separate backups that were not affected.
- **Confirm the bcdedit boot recovery settings are restored on we8105desk** before returning the machine to service.

## Prevention

- **Put the three detections from this project into production.** They cover shadow copy deletion, process masquerading, and C2 beaconing to known-bad infrastructure.
- **Look into restricting or monitoring execution from removable media.** This is the leading hypothesis for how the malware was introduced to the system, even though it couldn't be confirmed with the available evidence.
- **Consider application allowlisting where practical** (standard best practice, not tied to a specific finding here). Preventing unauthorized executables from running, especially from removable media or temporary directories, could reduce the likelihood of similar infections.
- **Review whether bob.smith's access follows the principle of least privilege.** The compromised account was able to access approximately 640 folders, so it's worth checking whether that level of access was necessary.
