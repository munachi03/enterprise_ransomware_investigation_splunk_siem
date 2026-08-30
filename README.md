# Enterprise Ransomware Investigation: Splunk SIEM

## Overview

This project documents a SOC-style investigation of a ransomware incident using the Splunk BOTSv1 (Attack-Only) dataset in Splunk Enterprise.

The objective was to investigate a live alert the way a SOC analyst would, start from the alert, pivot through the available telemetry, and build an evidence-based case rather than working backward from known answers. The investigation combined dataset reconnaissance, alert triage, process analysis, network analysis, and lateral movement confirmation to produce a complete incident investigation report.

## Objectives

* Investigate a real IDS alert and determine whether it represented a successful compromise.
* Reconstruct the full attack chain using endpoint and network telemetry.
* Confirm the scope and impact of the incident.
* Extract indicators of compromise (IOCs) and map observed behavior to the MITRE ATT&CK framework.
* Build reusable Splunk detections based on confirmed findings.
* Produce incident response recommendations tied to the investigation.
* Document the investigation as a SOC-style incident report.

## Lab Environment

| Component   | Description                                     |
| ----------- | ----------------------------------------------- |
| Platform    | Splunk Enterprise                               |
| Dataset     | Splunk BOTSv1 (Attack-Only)                     |
| Index       | botsv1                                          |
| Log Sources | Suricata, Sysmon, Windows Security, WinRegistry |

## Tools Used

* Splunk Enterprise
* Splunk Search Processing Language (SPL)
* Splunk BOTSv1 (Attack-Only) dataset
* MITRE ATT&CK Framework

## Investigation Methodology

The investigation followed these stages:

1. Dataset Reconnaissance
2. Investigation Planning (scenario and hypotheses)
3. Initial Detection and Triage
4. Attack Reconstruction
5. IOC Extraction
6. MITRE ATT&CK Mapping
7. Detection Engineering
8. Incident Assessment
9. Incident Response Recommendations

Throughout the investigation, I separated confirmed findings from assumptions. If something couldn't be confirmed using the available logs, I stated that as a limitation instead of treating it as fact.

## Investigation Workflow

```text
Alert
   ↓
Identify affected host
   ↓
Trace process execution
   ↓
Analyze network activity
   ↓
Confirm ransomware behavior
   ↓
Assess impact
   ↓
Extract IOCs
   ↓
Build detections
   ↓
Produce incident report
```

## Key Findings

| Finding                                                                      | Confidence                                                      |
| ---------------------------------------------------------------------------- | --------------------------------------------------------------- |
| Cerber ransomware infection on workstation `we8105desk`                      | High (directly observed)                                        |
| Privilege escalation via repeated self-relaunch (Medium to High integrity)   | High (directly observed)                                        |
| Shadow copy deletion and boot recovery disabled (anti-recovery)              | High (directly observed)                                        |
| Command-and-control communication to external infrastructure                 | High (directly observed)                                        |
| Lateral spread to `we9041srv` fileshare (approximately 640 folders impacted) | High (directly observed)                                        |
| Initial delivery via removable media                                         | Medium (leading hypothesis, not confirmed)                      |
| Specific privilege escalation mechanism                                      | Low (integrity change observed, exact technique not identified) |

Full details for each finding are documented in `documentation/incident-assessment.md`.

## Repository Structure

```text
enterprise_ransomware_investigation_splunk_siem/
│
├── README.md
│
├── documentation/
│   ├── attack-timeline.md
│   ├── iocs.md
│   ├── mitre-attack-mapping.md
│   ├── incident-assessment.md
│   └── ir-recommendations.md
│
├── detections/
│   └── splunk-detections.md
│
├── spl/
│   └── investigation-queries.md
│
└── screenshots/
    └── (Screenshots taken throughout the investigation)
```

## Skills Demonstrated

* SIEM Investigation (Splunk)
* SPL Query Development
* Alert Triage
* Process Tree Analysis
* Network Traffic Analysis
* Incident Timeline Reconstruction
* IOC Extraction
* MITRE ATT&CK Mapping
* Detection Engineering
* Incident Response Planning
* Technical Documentation

## Disclaimer

This investigation was performed using the publicly available Splunk BOTSv1 dataset for educational purposes. It does not represent a real enterprise environment or an actual production incident.
