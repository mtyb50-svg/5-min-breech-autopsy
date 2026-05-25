#!/usr/bin/env python3
"""
Synthesis Agent MCP Server — built with FastMCP
================================================
Tools:
  1. assemble_timeline     — merge findings from all agents chronologically
  2. map_mitre_attack      — map findings to MITRE ATT&CK framework
  3. calculate_confidence  — aggregate confidence scores across findings
  4. generate_ioc_list     — extract Indicators of Compromise
  5. generate_report       — produce executive + technical incident report

Evidence dir : ~/lab/
Logs         : mcp_servers/synthesis_mcp/logs/synthesis_mcp.log
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastmcp import FastMCP

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "synthesis_mcp.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("synthesis_mcp")

mcp = FastMCP(
    name="synthesis-mcp-server",
    instructions=(
        "Synthesis MCP server. Combines findings from all specialist agents "
        "(Persistence, Lateral Movement, Exfiltration, Credential Access) into "
        "a unified attack timeline, MITRE ATT&CK mapping, confidence scores, "
        "IOC list, and a final incident report."
    ),
)

TECHNIQUE_TO_TACTIC = {
    "T1566.001": "Initial Access",
    "T1566.002": "Initial Access",
    "T1190": "Initial Access",
    "T1204.002": "Execution",
    "T1059.001": "Execution",
    "T1059.003": "Execution",
    "T1053.005": "Persistence",
    "T1547.001": "Persistence",
    "T1547.009": "Persistence",
    "T1543.003": "Persistence",
    "T1546.003": "Persistence",
    "T1574.001": "Privilege Escalation",
    "T1055": "Defense Evasion",
    "T1070.004": "Defense Evasion",
    "T1003.001": "Credential Access",
    "T1003.002": "Credential Access",
    "T1003.003": "Credential Access",
    "T1552.001": "Credential Access",
    "T1555.003": "Credential Access",
    "T1110.001": "Credential Access",
    "T1110.003": "Credential Access",
    "T1558": "Credential Access",
    "T1555": "Credential Access",
    "T1135": "Discovery",
    "T1021.001": "Lateral Movement",
    "T1021.002": "Lateral Movement",
    "T1021.003": "Lateral Movement",
    "T1021.006": "Lateral Movement",
    "T1570": "Lateral Movement",
    "T1560.001": "Collection",
    "T1041": "Exfiltration",
    "T1048": "Exfiltration",
    "T1052.001": "Exfiltration",
    "T1567.002": "Exfiltration",
    "T1020": "Exfiltration",
}

SEVERITY_WEIGHTS = {"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.5, "INFO": 0.1}

MITRE_NAMES = {
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1204.002": "User Execution: Malicious File",
    "T1053.005": "Scheduled Task/Job",
    "T1547.001": "Boot/Logon Autostart: Registry Run Keys",
    "T1547.009": "Boot/Logon Autostart: Shortcut Modification",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1546.003": "Event Triggered Execution: Windows Management Instrumentation",
    "T1574.001": "Hijack Execution Flow: DLL Search Order Hijacking",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1003.002": "OS Credential Dumping: SAM",
    "T1003.003": "OS Credential Dumping: NTDS",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1555.003": "Credentials from Password Stores: Web Browsers",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1021.006": "Remote Services: Windows Remote Management",
    "T1570": "Lateral Tool Transfer",
    "T1560.001": "Archive Collected Data: Archive via Utility",
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1052.001": "Exfiltration Over Physical Medium: USB",
    "T1567.002": "Exfiltration Over Web Service: Cloud Storage",
    "T1070.004": "Indicator Removal: File Deletion",
    "T1055": "Process Injection",
    "T1135": "Network Share Discovery",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1555": "Credentials from Password Stores",
}


def _parse_timestamp(ts: str) -> Optional[datetime]:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except (ValueError, TypeError):
            continue
    return None


def _severity_order(s: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(s, 0)


@mcp.tool()
async def assemble_timeline(
    persistence_findings: Optional[list[dict[str, Any]]] = None,
    lateral_movement_findings: Optional[list[dict[str, Any]]] = None,
    exfiltration_findings: Optional[list[dict[str, Any]]] = None,
    credential_access_findings: Optional[list[dict[str, Any]]] = None,
    triage_summary: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Merge findings from all specialist agents into a chronological attack timeline.

    Groups events within a 5-second window as related, resolves conflicts,
    and labels each event with its attack phase.

    Args:
        persistence_findings:        List of findings from Persistence Agent
        lateral_movement_findings:   List of findings from Lateral Movement Agent
        exfiltration_findings:       List of findings from Exfiltration Agent
        credential_access_findings:  List of findings from Credential Access Agent
        triage_summary:              Summary dict from Triage Agent
    """
    t0 = time.time()
    log.info("[assemble_timeline] merging agent findings")

    source_map = {
        "persistence": persistence_findings or [],
        "lateral_movement": lateral_movement_findings or [],
        "exfiltration": exfiltration_findings or [],
        "credential_access": credential_access_findings or [],
    }

    timeline_events: list[dict[str, Any]] = []

    for source_agent, findings in source_map.items():
        for finding in findings:
            if not isinstance(finding, dict):
                continue

            timestamp = (
                finding.get("timestamp")
                or finding.get("created_timestamp")
                or finding.get("first_run")
                or finding.get("access_time")
            )

            mitre = finding.get("mitre_technique") or finding.get("mitre_techniques")
            if isinstance(mitre, str):
                mitre = [mitre]
            elif not mitre:
                mitre = []

            tactic = next(
                (TECHNIQUE_TO_TACTIC.get(t) for t in mitre if t in TECHNIQUE_TO_TACTIC),
                source_agent.replace("_", " ").title()
            )

            severity = finding.get("severity", "MEDIUM")
            confidence = finding.get("confidence", 0.5)

            description = (
                finding.get("reason")
                or finding.get("description")
                or finding.get("note")
                or f"{source_agent.replace('_', ' ').title()} finding"
            )

            timeline_events.append({
                "timestamp": timestamp,
                "event_type": source_agent,
                "attack_phase": tactic,
                "description": description,
                "details": finding,
                "source_agent": source_agent,
                "confidence": confidence,
                "mitre_techniques": mitre,
                "severity": severity,
                "evidence_artifacts": finding.get("evidence", []),
            })

    timed = [e for e in timeline_events if e["timestamp"]]
    untimed = [e for e in timeline_events if not e["timestamp"]]

    timed.sort(key=lambda e: _parse_timestamp(e["timestamp"]) or datetime.min)

    sorted_timeline = timed + untimed

    attack_phases = {}
    for event in sorted_timeline:
        phase = event["attack_phase"]
        if phase not in attack_phases:
            attack_phases[phase] = 0
        attack_phases[phase] += 1

    critical_events = [e for e in sorted_timeline if e["severity"] == "CRITICAL"]
    start_time = timed[0]["timestamp"] if timed else "Unknown"
    end_time = timed[-1]["timestamp"] if timed else "Unknown"

    return {
        "status": "OK",
        "timeline": sorted_timeline[:200],
        "total_events": len(sorted_timeline),
        "timed_events": len(timed),
        "untimed_events": len(untimed),
        "critical_events": critical_events[:20],
        "attack_phases_detected": attack_phases,
        "incident_start": start_time,
        "incident_end": end_time,
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def map_mitre_attack(
    timeline: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Map all timeline findings to the MITRE ATT&CK framework.

    Groups techniques by tactic (attack phase), calculates coverage,
    and identifies the primary attack pattern.

    Args:
        timeline: List of timeline events from assemble_timeline
    """
    t0 = time.time()
    log.info("[map_mitre_attack] mapping to ATT&CK")

    tactics_map: dict[str, list[dict[str, Any]]] = {}
    all_techniques: set[str] = set()

    for event in timeline:
        techniques = event.get("mitre_techniques", [])
        if isinstance(techniques, str):
            techniques = [techniques]

        for technique in techniques:
            if not technique:
                continue

            all_techniques.add(technique)
            tactic = TECHNIQUE_TO_TACTIC.get(technique, "Unknown")

            if tactic not in tactics_map:
                tactics_map[tactic] = []

            tactics_map[tactic].append({
                "technique_id": technique,
                "technique_name": MITRE_NAMES.get(technique, technique),
                "event_description": event.get("description", ""),
                "confidence": event.get("confidence", 0.5),
                "severity": event.get("severity", "MEDIUM"),
                "source_agent": event.get("source_agent", "unknown"),
            })

    technique_summary: list[dict[str, Any]] = []
    for technique in sorted(all_techniques):
        tactic = TECHNIQUE_TO_TACTIC.get(technique, "Unknown")
        events_using = [
            e for e in timeline
            if technique in (e.get("mitre_techniques") or [])
        ]
        max_confidence = max((e.get("confidence", 0) for e in events_using), default=0)
        technique_summary.append({
            "technique_id": technique,
            "technique_name": MITRE_NAMES.get(technique, technique),
            "tactic": tactic,
            "evidence_count": len(events_using),
            "max_confidence": round(max_confidence, 2),
            "severity": max(
                (e.get("severity", "LOW") for e in events_using),
                key=_severity_order,
                default="LOW",
            ),
        })

    all_tactics = list(TECHNIQUE_TO_TACTIC.values())
    unique_tactics = list(set(all_tactics))
    tactics_detected = [t for t in unique_tactics if t in tactics_map]
    coverage_pct = round(len(tactics_detected) / max(len(unique_tactics), 1) * 100, 1)

    attack_flow = []
    tactic_order = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Exfiltration", "Impact",
    ]
    for tactic in tactic_order:
        if tactic in tactics_map:
            attack_flow.append(tactic)

    sophistication = (
        "HIGH" if len(tactics_detected) >= 6
        else "MEDIUM" if len(tactics_detected) >= 3
        else "LOW"
    )

    return {
        "status": "OK",
        "tactics_detected": tactics_detected,
        "tactics_count": len(tactics_detected),
        "techniques_detected": technique_summary,
        "total_techniques": len(all_techniques),
        "tactics_breakdown": {k: len(v) for k, v in tactics_map.items()},
        "attack_flow": " → ".join(attack_flow),
        "attack_sophistication": sophistication,
        "tactic_coverage_pct": coverage_pct,
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def calculate_confidence(
    timeline: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Calculate aggregate confidence scores across all findings.

    Uses severity-weighted averaging and evidence count boosting.
    Returns overall confidence and per-phase breakdowns.

    Args:
        timeline: List of timeline events from assemble_timeline
    """
    t0 = time.time()
    log.info("[calculate_confidence] calculating scores")

    if not timeline:
        return {
            "status": "WARNING",
            "message": "No timeline events provided",
            "overall_confidence": 0.0,
            "duration_ms": round((time.time() - t0) * 1000),
        }

    confidences = [e.get("confidence", 0.5) for e in timeline]
    weights = [SEVERITY_WEIGHTS.get(e.get("severity", "MEDIUM"), 1.0) for e in timeline]

    weighted_sum = sum(c * w for c, w in zip(confidences, weights))
    weight_total = sum(weights)
    overall_confidence = round(weighted_sum / max(weight_total, 1), 3)

    evidence_counts: dict[str, int] = {}
    for event in timeline:
        agent = event.get("source_agent", "unknown")
        evidence_counts[agent] = evidence_counts.get(agent, 0) + 1

    evidence_boost = min(0.10, len(evidence_counts) * 0.025)
    final_confidence = min(1.0, overall_confidence + evidence_boost)

    phase_confidence: dict[str, dict[str, Any]] = {}
    for event in timeline:
        phase = event.get("attack_phase", "Unknown")
        if phase not in phase_confidence:
            phase_confidence[phase] = {"values": [], "weights": []}
        phase_confidence[phase]["values"].append(event.get("confidence", 0.5))
        phase_confidence[phase]["weights"].append(
            SEVERITY_WEIGHTS.get(event.get("severity", "MEDIUM"), 1.0)
        )

    phase_summary: dict[str, float] = {}
    for phase, data in phase_confidence.items():
        ws = sum(c * w for c, w in zip(data["values"], data["weights"]))
        wt = sum(data["weights"])
        phase_summary[phase] = round(ws / max(wt, 1), 3)

    if final_confidence >= 0.95:
        category = "CONFIRMED"
    elif final_confidence >= 0.80:
        category = "LIKELY"
    elif final_confidence >= 0.60:
        category = "PROBABLE"
    elif final_confidence >= 0.40:
        category = "POSSIBLE"
    else:
        category = "UNCERTAIN"

    critical_count = sum(1 for e in timeline if e.get("severity") == "CRITICAL")
    high_count = sum(1 for e in timeline if e.get("severity") == "HIGH")

    return {
        "status": "OK",
        "overall_confidence": final_confidence,
        "confidence_category": category,
        "confidence_pct": round(final_confidence * 100, 1),
        "evidence_boost_applied": round(evidence_boost, 3),
        "per_phase_confidence": phase_summary,
        "contributing_agents": list(evidence_counts.keys()),
        "agent_evidence_counts": evidence_counts,
        "total_findings": len(timeline),
        "critical_findings": critical_count,
        "high_findings": high_count,
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def generate_ioc_list(
    timeline: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Extract all Indicators of Compromise (IOCs) from the timeline.

    Produces structured IOC list including:
      - Malicious file paths and hashes
      - Network IOCs (IPs, domains)
      - Registry paths
      - Compromised accounts

    Args:
        timeline: List of timeline events from assemble_timeline
    """
    t0 = time.time()
    log.info("[generate_ioc_list] extracting IOCs")

    file_iocs: list[dict[str, Any]] = []
    network_iocs: list[dict[str, Any]] = []
    registry_iocs: list[dict[str, Any]] = []
    account_iocs: list[dict[str, Any]] = []

    seen_ips: set[str] = set()
    seen_files: set[str] = set()
    seen_accounts: set[str] = set()

    import re

    for event in timeline:
        details = event.get("details", {})
        desc = event.get("description", "")

        ip_matches = re.findall(
            r"\b(?:185|194|45|23|91|104|198)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            str(details) + " " + desc
        )
        for ip in ip_matches:
            if ip not in seen_ips:
                seen_ips.add(ip)
                network_iocs.append({
                    "type": "ip_address",
                    "value": ip,
                    "description": f"Suspicious external IP — {desc[:100]}",
                    "source_agent": event.get("source_agent"),
                    "confidence": event.get("confidence", 0.7),
                    "severity": event.get("severity", "HIGH"),
                })

        file_path = (
            details.get("executable")
            or details.get("file_path")
            or details.get("data")
            or details.get("action")
        )
        if file_path and isinstance(file_path, str) and file_path not in seen_files:
            if any(ext in file_path.lower() for ext in [".exe", ".dll", ".bat", ".ps1", ".dmp"]):
                seen_files.add(file_path)
                is_suspicious_loc = any(
                    s in file_path.lower()
                    for s in ["\\temp\\", "\\downloads\\", "\\appdata\\local\\temp\\"]
                )
                file_iocs.append({
                    "type": "file",
                    "value": file_path,
                    "description": desc[:100],
                    "source_agent": event.get("source_agent"),
                    "confidence": event.get("confidence", 0.7),
                    "severity": "CRITICAL" if "lsass" in file_path.lower() else
                                "HIGH" if is_suspicious_loc else "MEDIUM",
                })

        reg_path = details.get("key") or details.get("registry_path")
        if reg_path and isinstance(reg_path, str):
            registry_iocs.append({
                "type": "registry",
                "value": reg_path,
                "description": desc[:100],
                "source_agent": event.get("source_agent"),
                "confidence": event.get("confidence", 0.7),
            })

        account = details.get("account_name") or details.get("account_used")
        if account and isinstance(account, str) and account not in seen_accounts and account != "Unknown":
            seen_accounts.add(account)
            account_iocs.append({
                "type": "account",
                "value": account,
                "description": f"Compromised/misused account — {desc[:80]}",
                "source_agent": event.get("source_agent"),
                "confidence": event.get("confidence", 0.7),
            })

    return {
        "status": "OK",
        "file_iocs": file_iocs,
        "network_iocs": network_iocs,
        "registry_iocs": registry_iocs,
        "account_iocs": account_iocs,
        "total_iocs": len(file_iocs) + len(network_iocs) + len(registry_iocs) + len(account_iocs),
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def generate_report(
    timeline: list[dict[str, Any]],
    mitre_mapping: Optional[dict[str, Any]] = None,
    confidence_scores: Optional[dict[str, Any]] = None,
    ioc_list: Optional[dict[str, Any]] = None,
    case_name: Optional[str] = None,
    analyst_notes: Optional[str] = None,
) -> dict[str, Any]:
    """
    Generate the final incident analysis report combining all agent findings.

    Produces:
      1. Executive summary (business language, non-technical)
      2. Attack timeline with evidence
      3. MITRE ATT&CK coverage
      4. IOC list
      5. Prioritized recommendations

    Args:
        timeline:          Sorted timeline from assemble_timeline
        mitre_mapping:     ATT&CK mapping from map_mitre_attack
        confidence_scores: Scores from calculate_confidence
        ioc_list:          IOCs from generate_ioc_list
        case_name:         Optional case identifier
        analyst_notes:     Optional analyst context or observations
    """
    t0 = time.time()
    log.info("[generate_report] generating final report")

    case_name = case_name or "FORENSIC-INVESTIGATION"
    analysis_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    overall_confidence = confidence_scores.get("confidence_pct", 0) if confidence_scores else 0
    confidence_category = confidence_scores.get("confidence_category", "UNKNOWN") if confidence_scores else "UNKNOWN"
    attack_flow = mitre_mapping.get("attack_flow", "Unknown") if mitre_mapping else "Unknown"
    tactics_count = mitre_mapping.get("tactics_count", 0) if mitre_mapping else 0
    sophistication = mitre_mapping.get("attack_sophistication", "UNKNOWN") if mitre_mapping else "UNKNOWN"

    critical_events = [e for e in timeline if e.get("severity") == "CRITICAL"]
    high_events = [e for e in timeline if e.get("severity") == "HIGH"]

    incident_start = next(
        (e["timestamp"] for e in timeline if e.get("timestamp")),
        "Unknown"
    )
    incident_end = next(
        (e["timestamp"] for e in reversed(timeline) if e.get("timestamp")),
        "Unknown"
    )

    agents_involved = list({e.get("source_agent", "unknown") for e in timeline})

    compromised_accounts = []
    if ioc_list:
        compromised_accounts = [i["value"] for i in ioc_list.get("account_iocs", [])]

    external_ips = []
    if ioc_list:
        external_ips = [i["value"] for i in ioc_list.get("network_iocs", [])]

    executive_summary = f"""# Incident Analysis Report

**Case:** {case_name}
**Analysis Completed:** {analysis_time}
**Confidence Level:** {overall_confidence}% ({confidence_category})

## Executive Summary

Digital forensic analysis detected evidence of a security incident on the examined system.
The investigation covered {len(agents_involved)} analysis domains and identified {len(critical_events)} critical
and {len(high_events)} high-severity findings.

**Attack Timeline:** {incident_start} → {incident_end}
**Attack Flow:** {attack_flow}
**Attack Sophistication:** {sophistication}
**Tactics Observed:** {tactics_count} of 11 MITRE ATT&CK tactics

**Key Findings:**
"""

    for i, event in enumerate(critical_events[:5], 1):
        executive_summary += f"  {i}. {event.get('description', 'Critical event detected')}\n"

    if compromised_accounts:
        executive_summary += f"\n**Compromised Accounts:** {', '.join(compromised_accounts[:5])}\n"

    if external_ips:
        executive_summary += f"**External C2/Exfiltration IPs:** {', '.join(external_ips[:5])}\n"

    if analyst_notes:
        executive_summary += f"\n**Analyst Notes:** {analyst_notes}\n"

    timeline_section = "\n## Attack Timeline\n\n"
    for event in timeline[:50]:
        ts = event.get("timestamp", "Unknown Time")
        severity = event.get("severity", "INFO")
        phase = event.get("attack_phase", "Unknown")
        desc = event.get("description", "")
        techniques = ", ".join(event.get("mitre_techniques", []))
        conf = round(event.get("confidence", 0) * 100)

        timeline_section += (
            f"**{ts}** [{severity}] — {phase}\n"
            f"- {desc}\n"
        )
        if techniques:
            timeline_section += f"- MITRE ATT&CK: {techniques}\n"
        timeline_section += f"- Confidence: {conf}%\n\n"

    mitre_section = "\n## MITRE ATT&CK Coverage\n\n"
    if mitre_mapping:
        mitre_section += f"**Attack Sophistication:** {sophistication}\n"
        mitre_section += f"**Tactic Coverage:** {mitre_mapping.get('tactic_coverage_pct', 0)}%\n\n"
        for technique in mitre_mapping.get("techniques_detected", [])[:20]:
            mitre_section += (
                f"- **{technique['technique_id']}** — {technique['technique_name']} "
                f"[{technique['tactic']}] (confidence: {round(technique['max_confidence'] * 100)}%)\n"
            )

    ioc_section = "\n## Indicators of Compromise (IOCs)\n\n"
    if ioc_list:
        if ioc_list.get("file_iocs"):
            ioc_section += "### Malicious Files\n"
            for ioc in ioc_list["file_iocs"][:10]:
                ioc_section += f"- `{ioc['value']}` — {ioc['description']}\n"

        if ioc_list.get("network_iocs"):
            ioc_section += "\n### Network IOCs\n"
            for ioc in ioc_list["network_iocs"][:10]:
                ioc_section += f"- `{ioc['value']}` — {ioc['description']}\n"

        if ioc_list.get("account_iocs"):
            ioc_section += "\n### Compromised Accounts\n"
            for ioc in ioc_list["account_iocs"][:10]:
                ioc_section += f"- `{ioc['value']}` — {ioc['description']}\n"

    recommendations = """
## Recommendations

### Immediate Actions (0-24 hours)
1. **CRITICAL:** Isolate all identified compromised systems from the network
2. **CRITICAL:** Reset passwords for all compromised and administrative accounts
3. **CRITICAL:** Block identified external C2/exfiltration IP addresses at firewall
4. **HIGH:** Revoke all active sessions and authentication tokens
5. **HIGH:** Scan network for all identified IOCs

### Short-Term (1-7 days)
6. Perform forensic analysis on all systems that had network contact with compromised hosts
7. Identify and quarantine the initial infection vector
8. Hunt for similar IOCs across the entire environment
9. Review and audit all privileged account usage

### Long-Term (1-3 months)
10. Deploy EDR (Endpoint Detection and Response) solution
11. Implement MFA for all administrative and privileged accounts
12. Restrict LSASS memory access (LSA Protection, Windows Credential Guard)
13. Deploy email security gateway with attachment sandboxing
14. Implement network segmentation to limit lateral movement
15. Establish SOC monitoring with alerting on identified IOC patterns
"""

    full_report = executive_summary + timeline_section + mitre_section + ioc_section + recommendations

    return {
        "status": "OK",
        "case_name": case_name,
        "analysis_timestamp": analysis_time,
        "report_markdown": full_report,
        "summary": {
            "incident_start": incident_start,
            "incident_end": incident_end,
            "overall_confidence_pct": overall_confidence,
            "confidence_category": confidence_category,
            "attack_flow": attack_flow,
            "attack_sophistication": sophistication,
            "tactics_detected": tactics_count,
            "critical_findings": len(critical_events),
            "high_findings": len(high_events),
            "total_timeline_events": len(timeline),
            "compromised_accounts": compromised_accounts[:10],
            "external_ips": external_ips[:10],
            "agents_contributed": agents_involved,
        },
        "duration_ms": round((time.time() - t0) * 1000),
    }


if __name__ == "__main__":
    log.info("-" * 60)
    log.info("Synthesis MCP Server (FastMCP) starting")
    log.info(f"  Logs : {LOG_DIR}")
    log.info("-" * 60)
    mcp.run()
