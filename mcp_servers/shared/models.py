"""
Shared Pydantic models for Forensics-MCP.

Every specialist agent's tool output is typed here so that:
  1. FastMCP validates inputs/outputs via Pydantic before serialising to JSON.
  2. The synthesis agent and DB layer get fully-typed data to work with.
  3. OpenClaw agents receive deterministic, schema-validated JSON over stdio.

Model hierarchy:
    BaseFinding                         — fields common to every finding
    ├── RunKeyFinding                   — persistence: registry run keys
    ├── ServiceFinding                  — persistence: windows services
    ├── ScheduledTaskFinding            — persistence: scheduled tasks
    ├── StartupFinding                  — persistence: startup folders
    ├── WMIFinding                      — persistence: WMI subscriptions
    ├── AuthEvent                       — lateral movement: event log auth events
    ├── JumpListFinding                 — lateral/exfil: jump list entries
    ├── NetworkConnection               — lateral/exfil: memory network connections
    ├── CredentialToolFinding           — credential access: cred-dumping tools
    ├── PasswordFileFinding             — credential access: password files on disk
    ├── BruteForcePattern               — credential access: brute force / spraying
    ├── ExfiltrationEvent               — exfiltration: timeline events
    └── StringsMatch                    — exfiltration: sensitive pattern matches

Synthesis models:
    TimelineEvent                       — normalised cross-agent timeline entry
    MITRETechnique                      — ATT&CK technique with evidence metadata
    IOCItem                             — individual indicator of compromise
    InvestigationSummary                — high-level numbers for the DB row
    InvestigationReport                 — full report container saved to Postgres
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ──────────────────────────────────────────────────────────────────────────────
# Base
# ──────────────────────────────────────────────────────────────────────────────

class BaseFinding(BaseModel):
    """Fields present on every specialist agent finding."""

    suspicious: bool = False
    reason: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    mitre_technique: Optional[str] = None
    severity: str = "INFO"

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: str) -> str:
        allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        return v.upper() if v.upper() in allowed else "INFO"

    @field_validator("confidence")
    @classmethod
    def _clamp_confidence(cls, v: float) -> float:
        return max(0.0, min(1.0, v))


# ──────────────────────────────────────────────────────────────────────────────
# Persistence Agent models
# ──────────────────────────────────────────────────────────────────────────────

class RunKeyFinding(BaseFinding):
    """Registry Run / RunOnce key entry."""
    key: str = ""
    value_name: str = ""
    data: str = ""
    execution_confirmed: bool = False


class ServiceFinding(BaseFinding):
    """Windows service parsed from SYSTEM hive."""
    service_name: str = ""
    executable_path: str = ""
    start_type: Optional[str] = None


class ScheduledTaskFinding(BaseFinding):
    """Windows Scheduled Task parsed from System32/Tasks."""
    task_name: str = ""
    task_path: str = ""
    xml_action: Optional[str] = None
    xml_arguments: Optional[str] = None
    xml_run_as: Optional[str] = None
    xml_trigger: Optional[str] = None
    runs_as_system: bool = False
    execution_confirmed: bool = False


class StartupFinding(BaseFinding):
    """File found in a Windows Startup folder."""
    location: str = ""
    filename: str = ""
    full_path: str = ""
    file_type: str = ""


class WMIFinding(BaseFinding):
    """WMI event subscription persistence entry."""
    filter_name: Optional[str] = None
    consumer_name: Optional[str] = None
    consumer_command: Optional[str] = None
    binding_found: bool = False


# ──────────────────────────────────────────────────────────────────────────────
# Lateral Movement Agent models
# ──────────────────────────────────────────────────────────────────────────────

class AuthEvent(BaseFinding):
    """Windows authentication / logon event."""
    event_id: int = 0
    logon_type: Optional[int] = None
    logon_type_name: Optional[str] = None
    account_name: str = "Unknown"
    source_ip: str = "Unknown"
    share_name: Optional[str] = None
    timestamp: Optional[str] = None


class JumpListFinding(BaseFinding):
    """Jump List entry showing remote connection history."""
    application: str = ""
    target: str = ""
    connection_type: str = ""
    is_internal_target: bool = True
    jump_list_file: str = ""
    cloud_domain: Optional[str] = None


class NetworkConnection(BaseFinding):
    """Active network connection extracted from memory (Volatility netscan)."""
    local_ip: str = ""
    local_port: int = 0
    remote_ip: str = ""
    remote_port: int = 0
    state: str = ""
    process: str = ""
    protocol_type: str = ""
    is_external: bool = False


# ──────────────────────────────────────────────────────────────────────────────
# Credential Access Agent models
# ──────────────────────────────────────────────────────────────────────────────

class CredentialToolFinding(BaseFinding):
    """Credential-dumping tool detected in memory process list."""
    tool_name: str = ""
    pid: int = 0
    ppid: int = 0
    description: str = ""
    lsass_dump_detected: bool = False


class PasswordFileFinding(BaseFinding):
    """Credential-bearing file found on disk."""
    file_path: str = ""
    file_name: str = ""
    match_reason: str = ""
    is_lsass_dump: bool = False
    is_password_manager: bool = False
    is_memory_dump: bool = False


class BrowserCredential(BaseModel):
    """Saved credential entry from a browser database."""
    origin_url: str = ""
    username: str = ""


class BrowserCredentialFinding(BaseFinding):
    """Browser credential database detected on disk image."""
    browser: str = ""
    db_paths: list[str] = Field(default_factory=list)
    credential_count: int = 0
    extracted_credentials: list[BrowserCredential] = Field(default_factory=list)


class BruteForcePattern(BaseFinding):
    """Brute-force or password-spraying pattern detected in event logs."""
    attack_type: str = ""
    source_ip: str = ""
    target_account: Optional[str] = None
    accounts_targeted: Optional[int] = None
    attempt_count: int = 0
    total_attempts: Optional[int] = None


# ──────────────────────────────────────────────────────────────────────────────
# Exfiltration Agent models
# ──────────────────────────────────────────────────────────────────────────────

class ExfiltrationEvent(BaseFinding):
    """File-system or memory event suggesting data collection / staging."""
    event_type: str = ""
    file_path: str = ""
    file_extension: str = ""
    in_staging_location: bool = False


class StringsMatch(BaseFinding):
    """Sensitive pattern found via strings analysis."""
    pattern_type: str = ""
    matches: list[str] = Field(default_factory=list)
    match_count: int = 0
    cloud_domain: Optional[str] = None


class USBDevice(BaseFinding):
    """USB storage device detected in USBSTOR registry."""
    device_name: str = ""
    serial_number: Optional[str] = None
    last_connected: Optional[str] = None
    drive_letter: Optional[str] = None


# ──────────────────────────────────────────────────────────────────────────────
# Synthesis / Timeline models
# ──────────────────────────────────────────────────────────────────────────────

class TimelineEvent(BaseModel):
    """
    A single normalised event in the cross-agent attack timeline.
    Produced by synthesis_mcp.assemble_timeline.
    """
    timestamp: Optional[str] = None
    event_type: str = ""
    attack_phase: str = ""
    description: str = ""
    source_agent: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    mitre_techniques: list[str] = Field(default_factory=list)
    severity: str = "INFO"
    evidence_artifacts: list[Any] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class MITRETechnique(BaseModel):
    """ATT&CK technique with aggregated evidence metadata."""
    technique_id: str
    technique_name: str = ""
    tactic: str = ""
    evidence_count: int = 0
    max_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: str = "INFO"


class IOCItem(BaseModel):
    """A single Indicator of Compromise."""
    ioc_type: str
    value: str
    description: str = ""
    source_agent: Optional[str] = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: str = "MEDIUM"


class IOCList(BaseModel):
    """Full IOC collection produced by synthesis_mcp.generate_ioc_list."""
    file_iocs: list[IOCItem] = Field(default_factory=list)
    network_iocs: list[IOCItem] = Field(default_factory=list)
    registry_iocs: list[IOCItem] = Field(default_factory=list)
    account_iocs: list[IOCItem] = Field(default_factory=list)
    total_iocs: int = 0

    @classmethod
    def from_tool_output(cls, raw: dict[str, Any]) -> "IOCList":
        """Convert the raw dict from generate_ioc_list into a typed IOCList."""

        def _to_items(lst: list[dict[str, Any]], fallback_type: str) -> list[IOCItem]:
            items = []
            for d in (lst or []):
                items.append(IOCItem(
                    ioc_type=d.get("type", fallback_type),
                    value=d.get("value", ""),
                    description=d.get("description", ""),
                    source_agent=d.get("source_agent"),
                    confidence=d.get("confidence", 0.7),
                    severity=d.get("severity", "MEDIUM"),
                ))
            return items

        file_iocs    = _to_items(raw.get("file_iocs", []),     "file")
        network_iocs = _to_items(raw.get("network_iocs", []),  "ip_address")
        registry_iocs= _to_items(raw.get("registry_iocs", []), "registry")
        account_iocs = _to_items(raw.get("account_iocs", []),  "account")

        return cls(
            file_iocs=file_iocs,
            network_iocs=network_iocs,
            registry_iocs=registry_iocs,
            account_iocs=account_iocs,
            total_iocs=len(file_iocs) + len(network_iocs) + len(registry_iocs) + len(account_iocs),
        )


class InvestigationSummary(BaseModel):
    """
    High-level numbers extracted from synthesis outputs.
    These become the top-level columns in the investigations table.
    """
    case_name: str
    evidence_path: str = ""
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow)
    overall_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence_category: str = "UNKNOWN"
    attack_flow: str = ""
    attack_sophistication: str = "UNKNOWN"
    tactics_count: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    total_timeline_events: int = 0
    compromised_accounts: list[str] = Field(default_factory=list)
    external_ips: list[str] = Field(default_factory=list)
    agents_contributed: list[str] = Field(default_factory=list)
    incident_start: str = "Unknown"
    incident_end: str = "Unknown"
    report_markdown: str = ""


class InvestigationReport(BaseModel):
    """
    Full investigation report — persisted to PostgreSQL by save_investigation.

    summary          → investigations table (one row)
    timeline         → timeline_events table (one row per event)
    ioc_list         → ioc_items table (one row per IOC)
    mitre_techniques → mitre_techniques table (one row per technique)
    """
    summary: InvestigationSummary
    timeline: list[TimelineEvent] = Field(default_factory=list)
    ioc_list: IOCList = Field(default_factory=IOCList)
    mitre_techniques: list[MITRETechnique] = Field(default_factory=list)

    @classmethod
    def from_synthesis_outputs(
        cls,
        *,
        case_name: str,
        evidence_path: str,
        report_output: dict[str, Any],
        timeline_output: dict[str, Any],
        mitre_output: Optional[dict[str, Any]] = None,
        ioc_output: Optional[dict[str, Any]] = None,
        confidence_output: Optional[dict[str, Any]] = None,
    ) -> "InvestigationReport":
        """
        Build a fully-typed InvestigationReport from the raw dicts returned
        by each synthesis MCP tool.  This is called inside save_investigation.
        """
        rep_sum  = report_output.get("summary", {})
        conf     = confidence_output or {}

        summary = InvestigationSummary(
            case_name=case_name,
            evidence_path=evidence_path,
            overall_confidence=conf.get("overall_confidence", rep_sum.get("overall_confidence_pct", 0) / 100),
            confidence_category=rep_sum.get("confidence_category", conf.get("confidence_category", "UNKNOWN")),
            attack_flow=rep_sum.get("attack_flow", ""),
            attack_sophistication=rep_sum.get("attack_sophistication", "UNKNOWN"),
            tactics_count=rep_sum.get("tactics_detected", 0),
            critical_findings=rep_sum.get("critical_findings", 0),
            high_findings=rep_sum.get("high_findings", 0),
            total_timeline_events=rep_sum.get("total_timeline_events", 0),
            compromised_accounts=rep_sum.get("compromised_accounts", []),
            external_ips=rep_sum.get("external_ips", []),
            agents_contributed=rep_sum.get("agents_contributed", []),
            incident_start=rep_sum.get("incident_start", "Unknown"),
            incident_end=rep_sum.get("incident_end", "Unknown"),
            report_markdown=report_output.get("report_markdown", ""),
        )

        timeline_events = [
            TimelineEvent(
                timestamp=e.get("timestamp"),
                event_type=e.get("event_type", ""),
                attack_phase=e.get("attack_phase", ""),
                description=e.get("description", ""),
                source_agent=e.get("source_agent", ""),
                confidence=e.get("confidence", 0.0),
                mitre_techniques=e.get("mitre_techniques") or [],
                severity=e.get("severity", "INFO"),
                evidence_artifacts=e.get("evidence_artifacts") or [],
                details=e.get("details") or {},
            )
            for e in (timeline_output.get("timeline") or [])
        ]

        ioc_list = IOCList.from_tool_output(ioc_output or {})

        techniques = [
            MITRETechnique(
                technique_id=t.get("technique_id", ""),
                technique_name=t.get("technique_name", ""),
                tactic=t.get("tactic", ""),
                evidence_count=t.get("evidence_count", 0),
                max_confidence=t.get("max_confidence", 0.0),
                severity=t.get("severity", "INFO"),
            )
            for t in (mitre_output.get("techniques_detected") or [] if mitre_output else [])
        ]

        return cls(
            summary=summary,
            timeline=timeline_events,
            ioc_list=ioc_list,
            mitre_techniques=techniques,
        )
