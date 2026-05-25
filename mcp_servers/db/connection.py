"""
Database connection and persistence helpers for Forensics-MCP.

All writes go through save_investigation_report(), which is called
by the save_investigation MCP tool in synthesis_mcp/server.py.

Uses psycopg2 with DATABASE_URL from the environment (set by Replit's
PostgreSQL integration).  All queries use parameterised placeholders
($1, $2, …) — no string interpolation of user data.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

import psycopg2
import psycopg2.extras

from mcp_servers.shared.models import InvestigationReport

log = logging.getLogger("forensics_db")



def _get_conn() -> psycopg2.extensions.connection:
    """Return a new psycopg2 connection using DATABASE_URL."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set. "
            "Provision the Replit PostgreSQL database first."
        )
    return psycopg2.connect(url, cursor_factory=psycopg2.extras.RealDictCursor)


def save_investigation_report(report: InvestigationReport) -> int:
    """
    Persist a complete InvestigationReport to PostgreSQL.

    Writes:
      1. investigations      — one row (the summary + markdown report)
      2. timeline_events     — one row per TimelineEvent
      3. ioc_items           — one row per IOCItem
      4. mitre_techniques    — one row per MITRETechnique

    Returns the new investigations.id so callers can reference the record.
    """
    s = report.summary

    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:

                # ── 1. investigations row ──────────────────────────────────
                cur.execute(
                    """
                    INSERT INTO investigations (
                        case_name, evidence_path, analysis_timestamp,
                        overall_confidence, confidence_category,
                        attack_flow, attack_sophistication,
                        tactics_count, critical_findings, high_findings,
                        total_timeline_events,
                        compromised_accounts, external_ips, agents_contributed,
                        incident_start, incident_end, report_markdown
                    ) VALUES (
                        %s, %s, %s,
                        %s, %s,
                        %s, %s,
                        %s, %s, %s,
                        %s,
                        %s, %s, %s,
                        %s, %s, %s
                    ) RETURNING id
                    """,
                    (
                        s.case_name,
                        s.evidence_path,
                        s.analysis_timestamp,
                        s.overall_confidence,
                        s.confidence_category,
                        s.attack_flow,
                        s.attack_sophistication,
                        s.tactics_count,
                        s.critical_findings,
                        s.high_findings,
                        s.total_timeline_events,
                        json.dumps(s.compromised_accounts),
                        json.dumps(s.external_ips),
                        json.dumps(s.agents_contributed),
                        s.incident_start,
                        s.incident_end,
                        s.report_markdown,
                    ),
                )
                inv_id: int = cur.fetchone()["id"]
                log.info(f"[db] Created investigations row id={inv_id}")

                # ── 2. timeline_events rows ────────────────────────────────
                if report.timeline:
                    timeline_rows = [
                        (
                            inv_id,
                            e.timestamp,
                            e.event_type,
                            e.attack_phase,
                            e.description,
                            e.source_agent,
                            e.confidence,
                            json.dumps(e.mitre_techniques),
                            e.severity,
                            json.dumps(e.evidence_artifacts),
                            json.dumps(e.details),
                        )
                        for e in report.timeline
                    ]
                    psycopg2.extras.execute_batch(
                        cur,
                        """
                        INSERT INTO timeline_events (
                            investigation_id,
                            event_timestamp, event_type, attack_phase,
                            description, source_agent, confidence,
                            mitre_techniques, severity,
                            evidence_artifacts, details
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        timeline_rows,
                        page_size=200,
                    )
                    log.info(f"[db] Inserted {len(timeline_rows)} timeline_events")

                # ── 3. ioc_items rows ──────────────────────────────────────
                all_iocs = (
                    report.ioc_list.file_iocs
                    + report.ioc_list.network_iocs
                    + report.ioc_list.registry_iocs
                    + report.ioc_list.account_iocs
                )
                if all_iocs:
                    ioc_rows = [
                        (
                            inv_id,
                            ioc.ioc_type,
                            ioc.value,
                            ioc.description,
                            ioc.source_agent,
                            ioc.confidence,
                            ioc.severity,
                        )
                        for ioc in all_iocs
                    ]
                    psycopg2.extras.execute_batch(
                        cur,
                        """
                        INSERT INTO ioc_items (
                            investigation_id,
                            ioc_type, ioc_value, description,
                            source_agent, confidence, severity
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        ioc_rows,
                        page_size=200,
                    )
                    log.info(f"[db] Inserted {len(ioc_rows)} ioc_items")

                # ── 4. mitre_techniques rows ───────────────────────────────
                if report.mitre_techniques:
                    mitre_rows = [
                        (
                            inv_id,
                            t.technique_id,
                            t.technique_name,
                            t.tactic,
                            t.evidence_count,
                            t.max_confidence,
                            t.severity,
                        )
                        for t in report.mitre_techniques
                    ]
                    psycopg2.extras.execute_batch(
                        cur,
                        """
                        INSERT INTO mitre_techniques (
                            investigation_id,
                            technique_id, technique_name, tactic,
                            evidence_count, max_confidence, severity
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        mitre_rows,
                        page_size=200,
                    )
                    log.info(f"[db] Inserted {len(mitre_rows)} mitre_techniques")

        return inv_id

    finally:
        conn.close()


def save_agent_finding(
    investigation_id: int,
    agent_name: str,
    tool_name: str,
    finding: dict[str, Any],
) -> None:
    """
    Persist a single specialist agent finding to agent_findings.

    Called optionally by each specialist MCP server after a tool run,
    before the synthesis agent assembles the final report.  This lets
    you query per-domain findings independently of the final report.
    """
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO agent_findings (
                        investigation_id, agent_name, tool_name,
                        severity, confidence, mitre_technique,
                        suspicious, reason, finding_data
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        investigation_id,
                        agent_name,
                        tool_name,
                        finding.get("severity", "INFO"),
                        finding.get("confidence", 0.0),
                        finding.get("mitre_technique"),
                        bool(finding.get("suspicious", False)),
                        finding.get("reason", ""),
                        json.dumps(finding),
                    ),
                )
    finally:
        conn.close()


def get_investigation(investigation_id: int) -> Optional[dict[str, Any]]:
    """Fetch a full investigation row by ID (for debugging / verification)."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM investigations WHERE id = %s",
                (investigation_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()


def list_investigations(limit: int = 20) -> list[dict[str, Any]]:
    """Return the most recent investigations (summary columns only)."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, case_name, evidence_path, analysis_timestamp,
                       overall_confidence, confidence_category,
                       attack_flow, attack_sophistication,
                       tactics_count, critical_findings, high_findings,
                       incident_start, incident_end, created_at
                FROM investigations
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
