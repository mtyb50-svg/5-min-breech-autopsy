import asyncio
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain.agents import create_agent
from pydantic import BaseModel, Field
from typing import Any, Literal

from langchain_huggingface import ChatHuggingFace, HuggingFaceEndpoint

import getpass
import os
from dotenv import load_dotenv

load_dotenv()

if not os.getenv("HUGGINGFACEHUB_API_TOKEN"):
    os.environ["HUGGINGFACEHUB_API_TOKEN"] = getpass.getpass("Enter your token: ")

from langchain_huggingface import ChatHuggingFace, HuggingFaceEndpoint
from typing import Any

class PatchedChatHuggingFace(ChatHuggingFace):
    """
    Workaround for HuggingFace's bind_tools limitation:
    it rejects tool_choice when multiple tools are bound.
    create_agent internally passes tool_choice, so we silently
    drop it when there's more than one tool.
    """
    def bind_tools(self, tools: list, **kwargs: Any):
        if len(tools) > 1 and "tool_choice" in kwargs:
            kwargs.pop("tool_choice")
        return super().bind_tools(tools, **kwargs)


llm = HuggingFaceEndpoint(
    repo_id="deepseek-ai/DeepSeek-R1-0528",
    task="text-generation",
    do_sample=False,
    repetition_penalty=1.03,
    provider="auto",
)

chat_model = PatchedChatHuggingFace(llm=llm)  # ← swap this in, nothing else changes


class EvidenceMeta(BaseModel):
    file_name:    str
    file_path:    str
    sha256:       str
    size_gb:      float
    evidence_type: Literal["disk_image", "memory_dump", "archive", "unknown"]
    format:       str                   # E01/EWF, RAW/DD, VMEM, etc.
    filesystem:   str                   # NTFS, EXT4/3/2, FAT32, HFS+/APFS, Unknown
    os_detected:  str                   # Windows 10, Ubuntu Linux, etc.
    partition_table: str | None = None  # raw mmls output if available

class OsInfo(BaseModel):
    os_family:   Literal["Windows", "Linux", "macOS", "Unknown"]
    os_version:  str                    # e.g. "Windows 10", "Ubuntu Linux"
    filesystem:  str
    evidence_type: str

class ArtifactInventory(BaseModel):
    # --- Windows ---
    has_registry:        bool = False
    registry_hives:      list[str] = Field(default_factory=list)   # ["SOFTWARE","SAM",...]
    has_prefetch:        bool = False
    prefetch_count:      int  = 0
    has_event_logs:      bool = False
    event_log_files:     list[str] = Field(default_factory=list)
    event_log_count:     int  = 0
    has_mft:             bool = False
    has_usnjrnl:         bool = False
    has_pagefile:        bool = False
    has_hiberfil:        bool = False
    has_jump_lists:      bool = False
    has_lnk_files:       bool = False
    has_scheduled_tasks: bool = False
    has_startup_items:   bool = False
    has_recycle_bin:     bool = False
    has_amcache:         bool = False
    has_srum:            bool = False
    has_sam_database:    bool = False
    has_browser_artifacts: bool = False
    browsers_found:      list[str] = Field(default_factory=list)   # ["Chrome","Edge"]
    # --- Linux ---
    has_syslog:          bool = False
    has_auth_log:        bool = False
    has_bash_history:    bool = False
    has_crontabs:        bool = False
    has_passwd:          bool = False
    has_shadow:          bool = False
    has_ssh_keys:        bool = False
    has_journal:         bool = False
    # --- Shared ---
    has_memory:          bool = False
    has_network_artifacts: bool = False
    total_files_indexed: int  = 0

class IocFindings(BaseModel):
    # Each entry from quick_threat_scan tool, kept as-is
    suspicious_files:  list[dict[str, Any]] = Field(default_factory=list)  # {path, reason, risk}
    yara_hits:         list[dict[str, Any]] = Field(default_factory=list)  # {rule, file, rule_source, severity}
    clamav_hits:       list[dict[str, Any]] = Field(default_factory=list)  # {file, signature, risk}
    network_ioc_hits:  list[dict[str, Any]] = Field(default_factory=list)  # {matched_string, pattern, risk}
    command_ioc_hits:  list[dict[str, Any]] = Field(default_factory=list)  # {matched_string, pattern, risk}

class ThreatAssessment(BaseModel):
    overall_risk:          Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    suspicious_file_count: int
    yara_hit_count:        int
    clamav_hit_count:      int
    network_ioc_count:     int
    command_ioc_count:     int

class TriageResponse(BaseModel):
    """
    Complete triage output produced after running all 3 MCP tools:
    identify_evidence_type → list_artifacts → quick_threat_scan.
    """
    # ── 1. Human-readable brief ──────────────────
    triage_summary: str = Field(
        description=(
            "3-5 sentence forensic brief: what the evidence is, what OS/filesystem, "
            "overall threat level, key findings, and which specialists are needed."
        )
    )

    # ── 2. Evidence identity (from identify_evidence_type) ───
    evidence_meta: EvidenceMeta

    # ── 3. OS/filesystem snapshot ────────────────
    os_info: OsInfo

    # ── 4. Artifact inventory (from list_artifacts) ──
    artifact_inventory: ArtifactInventory

    # ── 5. Threat scan results (from quick_threat_scan) ──
    threat_assessment: ThreatAssessment
    ioc_findings:      IocFindings

    # ── 6. Specialist dispatch ───────────────────
    specialist_dispatch: list[str] = Field(
        description=(
            "Ordered list of specialist agents to invoke next, chosen from: "
            "registry_agent, event_log_agent, prefetch_agent, memory_agent, "
            "persistence_agent, lateral_movement_agent, browser_agent, "
            "network_agent, sam_agent, malware_agent. "
            "Only include agents relevant to discovered artifacts + IOC severity."
        )
    )

    # ── 7. Priority IOCs for specialists ─────────
    priority_targets: list[dict[str, Any]] = Field(
        description=(
            "Top HIGH/CRITICAL IOCs to hand off to specialist agents. "
            "Each entry: {ioc_type, value, risk, source_tool, context}."
        )
    )

    # ── 8. Artifact locations for specialists ────
    artifact_locations: dict[str, Any] = Field(
        description=(
            "Known paths and availability flags for each artifact category. "
            "e.g. {'registry': {'available': True, 'hives': ['SOFTWARE','SAM']}, "
            "'event_logs': {'available': True, 'count': 42}, ...}"
        )
    )

    # ── 9. Recommended next steps ────────────────
    recommended_next_steps: list[str] = Field(
        description=(
            "Ordered list of concrete forensic actions for the specialist agents, "
            "e.g. 'Parse SAM hive for local accounts', 'Carve MFT for deleted executables'."
        )
    )


# ── System Prompt ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert forensic triage agent operating inside a DFIR (Digital \
Forensics and Incident Response) pipeline. Your sole responsibility is to perform a fast, \
thorough first-pass examination of a forensic evidence file and produce a structured triage \
report that downstream specialist agents will rely on.

## YOUR TOOLS

You have access to exactly three MCP tools. You MUST call all three on every evidence file, \
in this exact order:

1. **identify_evidence_type(file_path)**
   - Determines: evidence format (E01/EWF, RAW/DD, memory dump, archive), OS, filesystem, \
     SHA-256 hash, size, partition table.
   - Call this FIRST. The output drives every decision that follows.

2. **list_artifacts(image_path)**
   - Inventories forensic artifacts: Registry hives, Prefetch, Event Logs, MFT, \
     $UsnJrnl, SAM, AmCache, SRUM, browser history, Jump Lists, Scheduled Tasks, \
     pagefile, hiberfil, SSH keys, crontabs, bash history, syslog, auth.log, and more.
   - Returns boolean dispatch flags (has_registry, has_event_logs, has_sam_database, \
     has_memory, has_network_artifacts, has_browser_artifacts, etc.) that determine \
     which specialists to activate.
   - Call this SECOND.

3. **quick_threat_scan(image_path)**
   - Runs four parallel checks: path heuristics, YARA signature matching, ClamAV scan, \
     and strings/regex IOC extraction.
   - Returns: overall_risk (LOW/MEDIUM/HIGH/CRITICAL), suspicious_files, yara_hits \
     (with severity), clamav_hits, network_ioc_hits, command_ioc_hits.
   - Call this THIRD.

## DECISION RULES — SPECIALIST DISPATCH

After collecting all tool outputs, apply these rules to populate `specialist_dispatch`:

| Condition                                    | Add to dispatch              |
|----------------------------------------------|------------------------------|
| has_registry = True                          | registry_agent               |
| has_event_logs = True                        | event_log_agent              |
| has_prefetch = True                          | prefetch_agent               |
| has_sam_database = True                      | sam_agent                    |
| has_browser_artifacts = True                 | browser_agent                |
| has_scheduled_tasks OR has_startup_items     | persistence_agent            |
| has_network_artifacts = True                 | network_agent                |
| has_memory = True                            | memory_agent                 |
| yara_hits with severity=CRITICAL             | malware_agent (top priority) |
| clamav_hits present                          | malware_agent (top priority) |
| network_ioc_hits OR command_ioc_hits present | lateral_movement_agent       |
| overall_risk = HIGH or CRITICAL              | malware_agent (if not added) |

Order dispatch list: CRITICAL threat agents first, then artifact-based agents.

## PRIORITY TARGETS

From the IOC findings, extract entries where risk = "CRITICAL" or severity = "CRITICAL" first, \
then "HIGH". For each entry produce:
  {ioc_type: "yara_hit"|"clamav_hit"|"suspicious_file"|"network_ioc"|"command_ioc",
   value: <path or matched string>,
   risk: "CRITICAL"|"HIGH",
   source_tool: "quick_threat_scan",
   context: <rule name, pattern, or reason>}

Limit to the top 20 most severe entries.

## ARTIFACT LOCATIONS

Build `artifact_locations` as a structured dict grouping artifact presence and key metadata \
that specialists need to know upfront:
  - registry: {available, hives: [...]}
  - event_logs: {available, count, sample_files: [...5]}
  - prefetch: {available, count}
  - sam: {available}
  - browser: {available, browsers: [...]}
  - persistence: {scheduled_tasks, startup_items, run_keys_likely}
  - network: {srum, event_logs, ssh_keys}
  - memory: {available, volatility_supported}

## TRIAGE SUMMARY

Write a concise 3–5 sentence brief that covers:
  1. What the evidence file is (format, OS, filesystem, hash prefix)
  2. Overall threat level and the most alarming finding
  3. Which artifact categories are present and investigation-ready
  4. Which specialist agents are being dispatched and why

## RULES

- Never guess or hallucinate. If a tool returns an error, include it in the summary and \
  set the relevant flags to False.
- Always call all three tools even if the first one returns an error.
- If `clamav_note` is present in the scan result, include it in `recommended_next_steps`.
- If overall_risk is CRITICAL, put malware_agent first in specialist_dispatch.
- File paths passed to tools should be relative to ~/lab/ or absolute.
"""


# ── Agent setup ───────────────────────────────────────────────────────────────

async def triage_agent(image_filename: str) -> TriageResponse:
    """
    Run the full triage pipeline on a forensic evidence file.
    `image_filename` is relative to ~/lab/ on the WSL2 Ubuntu host.
    """
    client = MultiServerMCPClient(
        {
            "triage-mcp": {
                "transport": "stdio",
                "command":   "wsl", 
                "args": [
                    "python3",
                    "/home/tayyab_h/triage_mcp/server.py",  # Linux path, valid inside WSL
                ],
            },
        }
    )

    tools = await client.get_tools()

    agent = create_agent(
        model=chat_model,
        tools=tools,
        system_prompt=SYSTEM_PROMPT,
        # response_format=TriageResponse,
    )

    result = await agent.ainvoke({
        "messages": [{
            "role":    "user",
            "content": f"Triage this forensic evidence file: {image_filename}",
        }]
    })

    final_text = result["messages"][-1].content

    return final_text


if __name__ == "__main__":
    import json

    report = asyncio.run(triage_agent("test.img"))

    print(report)