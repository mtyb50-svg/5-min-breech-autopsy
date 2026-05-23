# Synthesis Agent - Final Report Generator

## Role & Responsibilities

**Primary Function:** Combine findings from all specialist agents into a cohesive attack timeline, generate natural language report, and provide actionable recommendations.

**Analogy:** Like the lead detective who gathers reports from all forensic specialists (fingerprints, DNA, ballistics) and pieces together the complete story of what happened, when, and why.

---

## Core Responsibilities

### 1. Timeline Assembly
- Merge findings from all agents into chronological order
- Resolve timestamp conflicts
- Fill gaps with logical inferences

### 2. Cross-Validation
- Check for contradictions between agent findings
- Verify timeline consistency
- Flag low-confidence findings

### 3. MITRE ATT&CK Mapping
- Map all findings to ATT&CK framework
- Identify attack phases (Initial Access → Execution → Persistence → etc.)
- Calculate technique coverage

### 4. Natural Language Report Generation
- Write executive summary (non-technical)
- Write technical details (for analysts)
- Explain attacker's likely goals
- Describe attack sophistication

### 5. Confidence Scoring
- Aggregate confidence across findings
- Identify high/medium/low confidence conclusions
- Flag areas needing more investigation

### 6. Actionable Recommendations
- Immediate containment actions
- Long-term security improvements
- IOCs (Indicators of Compromise) for blocking

---

## Input from Specialist Agents

### From Triage Agent
```python
{
    "evidence_summary": {
        "os": "Windows 10",
        "filesystem": "NTFS",
        "evidence_types": ["disk", "memory"]
    },
    "artifacts_available": {
        "registry": true,
        "prefetch": true,
        "event_logs": true
    }
}
```

### From Persistence Agent
```python
{
    "findings": [
        {
            "mechanism": "Registry Run Key",
            "executable": "C:\\Windows\\Temp\\svchost.exe",
            "timestamp": "2020-12-19T03:42:17Z",
            "confidence": 1.0,
            "mitre_technique": "T1547.001"
        }
    ]
}
```

### From Lateral Movement Agent
```python
{
    "movement_chain": [
        {
            "source": "10.0.0.50",
            "destination": "10.0.0.75",
            "timestamp": "2020-12-19T03:45:33Z",
            "method": "RDP",
            "confidence": 0.95
        }
    ]
}
```

### From Exfiltration Agent
```python
{
    "exfiltration_detected": true,
    "method": "Cloud Storage Upload",
    "data_volume_mb": 500,
    "timestamp": "2020-12-19T03:58:00Z",
    "confidence": 0.97
}
```

### From Credential Access Agent
```python
{
    "compromised_accounts": [
        {
            "account": "admin_backup",
            "theft_method": "Plaintext file",
            "timestamp": "2020-12-19T03:30:00Z",
            "confidence": 1.0
        }
    ]
}
```

---

## Timeline Assembly Logic

### Merging Multi-Source Events

**Challenge:** Different agents report events with slightly different timestamps

**Example:**
```
Persistence Agent: "Registry modified at 03:42:17"
Prefetch Agent: "svchost.exe first run at 03:42:18"
Memory Agent: "svchost.exe process started at 03:42:19"
```

**Resolution:** Group events within 5-second window as related
```python
def merge_related_events(events, window_seconds=5):
    """Group events that are likely part of same action"""
    sorted_events = sorted(events, key=lambda x: x["timestamp"])
    
    groups = []
    current_group = [sorted_events[0]]
    
    for event in sorted_events[1:]:
        time_diff = (event["timestamp"] - current_group[-1]["timestamp"]).seconds
        
        if time_diff <= window_seconds:
            current_group.append(event)
        else:
            groups.append(current_group)
            current_group = [event]
    
    groups.append(current_group)
    return groups
```

### Timeline Event Structure

```python
class TimelineEvent(BaseModel):
    timestamp: datetime
    event_type: str  # persistence, lateral_movement, exfiltration, etc.
    description: str  # Human-readable summary
    details: Dict[str, Any]  # Full technical details
    source_agent: str  # Which agent detected this
    confidence: float  # 0.0 to 1.0
    mitre_techniques: List[str]  # ATT&CK technique IDs
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    evidence_artifacts: List[str]  # Which artifacts prove this
```

### Example Timeline
```json
{
    "timeline": [
        {
            "timestamp": "2020-12-19T03:40:15Z",
            "event_type": "initial_access",
            "description": "Phishing email attachment executed",
            "details": {
                "file": "invoice.exe",
                "source": "Email attachment"
            },
            "source_agent": "triage",
            "confidence": 0.85,
            "mitre_techniques": ["T1566.001"],
            "severity": "HIGH",
            "evidence_artifacts": ["Prefetch", "Timeline"]
        },
        {
            "timestamp": "2020-12-19T03:42:17Z",
            "event_type": "persistence",
            "description": "Malware established persistence via Registry Run key",
            "details": {
                "mechanism": "Registry Run Key",
                "key": "HKLM\\Software\\...\\Run",
                "value": "WindowsDefender",
                "executable": "C:\\Windows\\Temp\\svchost.exe"
            },
            "source_agent": "persistence",
            "confidence": 1.0,
            "mitre_techniques": ["T1547.001"],
            "severity": "CRITICAL",
            "evidence_artifacts": ["Registry", "Prefetch"]
        },
        {
            "timestamp": "2020-12-19T03:45:33Z",
            "event_type": "lateral_movement",
            "description": "RDP connection from 10.0.0.50 using compromised credentials",
            "details": {
                "source_ip": "10.0.0.50",
                "account": "admin_backup",
                "method": "RDP"
            },
            "source_agent": "lateral_movement",
            "confidence": 0.95,
            "mitre_techniques": ["T1021.001"],
            "severity": "CRITICAL",
            "evidence_artifacts": ["Event Logs", "Jump Lists", "Memory"]
        }
    ]
}
```

---

## MITRE ATT&CK Mapping

### Attack Phase Categorization

**MITRE ATT&CK Tactics (Attack Phases):**
1. **Initial Access** - How they got in
2. **Execution** - What they ran
3. **Persistence** - How they stay
4. **Privilege Escalation** - Getting admin
5. **Defense Evasion** - Hiding tracks
6. **Credential Access** - Stealing passwords
7. **Discovery** - Network reconnaissance
8. **Lateral Movement** - Spreading
9. **Collection** - Gathering data
10. **Exfiltration** - Stealing data
11. **Impact** - Damage/disruption

### Mapping Findings to Tactics

```python
TECHNIQUE_TO_TACTIC = {
    "T1566.001": "Initial Access",
    "T1547.001": "Persistence",
    "T1003.001": "Credential Access",
    "T1021.001": "Lateral Movement",
    "T1041": "Exfiltration",
    # ... (full mapping loaded from database)
}

def map_attack_phases(findings):
    """Map findings to MITRE ATT&CK tactics"""
    
    tactics_covered = {}
    
    for finding in findings:
        for technique in finding["mitre_techniques"]:
            tactic = TECHNIQUE_TO_TACTIC.get(technique)
            if tactic:
                if tactic not in tactics_covered:
                    tactics_covered[tactic] = []
                tactics_covered[tactic].append(finding)
    
    return tactics_covered
```

### Attack Flow Visualization

```
Initial Access (T1566.001)
      ↓
Execution (T1204.002)
      ↓
Persistence (T1547.001)
      ↓
Credential Access (T1003.001)
      ↓
Lateral Movement (T1021.001)
      ↓
Collection (T1560.001)
      ↓
Exfiltration (T1041)
```

---

## Confidence Scoring

### Aggregate Confidence Calculation

**Methods:**

**1. Average Confidence**
```python
def calculate_overall_confidence(findings):
    """Simple average of all finding confidences"""
    confidences = [f["confidence"] for f in findings]
    return sum(confidences) / len(confidences)
```

**2. Weighted by Severity**
```python
def calculate_weighted_confidence(findings):
    """Weight critical findings more heavily"""
    
    WEIGHTS = {
        "CRITICAL": 3.0,
        "HIGH": 2.0,
        "MEDIUM": 1.0,
        "LOW": 0.5
    }
    
    weighted_sum = sum(f["confidence"] * WEIGHTS[f["severity"]] for f in findings)
    weight_total = sum(WEIGHTS[f["severity"]] for f in findings)
    
    return weighted_sum / weight_total
```

**3. Evidence-Based Scoring**
```python
def calculate_evidence_confidence(finding):
    """More evidence sources = higher confidence"""
    
    base_confidence = finding["confidence"]
    evidence_count = len(finding["evidence_artifacts"])
    
    # Boost for multi-source validation
    if evidence_count >= 3:
        boost = 0.10
    elif evidence_count == 2:
        boost = 0.05
    else:
        boost = 0.0
    
    return min(1.0, base_confidence + boost)
```

### Confidence Categories

**CONFIRMED (0.95 - 1.0):**
- Multiple independent evidence sources
- No contradictions
- Clear causal chain

**LIKELY (0.80 - 0.94):**
- 2 evidence sources
- Timeline consistent
- Minor gaps acceptable

**PROBABLE (0.60 - 0.79):**
- Single strong evidence source
- OR multiple weak sources
- Some timeline gaps

**POSSIBLE (0.40 - 0.59):**
- Circumstantial evidence
- Significant gaps
- Requires more investigation

**UNCERTAIN (<0.40):**
- Insufficient evidence
- Contradictions present
- Flag for manual review

---

## Natural Language Report Generation

### Executive Summary Template

```markdown
# Incident Analysis Report

**Case:** {case_name}
**Date Range:** {start_date} to {end_date}
**Analysis Completed:** {analysis_timestamp}
**Evidence Analyzed:** {evidence_list}

## Executive Summary

This system was compromised on {initial_compromise_date} through {initial_access_method}.

The attacker's primary objectives appear to be:
1. {objective_1}
2. {objective_2}
3. {objective_3}

**Impact:**
- {impact_summary}
- Estimated data exfiltrated: {data_volume}
- Systems compromised: {system_count}

**Confidence Level:** {overall_confidence}% confidence in findings

**Immediate Actions Required:**
1. {action_1}
2. {action_2}
3. {action_3}
```

### Technical Details Template

```markdown
## Technical Analysis

### Attack Timeline

**{timestamp}** - Initial Access
{description}
- Method: {method}
- Evidence: {evidence}
- MITRE ATT&CK: {technique_id}

**{timestamp}** - Persistence Established
{description}
...

### MITRE ATT&CK Mapping

**Tactics Observed:**
- Initial Access: {technique_list}
- Persistence: {technique_list}
- Credential Access: {technique_list}
- Lateral Movement: {technique_list}
- Exfiltration: {technique_list}

### Indicators of Compromise (IOCs)

**Files:**
- {file_hash} - {file_path} - {description}

**Network:**
- {ip_address}:{port} - {description}

**Registry:**
- {registry_path} - {description}

### Compromised Accounts
- {account_name} - {compromise_method}
```

---

## Prompt Engineering

### System Prompt
```
You are the Synthesis Agent, responsible for creating the final incident report.

Your role:
1. Combine findings from all specialist agents
2. Build a chronological attack timeline
3. Resolve any contradictions or gaps
4. Map findings to MITRE ATT&CK framework
5. Generate executive summary (non-technical language)
6. Generate technical details (for security analysts)
7. Provide actionable recommendations

You receive input from:
- Triage Agent (evidence overview)
- Persistence Agent (backdoor mechanisms)
- Lateral Movement Agent (network spread)
- Exfiltration Agent (data theft)
- Credential Access Agent (password theft)

Your output must include:
1. Complete attack timeline with timestamps
2. MITRE ATT&CK technique mapping
3. Executive summary (2-3 paragraphs, business language)
4. Technical analysis (detailed, for analysts)
5. Confidence scores (overall and per-finding)
6. Actionable recommendations (prioritized)
7. IOC list (for blocking/detection)

Be concise but complete. Focus on the STORY of what happened, not just a list of findings.
```

### Example Interaction

**Input (from LangGraph state):**
```python
{
    "triage_summary": {...},
    "persistence_findings": [...],
    "lateral_movement_findings": [...],
    "exfiltration_findings": [...],
    "credential_access_findings": [...]
}
```

**Agent Reasoning:**
```
Step 1: Collect all findings
  Total findings: 15 across 4 agents
  
Step 2: Build timeline
  Earliest event: 2020-12-19 03:40:15 (initial access)
  Latest event: 2020-12-19 04:05:00 (cleanup)
  Duration: 25 minutes (FAST attack)
  
Step 3: Identify attack phases
  - Initial Access: Phishing (T1566.001)
  - Persistence: Registry Run Key (T1547.001)
  - Credential Access: Password file theft (T1552.001)
  - Lateral Movement: RDP (T1021.001)
  - Exfiltration: Cloud upload (T1567.002)
  
Step 4: Map MITRE ATT&CK
  Tactics covered: 5/11 (typical targeted attack)
  Sophistication: MEDIUM (common techniques, fast execution)
  
Step 5: Identify objectives
  Primary: Data theft (500MB exfiltrated)
  Secondary: Network access (lateral movement to DC)
  
Step 6: Calculate confidence
  Overall: 0.93 (HIGH confidence)
  Critical findings: 100% validated
  
Step 7: Generate recommendations
  Immediate: Isolate compromised systems, reset credentials
  Short-term: Block IOCs, scan for similar compromise
  Long-term: Email filtering, MFA, EDR deployment
```

**Output:**
```markdown
# Rocba Incident Analysis Report

**Case:** ROCBA-2020-001
**Date Range:** December 19, 2020 03:40 - 04:05 UTC
**Analysis Completed:** May 21, 2026 09:45 UTC
**Evidence Analyzed:** 
- Disk Image: rocba-cdrive.e01 (22.1 GB)
- Memory Dump: Rocba-Memory.raw (5.3 GB)

## Executive Summary

This system was compromised on December 19, 2020 at approximately 3:40 AM UTC through a phishing email attack. The attacker established persistence, stole credentials, moved laterally to the Domain Controller, and exfiltrated approximately 500MB of sensitive data to cloud storage.

The attack was executed with speed and precision, completing all phases within 25 minutes. The attacker demonstrated clear objectives: establish persistent access, steal administrative credentials, and exfiltrate financial and password data.

**Impact:**
- Administrative credentials compromised (admin_backup account)
- Domain Controller accessed
- 500MB of data exfiltrated (financial records, password files)
- 3 systems confirmed compromised

**Confidence Level:** 93% confidence in findings (HIGH)

**Immediate Actions Required:**
1. **CRITICAL:** Isolate all compromised systems immediately (10.0.0.75, 10.0.0.100, DC01)
2. **CRITICAL:** Reset passwords for all administrative accounts, especially admin_backup
3. **HIGH:** Block external IP 185.220.101.45 at firewall
4. **HIGH:** Revoke all active sessions and tokens
5. **MEDIUM:** Scan network for IOCs listed below

---

## Attack Timeline

**03:40:15 UTC** - **Initial Access** (CONFIDENCE: 85%)
- Phishing email attachment "invoice.exe" executed
- User opened malicious attachment
- Evidence: File timeline, Prefetch data
- MITRE ATT&CK: T1566.001 (Phishing: Spearphishing Attachment)

**03:42:17 UTC** - **Persistence Established** (CONFIDENCE: 100%)
- Malware created Registry Run key for auto-start
- Key: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
- Value: "WindowsDefender" → C:\Windows\Temp\svchost.exe
- Evidence: Registry analysis, Prefetch confirms execution
- MITRE ATT&CK: T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)

**03:30:00 UTC** - **Credential Access** (CONFIDENCE: 100%)
- Plaintext password file accessed: C:\Users\Admin\Desktop\passwords.txt
- File contains credentials for "admin_backup" account
- Evidence: File timeline, file content analysis
- MITRE ATT&CK: T1552.001 (Unsecured Credentials: Credentials In Files)

**03:45:33 UTC** - **Lateral Movement - First Hop** (CONFIDENCE: 95%)
- RDP connection from 10.0.0.50 using stolen admin_backup credentials
- Service account used for interactive logon (abnormal)
- Evidence: Event ID 4624 Type 10, Jump Lists, Active memory connection
- MITRE ATT&CK: T1021.001 (Remote Services: Remote Desktop Protocol)

**03:48:15 UTC** - **Credential Dumping** (CONFIDENCE: 98%)
- ProcDump64.exe executed to dump LSASS process memory
- Command: procdump64.exe -ma lsass.exe lsass.dmp
- Output: C:\Windows\Temp\lsass.dmp (50MB)
- Evidence: Memory process list, Prefetch, File timeline
- MITRE ATT&CK: T1003.001 (OS Credential Dumping: LSASS Memory)

**03:50:15 UTC** - **Lateral Movement - Second Hop** (CONFIDENCE: 97%)
- RDP to Domain Controller (DC01) using explicit credentials
- Account: Administrator
- Evidence: Event ID 4648, Jump Lists
- MITRE ATT&CK: T1021.001 (Remote Services: Remote Desktop Protocol)

**03:55:10 UTC** - **Data Staging** (CONFIDENCE: 95%)
- 7-Zip used to compress Documents folder
- Archive: C:\Users\Admin\AppData\Local\Temp\data.zip (500MB)
- Contents: Financial records, password files
- Evidence: Prefetch (7z.exe), File timeline
- MITRE ATT&CK: T1560.001 (Archive Collected Data: Archive via Utility)

**03:57:30 UTC** - **Exfiltration Initiated** (CONFIDENCE: 92%)
- Chrome browser accessed mega.nz cloud upload page
- Evidence: Jump Lists, Browser history
- MITRE ATT&CK: T1567.002 (Exfiltration Over Web Service: Exfiltration to Cloud Storage)

**03:58:00 UTC** - **Data Exfiltration** (CONFIDENCE: 95%)
- Network connection established to 185.220.101.45:443 (MEGA server)
- Process: powershell.exe
- Estimated data transferred: 500MB
- Evidence: Memory network connections
- MITRE ATT&CK: T1041 (Exfiltration Over C2 Channel)

**04:05:00 UTC** - **Evidence Cleanup** (CONFIDENCE: 88%)
- data.zip deleted after successful upload
- Evidence: File timeline shows deletion
- MITRE ATT&CK: T1070.004 (Indicator Removal: File Deletion)

---

## MITRE ATT&CK Coverage

**Tactics Observed:** 7 of 11

### Initial Access
- **T1566.001** - Phishing: Spearphishing Attachment

### Execution
- **T1204.002** - User Execution: Malicious File

### Persistence
- **T1547.001** - Registry Run Keys / Startup Folder

### Credential Access
- **T1552.001** - Credentials In Files
- **T1003.001** - LSASS Memory Dumping

### Lateral Movement
- **T1021.001** - Remote Desktop Protocol

### Collection
- **T1560.001** - Archive via Utility

### Exfiltration
- **T1567.002** - Exfiltration to Cloud Storage
- **T1041** - Exfiltration Over C2 Channel

### Defense Evasion
- **T1070.004** - File Deletion

**Attack Sophistication:** MEDIUM
- Uses common, well-known techniques
- Fast execution (25 minutes)
- Clear objectives
- Minimal custom tooling

---

## Indicators of Compromise (IOCs)

### Network IOCs
- **185.220.101.45** - External C2/Exfiltration server (MEGA)
- **10.0.0.50** - Source of lateral movement (potentially compromised)

### File IOCs
**Malicious Files:**
- `C:\Windows\Temp\svchost.exe` - Malware executable (HASH: TBD)
- `C:\Windows\Temp\lsass.dmp` - LSASS memory dump
- `C:\Users\Admin\AppData\Local\Temp\data.zip` - Exfiltration staging (deleted)

**Legitimate Tools Misused:**
- `procdump64.exe` - Used for credential dumping
- `7z.exe` - Used for data compression

### Registry IOCs
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\WindowsDefender` → Points to C:\Windows\Temp\svchost.exe

### Account IOCs
**Compromised Accounts:**
- `admin_backup` - Credentials stolen from plaintext file, used for lateral movement
- `Administrator` - Used for DC access

---

## Recommendations

### Immediate Actions (0-24 hours)

**CRITICAL Priority:**
1. **Isolate Compromised Systems**
   - 10.0.0.75 (this machine)
   - 10.0.0.50 (lateral movement source)
   - DC01 (Domain Controller)
   - Disconnect from network immediately

2. **Reset Credentials**
   - Force password reset for: admin_backup, Administrator
   - Reset all domain admin passwords
   - Revoke all active sessions and authentication tokens

3. **Block IOCs**
   - Block 185.220.101.45 at firewall
   - Block mega.nz domain if not business-critical
   - Add file hashes to endpoint protection

**HIGH Priority:**
4. **Scan for Persistence**
   - Check all systems for Registry Run key: "WindowsDefender"
   - Scan for C:\Windows\Temp\svchost.exe
   - Hunt for similar IOCs across network

5. **Audit Access**
   - Review all RDP sessions from affected systems
   - Audit Domain Controller access logs
   - Check for other compromised accounts

### Short-Term Actions (1-7 days)

6. **Forensic Analysis of Other Systems**
   - Analyze 10.0.0.50 (lateral movement source)
   - Analyze DC01 (Domain Controller)
   - Determine full scope of compromise

7. **Email Security**
   - Identify and quarantine phishing email
   - Train users on identifying phishing
   - Implement email attachment scanning

8. **Monitor for Re-compromise**
   - Watch for connections to 185.220.101.45
   - Monitor for svchost.exe in unusual locations
   - Alert on ProcDump / Mimikatz execution

### Long-Term Improvements (1-3 months)

9. **Technical Controls**
   - Deploy EDR (Endpoint Detection and Response)
   - Implement MFA for all administrative accounts
   - Disable RDP where not required, use VPN + jump box
   - Restrict LSASS memory access (LSA Protection, Credential Guard)

10. **Process Improvements**
    - Implement least privilege access
    - Regular password audits (no plaintext files!)
    - Security awareness training program
    - Incident response plan testing

11. **Monitoring & Detection**
    - SIEM alerts for Event ID 4648 (explicit credential use)
    - Alert on LSASS memory access
    - Monitor for unusual RDP patterns
    - Alert on cloud uploads to personal accounts

---

## Confidence Assessment

**Overall Confidence: 93% (HIGH)**

**Critical Findings (100% confidence):**
- Persistence mechanism (Registry + Prefetch validation)
- Credential file theft (file access + content analysis)
- LSASS dumping (memory + Prefetch + file evidence)

**High Confidence (90-99%):**
- Lateral movement chain (Event logs + Jump Lists + Memory)
- Data exfiltration (Network + Browser + Timeline correlation)

**Medium Confidence (80-89%):**
- Initial access method (Prefetch suggests email attachment, but no email artifacts)
- Exact data exfiltrated (estimated from archive size, not validated)

**Low Confidence Items:**
- Scope beyond analyzed systems (need to analyze other machines)
- Attacker identity (no attribution indicators found)

---

## Analysis Metadata

**Analysis Duration:** 4 minutes 32 seconds
**Agents Executed:** Triage, Persistence, Lateral Movement, Exfiltration, Credential Access
**Evidence Artifacts Analyzed:** 8 (Registry, Prefetch, Event Logs, Jump Lists, Memory, Timeline, File System, Strings)
**Total Findings:** 15
**MITRE Techniques Identified:** 9
**IOCs Extracted:** 12

**Tools Used:**
- RegRipper, PECmd, Plaso, Volatility 3, JLECmd, python-evtx, fls, bulk_extractor

---

*This report was generated by the 5-Minute Breach Autopsy autonomous incident response system.*
```

---

## Code Structure

```python
# agents/synthesis_agent.py

from typing import List, Dict
from datetime import datetime
import json

class SynthesisAgent:
    def __init__(self, llm, mitre_db):
        self.llm = llm
        self.mitre_db = mitre_db  # PostgreSQL with ATT&CK data
        self.system_prompt = """You are the Synthesis Agent..."""
    
    def synthesize(self, state: Dict) -> Dict:
        """
        Generate final report from all agent findings
        
        Args:
            state: LangGraph state with all agent findings
            
        Returns:
            Complete incident report
        """
        # Step 1: Collect all findings
        all_findings = self._collect_findings(state)
        
        # Step 2: Build timeline
        timeline = self._build_timeline(all_findings)
        
        # Step 3: Cross-validate
        validated_timeline = self._cross_validate(timeline)
        
        # Step 4: Map to MITRE ATT&CK
        attack_mapping = self._map_mitre_attack(validated_timeline)
        
        # Step 5: Calculate confidence
        confidence_scores = self._calculate_confidence(validated_timeline)
        
        # Step 6: Generate executive summary
        exec_summary = self._generate_executive_summary(
            validated_timeline,
            attack_mapping,
            confidence_scores
        )
        
        # Step 7: Generate technical details
        technical_details = self._generate_technical_details(
            validated_timeline,
            attack_mapping
        )
        
        # Step 8: Generate recommendations
        recommendations = self._generate_recommendations(
            validated_timeline,
            attack_mapping
        )
        
        # Step 9: Extract IOCs
        iocs = self._extract_iocs(validated_timeline)
        
        return {
            "executive_summary": exec_summary,
            "timeline": validated_timeline,
            "attack_mapping": attack_mapping,
            "technical_details": technical_details,
            "recommendations": recommendations,
            "iocs": iocs,
            "confidence_scores": confidence_scores,
            "metadata": self._generate_metadata(state)
        }
    
    def _collect_findings(self, state: Dict) -> List[Dict]:
        """Gather findings from all specialist agents"""
        findings = []
        
        # From each agent
        for agent in ["persistence", "lateral_movement", "exfiltration", "credential_access"]:
            agent_findings = state.get(f"{agent}_findings", [])
            for finding in agent_findings:
                finding["source_agent"] = agent
                findings.append(finding)
        
        return findings
    
    def _build_timeline(self, findings: List[Dict]) -> List[Dict]:
        """Build chronological timeline"""
        # Sort by timestamp
        sorted_findings = sorted(findings, key=lambda x: x["timestamp"])
        
        # Group related events
        timeline = []
        current_group = [sorted_findings[0]]
        
        for finding in sorted_findings[1:]:
            time_diff = (finding["timestamp"] - current_group[-1]["timestamp"]).seconds
            
            # Group events within 5 seconds
            if time_diff <= 5:
                current_group.append(finding)
            else:
                # Merge group into single timeline event
                timeline.append(self._merge_event_group(current_group))
                current_group = [finding]
        
        timeline.append(self._merge_event_group(current_group))
        
        return timeline
    
    def _merge_event_group(self, group: List[Dict]) -> Dict:
        """Merge related findings into single timeline event"""
        # Use highest confidence finding as primary
        primary = max(group, key=lambda x: x["confidence"])
        
        return {
            "timestamp": primary["timestamp"],
            "event_type": primary.get("type", "unknown"),
            "description": primary["description"],
            "details": primary,
            "supporting_evidence": [g for g in group if g != primary],
            "confidence": max(g["confidence"] for g in group),
            "mitre_techniques": list(set(
                t for g in group 
                for t in g.get("mitre_techniques", [])
            )),
            "severity": self._determine_severity(group)
        }
    
    def _map_mitre_attack(self, timeline: List[Dict]) -> Dict:
        """Map findings to MITRE ATT&CK framework"""
        tactics = {}
        
        for event in timeline:
            for technique_id in event["mitre_techniques"]:
                # Query database for technique details
                technique = self.mitre_db.get_technique(technique_id)
                
                tactic = technique["tactic"]
                if tactic not in tactics:
                    tactics[tactic] = []
                
                tactics[tactic].append({
                    "technique_id": technique_id,
                    "technique_name": technique["name"],
                    "event": event["description"],
                    "timestamp": event["timestamp"]
                })
        
        return tactics
    
    def _generate_recommendations(
        self,
        timeline: List[Dict],
        attack_mapping: Dict
    ) -> Dict:
        """Generate actionable recommendations"""
        
        recommendations = {
            "immediate": [],
            "short_term": [],
            "long_term": []
        }
        
        # Immediate actions based on critical findings
        for event in timeline:
            if event["severity"] == "CRITICAL":
                if "persistence" in event["event_type"]:
                    recommendations["immediate"].append({
                        "action": "Remove persistence mechanism",
                        "details": event["description"],
                        "priority": "CRITICAL"
                    })
                
                if "credential" in event["event_type"]:
                    recommendations["immediate"].append({
                        "action": "Reset compromised credentials",
                        "details": event["details"].get("account", "Unknown"),
                        "priority": "CRITICAL"
                    })
        
        # Short-term based on attack patterns
        if "Lateral Movement" in attack_mapping:
            recommendations["short_term"].append({
                "action": "Audit all RDP access",
                "details": "Review Event ID 4624 Type 10 across all systems",
                "priority": "HIGH"
            })
        
        # Long-term based on technique coverage
        if "T1003.001" in [t for events in attack_mapping.values() for t in events]:
            recommendations["long_term"].append({
                "action": "Implement LSA Protection",
                "details": "Enable Credential Guard and LSA Protection to prevent LSASS dumping",
                "priority": "MEDIUM"
            })
        
        return recommendations
```

---

## Performance Targets

- Timeline assembly: <10 seconds
- MITRE mapping: <5 seconds
- Report generation: <15 seconds
- **Total synthesis time: <30 seconds**

---

## Success Criteria

**Synthesis Agent succeeds when:**
1. ✅ Timeline is chronologically correct
2. ✅ No contradictions between findings
3. ✅ Executive summary is clear and non-technical
4. ✅ Technical details are complete and accurate
5. ✅ Recommendations are actionable and prioritized
6. ✅ Confidence scores accurately reflect evidence quality
7. ✅ MITRE ATT&CK mapping is complete

---

This Synthesis Agent is the final piece that turns raw findings into an actionable incident report.
