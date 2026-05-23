# Triage Agent - Investigation Orchestrator

## Role & Responsibilities

**Primary Function:** First-contact agent that analyzes evidence, determines investigation priorities, and dispatches specialist agents.

**Analogy:** Think of this as the lead detective who arrives at a crime scene, does the initial walkthrough, and assigns different teams to specific areas of investigation.

---

## Core Responsibilities

### 1. Evidence Identification
- Determine evidence type (disk image, memory dump, or both)
- Identify operating system (Windows, Linux, macOS)
- Verify file integrity (hash validation)

### 2. Artifact Inventory
- Scan for available artifacts (Registry, Prefetch, Event Logs, etc.)
- Prioritize high-value artifacts
- Identify missing artifacts that limit analysis

### 3. Threat Indicators Scan
- Quick pass for obvious red flags
- Known malware signatures
- Suspicious file locations
- Anomalous timestamps

### 4. Agent Dispatch
- Decide which specialist agents to call
- Set priority order
- Define investigation scope

---

## Decision Logic

### Evidence Type Decision Tree

```
Input: Evidence file(s)
    │
    ├─→ Is it E01/DD/RAW format?
    │   └─→ YES: Disk image
    │       ├─→ Mount read-only
    │       ├─→ Identify filesystem (NTFS/EXT4/HFS+)
    │       └─→ Identify OS from boot files
    │
    ├─→ Is it 7z/ZIP/RAW memory dump?
    │   └─→ YES: Memory dump
    │       ├─→ Extract if compressed
    │       ├─→ Identify OS from memory structures
    │       └─→ Run Volatility windows.info/linux.info
    │
    └─→ Both disk + memory?
        └─→ BEST CASE: Full analysis capabilities
```

### Artifact Prioritization Matrix

| Artifact | Value | Speed | Decision |
|----------|-------|-------|----------|
| Windows Registry | HIGH | Fast | ALWAYS scan |
| Prefetch | HIGH | Fast | ALWAYS scan |
| Event Logs | HIGH | Medium | ALWAYS scan |
| MFT Timeline | MEDIUM | Slow | Conditional* |
| Memory Processes | HIGH | Fast | If memory available |
| Memory Network | HIGH | Fast | If memory available |
| Browser History | MEDIUM | Fast | Time permitting |
| Email Archives | LOW | Slow | Skip unless specific IOC |

*Conditional: Only if time allows, or if other artifacts show suspicious activity in specific timeframe

### Specialist Dispatch Logic

```python
def decide_specialists(artifacts: ArtifactInventory) -> List[str]:
    """
    Decide which specialist agents to call based on available artifacts
    """
    specialists = []
    
    # ALWAYS call these if Windows artifacts present
    if artifacts.has_registry or artifacts.has_prefetch:
        specialists.append("persistence_agent")
    
    if artifacts.has_event_logs or artifacts.has_memory:
        specialists.append("lateral_movement_agent")
    
    # Conditional calls
    if artifacts.has_memory and artifacts.has_network_artifacts:
        specialists.append("exfiltration_agent")
    
    if artifacts.has_event_logs or artifacts.has_sam_database:
        specialists.append("credential_access_agent")
    
    return specialists
```

---

## MCP Functions Used

### 1. Evidence Type Identification
```python
identify_evidence_type(file_path: str) -> EvidenceType
```
**What it does:** Determines if file is disk image, memory dump, or other
**SIFT Tool Used:** `file` command + custom logic
**Example Output:**
```json
{
    "type": "disk_image",
    "format": "E01",
    "size_gb": 22.1,
    "os_detected": "Windows 10",
    "filesystem": "NTFS"
}
```

### 2. Artifact Inventory Scan
```python
list_artifacts(image_path: str) -> ArtifactInventory
```
**What it does:** Quick scan of what artifacts exist on the evidence
**SIFT Tools Used:** `fls` (file listing) + specific path checks
**Example Output:**
```json
{
    "has_registry": true,
    "registry_hives": ["SOFTWARE", "SYSTEM", "SAM", "SECURITY"],
    "has_prefetch": true,
    "prefetch_count": 128,
    "has_event_logs": true,
    "event_log_files": ["Security.evtx", "System.evtx", "Application.evtx"],
    "has_mft": true,
    "has_browser_artifacts": true,
    "has_jump_lists": true
}
```

### 3. Quick Threat Scan
```python
quick_threat_scan(image_path: str) -> ThreatIndicators
```
**What it does:** Fast scan for obvious IOCs (Indicators of Compromise)
**SIFT Tools Used:** `strings` + `grep` with IOC patterns
**Example Output:**
```json
{
    "suspicious_files": [
        {
            "path": "C:\\Windows\\Temp\\svchost.exe",
            "reason": "System executable in Temp folder",
            "risk": "HIGH"
        }
    ],
    "known_malware_signatures": [],
    "suspicious_network_artifacts": [
        {
            "artifact": "Connection to 185.220.101.45",
            "reason": "Unusual external IP in memory",
            "risk": "MEDIUM"
        }
    ]
}
```

---

## Prompt Engineering

### System Prompt
```
You are the Triage Agent in a digital forensics investigation system.

Your role:
1. Analyze evidence to determine what artifacts are available
2. Identify high-priority indicators of compromise
3. Decide which specialist agents should investigate
4. Set investigation priorities based on threat indicators

You have access to:
- identify_evidence_type(): Determines evidence format and OS
- list_artifacts(): Inventories available forensic artifacts
- quick_threat_scan(): Fast scan for obvious IOCs

Your output should be:
1. Evidence summary (type, OS, filesystem)
2. Available artifacts (what can be analyzed)
3. Initial threat indicators (if any obvious red flags)
4. Specialist dispatch plan (which agents to call and why)

Be concise. Focus on HIGH-VALUE artifacts. Skip low-signal noise.
```

### Example Interaction

**User Input:**
```
Evidence: rocba-cdrive.e01 (22.1 GB)
Memory: Rocba-Memory.raw (5.3 GB)
```

**Triage Agent Reasoning:**
```
1. Call identify_evidence_type("rocba-cdrive.e01")
   → Returns: Windows 10 disk, NTFS, 22.1GB
   
2. Call list_artifacts("rocba-cdrive.e01")
   → Returns: Has registry, prefetch, event logs, jump lists
   
3. Call identify_evidence_type("Rocba-Memory.raw")
   → Returns: Windows 10 memory dump, 5.3GB
   
4. Call quick_threat_scan("rocba-cdrive.e01")
   → Returns: Suspicious executable in C:\Windows\Temp\
   
DECISION:
- Evidence Type: Windows 10 system (disk + memory = FULL analysis possible)
- Available Artifacts: Registry ✓, Prefetch ✓, Event Logs ✓, Memory ✓
- Threat Indicators: Suspicious executable in Temp folder → HIGH priority
- Dispatch Plan:
  ✓ Call Persistence Agent (check if that Temp executable persists)
  ✓ Call Lateral Movement Agent (check Event Logs for RDP/SMB)
  ✓ Call Exfiltration Agent (memory has network connections to analyze)
  ✓ Call Credential Access Agent (check for LSASS dumps, password files)
```

**Triage Agent Output (to LangGraph state):**
```python
{
    "evidence_summary": {
        "disk_image": "rocba-cdrive.e01",
        "memory_dump": "Rocba-Memory.raw",
        "os": "Windows 10",
        "filesystem": "NTFS"
    },
    "artifacts_found": {
        "registry": True,
        "prefetch": True,
        "event_logs": True,
        "memory": True,
        "mft": True,
        "jump_lists": True
    },
    "initial_indicators": [
        {
            "type": "suspicious_file",
            "details": "System executable in Temp folder",
            "path": "C:\\Windows\\Temp\\svchost.exe",
            "priority": "HIGH"
        }
    ],
    "specialist_dispatch": [
        "persistence_agent",
        "lateral_movement_agent",
        "exfiltration_agent",
        "credential_access_agent"
    ]
}
```

---

## Performance Optimization

### Speed Targets
- Evidence type identification: <5 seconds
- Artifact inventory: <10 seconds
- Quick threat scan: <10 seconds
- **Total triage time: <30 seconds**

### Optimization Strategies

**1. Parallel Checks**
```python
async def triage_analysis(disk_path, memory_path):
    # Run these concurrently
    tasks = [
        identify_evidence_type(disk_path),
        identify_evidence_type(memory_path),
        list_artifacts(disk_path),
        quick_threat_scan(disk_path)
    ]
    results = await asyncio.gather(*tasks)
    return aggregate_results(results)
```

**2. Early Exit on Critical Findings**
- If quick_threat_scan finds known malware → Prioritize that artifact immediately
- Don't waste time on comprehensive inventory if obvious breach found

**3. Smart Caching**
- Cache artifact inventory (doesn't change between runs on same image)
- Cache key: SHA-256 of evidence file

---

## Error Handling

### Common Issues

**1. Corrupted Evidence File**
```python
try:
    evidence_type = identify_evidence_type(file_path)
except CorruptedFileError:
    return {
        "status": "ERROR",
        "message": "Evidence file appears corrupted",
        "recommendation": "Verify file integrity, try re-download"
    }
```

**2. Unsupported OS**
```python
if os_detected not in ["Windows", "Linux", "macOS"]:
    return {
        "status": "WARNING",
        "message": f"Detected OS: {os_detected} - Limited tool support",
        "recommendation": "Proceed with caution, some specialists may not work"
    }
```

**3. Missing Critical Artifacts**
```python
if not artifacts.has_registry and not artifacts.has_event_logs:
    return {
        "status": "WARNING",
        "message": "Critical Windows artifacts missing",
        "recommendation": "Analysis will be limited. Check if evidence is complete."
    }
```

---

## Integration with Specialists

### State Passing to Specialists

```python
# What Triage Agent provides to downstream agents
triage_state = {
    "evidence_paths": {
        "disk": "/evidence/rocba-cdrive.e01",
        "memory": "/evidence/Rocba-Memory.raw"
    },
    "os_info": {
        "type": "Windows",
        "version": "10",
        "architecture": "x64"
    },
    "artifact_locations": {
        "registry_hives": "/mnt/evidence/Windows/System32/config/",
        "prefetch": "/mnt/evidence/Windows/Prefetch/",
        "event_logs": "/mnt/evidence/Windows/System32/winevt/Logs/"
    },
    "priority_targets": [
        "C:\\Windows\\Temp\\svchost.exe",  # Suspicious file found
        "185.220.101.45"  # Suspicious IP found
    ]
}
```

### Specialist Activation Signal

```python
# LangGraph edge condition
def should_call_persistence_agent(state):
    return "persistence_agent" in state["specialist_dispatch"]

def should_call_lateral_movement_agent(state):
    return "lateral_movement_agent" in state["specialist_dispatch"]

# And so on for each specialist
```

---

## Example Scenarios

### Scenario 1: Disk Image Only (No Memory)
```
Input: base-dc-cdrive.E01 (Domain Controller disk)

Triage Decision:
✓ Can analyze: Registry, Prefetch, Event Logs, Timeline
✗ Cannot analyze: Running processes, network connections
→ Call: Persistence Agent, Lateral Movement Agent (Event Logs only)
→ Skip: Full exfiltration analysis (need memory for active connections)
```

### Scenario 2: Memory Dump Only (No Disk)
```
Input: base-admin-memory.7z

Triage Decision:
✓ Can analyze: Running processes, network connections, injected code
✗ Cannot analyze: Historical artifacts (Registry, Prefetch)
→ Call: Exfiltration Agent (network analysis), Credential Access (LSASS dump check)
→ Skip: Persistence Agent (need disk for Registry)
```

### Scenario 3: Both Disk + Memory (Best Case)
```
Input: rocba-cdrive.e01 + Rocba-Memory.raw

Triage Decision:
✓ Can analyze: EVERYTHING
→ Call: ALL specialists (Persistence, Lateral Movement, Exfiltration, Credential Access)
→ Full cross-validation possible (memory confirms disk findings)
```

### Scenario 4: Linux System
```
Input: linux-server.dd

Triage Decision:
OS: Linux → Different artifact set
✓ Can analyze: /var/log/ (system logs), /etc/ (config files), bash history
✗ Cannot use: Windows-specific tools (RegRipper, Prefetch)
→ Adapt: Use Linux-specific MCP functions
→ Call: Modified specialists with Linux artifact focus
```

---

## Success Criteria

**Triage Agent succeeds when:**
1. ✅ Correctly identifies evidence type and OS (100% accuracy)
2. ✅ Finds all available high-value artifacts
3. ✅ Dispatches appropriate specialists based on evidence
4. ✅ Completes analysis in <30 seconds
5. ✅ Provides clear priority indicators to specialists

**Triage Agent fails when:**
1. ❌ Misidentifies OS (leads to wrong specialist calls)
2. ❌ Misses critical artifacts (incomplete investigation)
3. ❌ Dispatches irrelevant specialists (wastes time)
4. ❌ Takes >1 minute (defeats speed goal)

---

## Logging & Observability

### What Gets Logged

```python
# Every triage run logs:
{
    "run_id": "uuid-1234",
    "timestamp": "2026-05-19T09:32:00Z",
    "evidence_files": [
        "rocba-cdrive.e01",
        "Rocba-Memory.raw"
    ],
    "evidence_hashes": {
        "disk": "sha256:abc123...",
        "memory": "sha256:def456..."
    },
    "mcp_calls": [
        {
            "function": "identify_evidence_type",
            "duration_ms": 3421,
            "success": true
        },
        {
            "function": "list_artifacts",
            "duration_ms": 8932,
            "success": true
        }
    ],
    "specialists_dispatched": [
        "persistence_agent",
        "lateral_movement_agent",
        "exfiltration_agent",
        "credential_access_agent"
    ],
    "total_duration_ms": 28451,
    "status": "SUCCESS"
}
```

---

## Future Enhancements

### Phase 2 Improvements (Post-Hackathon)

**1. Machine Learning-Based Prioritization**
- Train model on ground truth datasets
- Learn which artifact combinations predict specific attack types
- Auto-prioritize based on learned patterns

**2. Multi-Evidence Correlation**
- Handle multiple related disk images (e.g., SRL-2018 enterprise network)
- Identify which machines to analyze first based on network topology

**3. Incremental Analysis**
- Start specialist agents WHILE triage is still running
- Don't wait for complete inventory before dispatching

**4. Threat Intelligence Integration**
- Query external threat feeds during triage
- Identify known-bad IPs, domains, file hashes immediately

---

## Code Structure

```python
# agents/triage_agent.py

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.prompts import ChatPromptTemplate
from typing import Dict, List

class TriageAgent:
    def __init__(self, mcp_client, llm):
        self.mcp_client = mcp_client
        self.llm = llm
        self.system_prompt = """You are the Triage Agent..."""
    
    async def analyze(self, evidence_files: Dict[str, str]) -> Dict:
        """
        Main triage analysis function
        
        Args:
            evidence_files: {"disk": path, "memory": path}
            
        Returns:
            Triage results with specialist dispatch plan
        """
        # 1. Identify evidence types
        evidence_types = await self._identify_evidence(evidence_files)
        
        # 2. Inventory artifacts
        artifacts = await self._inventory_artifacts(evidence_files["disk"])
        
        # 3. Quick threat scan
        threats = await self._quick_threat_scan(evidence_files["disk"])
        
        # 4. Decide specialist dispatch
        specialists = self._decide_specialists(artifacts, threats)
        
        return {
            "evidence_summary": evidence_types,
            "artifacts_found": artifacts,
            "initial_threats": threats,
            "specialist_dispatch": specialists
        }
    
    async def _identify_evidence(self, files: Dict) -> Dict:
        """Calls MCP to identify evidence types"""
        results = {}
        for file_type, file_path in files.items():
            result = await self.mcp_client.call(
                "identify_evidence_type",
                {"file_path": file_path}
            )
            results[file_type] = result
        return results
    
    async def _inventory_artifacts(self, disk_path: str) -> Dict:
        """Calls MCP to inventory available artifacts"""
        return await self.mcp_client.call(
            "list_artifacts",
            {"image_path": disk_path}
        )
    
    async def _quick_threat_scan(self, disk_path: str) -> List:
        """Calls MCP for quick IOC scan"""
        return await self.mcp_client.call(
            "quick_threat_scan",
            {"image_path": disk_path}
        )
    
    def _decide_specialists(self, artifacts: Dict, threats: List) -> List[str]:
        """
        Decision logic for which specialists to call
        """
        specialists = []
        
        # Always call these for Windows systems
        if artifacts.get("has_registry") or artifacts.get("has_prefetch"):
            specialists.append("persistence_agent")
        
        if artifacts.get("has_event_logs"):
            specialists.append("lateral_movement_agent")
            specialists.append("credential_access_agent")
        
        if artifacts.get("has_memory"):
            specialists.append("exfiltration_agent")
        
        # Priority boost if threats found
        if threats:
            # Move most relevant specialist to front
            # (implementation depends on threat type)
            pass
        
        return specialists
```

---

## Testing Strategy

### Unit Tests
```python
def test_evidence_identification():
    """Test that agent correctly identifies E01 disk images"""
    result = triage_agent.identify_evidence("test.e01")
    assert result["type"] == "disk_image"
    assert result["format"] == "E01"

def test_artifact_inventory():
    """Test that agent finds all Windows artifacts"""
    result = triage_agent.inventory_artifacts("windows10.e01")
    assert result["has_registry"] == True
    assert result["has_prefetch"] == True
    assert len(result["registry_hives"]) >= 4  # SOFTWARE, SYSTEM, SAM, SECURITY

def test_specialist_dispatch_windows():
    """Test that Windows evidence triggers correct specialists"""
    artifacts = {"has_registry": True, "has_event_logs": True}
    specialists = triage_agent.decide_specialists(artifacts, [])
    assert "persistence_agent" in specialists
    assert "lateral_movement_agent" in specialists
```

### Integration Tests
```python
def test_full_triage_rocba():
    """Test complete triage flow on Rocba dataset"""
    result = triage_agent.analyze({
        "disk": "rocba-cdrive.e01",
        "memory": "Rocba-Memory.raw"
    })
    
    assert result["evidence_summary"]["disk"]["os"] == "Windows 10"
    assert len(result["specialist_dispatch"]) == 4  # All specialists
    assert result["duration_ms"] < 30000  # Under 30 seconds
```

---

This Triage Agent is the entry point for all investigations. Get this right, and the specialists have clear direction and priorities.
