# Lateral Movement Agent - Network Spread Specialist

## Role & Responsibilities

**Primary Function:** Detect how attackers move from the initially compromised system to other machines on the network.

**Analogy:** Like a detective tracking how a thief moved from one building to others in a complex - which doors they used, which credentials got them in, and their path through the campus.

---

## What is "Lateral Movement"?

**Simple explanation:**  
After attackers compromise one computer (Patient Zero), they rarely stop there. They want to:
- Access more valuable systems (servers, domain controllers)
- Steal more data
- Gain administrative control of the entire network

**Lateral movement** is how they "hop" from computer to computer, spreading their control.

---

## Core Responsibilities

### 1. Authentication Event Analysis
- Logon events (successful and failed)
- Remote desktop connections
- Network share access
- Explicit credential use

### 2. Remote Access Protocol Detection
- RDP (Remote Desktop Protocol)
- SMB (File sharing)
- WinRM (Windows Remote Management)
- PSExec (Remote execution)

### 3. Credential Usage Tracking
- Which accounts were used
- From which source machines
- To which destination machines
- Unusual account usage patterns

### 4. Network Connection Timeline
- Outbound connections to internal IPs
- Connection timing correlation
- Port usage patterns

---

## MITRE ATT&CK Techniques Covered

| Technique ID | Name | Detection Method |
|--------------|------|------------------|
| **T1021.001** | Remote Desktop Protocol | Event ID 4624 Type 10 + Jump Lists |
| **T1021.002** | SMB/Windows Admin Shares | Event ID 4624 Type 3 + 5140 |
| **T1021.006** | Windows Remote Management | Event ID 4624 + WinRM logs |
| **T1570** | Lateral Tool Transfer | Event logs + Prefetch on target |
| **T1135** | Network Share Discovery | Event ID 5140 (share access) |
| **T1021.003** | Distributed Component Object Model | DCOM activity in Event Logs |

---

## MCP Functions Used

### 1. Event Log Parser (Authentication Events)
```python
parse_event_logs(
    image_path: str,
    event_ids: List[int],
    start_time: Optional[str] = None
) -> EventLogData
```

**What it does:** Parses Windows Event Logs for specific authentication events

**SIFT Tool:** python-evtx or evtx_dump.py

**Critical Event IDs:**
- **4624:** Successful logon
- **4625:** Failed logon (brute force attempts)
- **4648:** Logon with explicit credentials (runas)
- **4672:** Special privileges assigned to new logon
- **5140:** Network share accessed
- **4776:** Domain controller credential validation

**Example Output:**
```json
{
    "events": [
        {
            "event_id": 4624,
            "timestamp": "2020-12-19T03:45:33Z",
            "logon_type": 10,
            "account_name": "admin_backup",
            "account_domain": "CORP",
            "source_workstation": "ADMIN-PC",
            "source_ip": "10.0.0.50",
            "logon_process": "User32",
            "authentication_package": "Negotiate",
            "suspicious": true,
            "reason": "Service account used for interactive RDP logon",
            "confidence": 0.90,
            "mitre_technique": "T1021.001"
        },
        {
            "event_id": 4648,
            "timestamp": "2020-12-19T03:50:15Z",
            "account_name": "admin_backup",
            "target_server": "DC01",
            "target_account": "Administrator",
            "process": "C:\\Windows\\System32\\mstsc.exe",
            "suspicious": true,
            "reason": "Explicit credential use to connect to Domain Controller",
            "confidence": 0.95,
            "mitre_technique": "T1021.001"
        }
    ],
    "total_events": 2,
    "suspicious_count": 2
}
```

### 2. Jump List Parser (RDP Evidence)
```python
parse_jump_lists(image_path: str) -> JumpListFindings
```

**What it does:** Parses Windows Jump Lists showing recent RDP connections

**SIFT Tool:** JLECmd

**What Jump Lists reveal:**
- Recent Remote Desktop connections
- Destination IPs/hostnames
- Connection timestamps

**Example Output:**
```json
{
    "findings": [
        {
            "application": "mstsc.exe",
            "target": "10.0.0.100",
            "timestamp": "2020-12-19T03:45:30Z",
            "connection_type": "RDP",
            "suspicious": true,
            "reason": "RDP to internal server during incident timeframe",
            "confidence": 0.85,
            "mitre_technique": "T1021.001"
        },
        {
            "application": "mstsc.exe",
            "target": "DC01.corp.local",
            "timestamp": "2020-12-19T03:50:12Z",
            "connection_type": "RDP",
            "suspicious": true,
            "reason": "RDP to Domain Controller",
            "confidence": 0.92,
            "mitre_technique": "T1021.001"
        }
    ]
}
```

### 3. Memory Network Connections
```python
analyze_memory_network(memory_path: str) -> NetworkConnections
```

**What it does:** Extracts active network connections from memory dump

**SIFT Tool:** Volatility `windows.netscan`

**What it reveals:**
- Active connections at time of memory capture
- Source/destination IPs and ports
- Associated processes

**Example Output:**
```json
{
    "connections": [
        {
            "local_ip": "10.0.0.75",
            "local_port": 3389,
            "remote_ip": "10.0.0.50",
            "remote_port": 54321,
            "state": "ESTABLISHED",
            "protocol": "TCP",
            "process": "svchost.exe",
            "pid": 1234,
            "timestamp": "2020-12-19T04:00:00Z",
            "suspicious": true,
            "reason": "Incoming RDP connection from workstation",
            "confidence": 0.88
        },
        {
            "local_ip": "10.0.0.75",
            "local_port": 445,
            "remote_ip": "10.0.0.100",
            "remote_port": 49152,
            "state": "ESTABLISHED",
            "protocol": "TCP",
            "process": "System",
            "pid": 4,
            "suspicious": true,
            "reason": "SMB connection to file server",
            "confidence": 0.75
        }
    ]
}
```

### 4. Prefetch Validation (Remote Tools)
```python
parse_prefetch(image_path: str, exe_name: str) -> PrefetchFindings
```

**What it does:** Checks for execution of remote access tools

**Common Tools to Check:**
- `mstsc.exe` - Remote Desktop
- `psexec.exe` - Remote execution
- `net.exe` - Network commands
- `powershell.exe` - Often used for lateral movement

**Example Output:**
```json
{
    "executable": "psexec.exe",
    "prefetch_file": "PSEXEC.EXE-12345678.pf",
    "first_run": "2020-12-19T03:52:10Z",
    "last_run": "2020-12-19T03:55:22Z",
    "run_count": 3,
    "files_accessed": [
        "\\\\10.0.0.100\\C$\\Windows\\System32\\cmd.exe"
    ],
    "suspicious": true,
    "reason": "PSExec used to access remote system",
    "confidence": 0.95,
    "mitre_technique": "T1570"
}
```

---

## Analysis Logic

### Logon Type Classification

**Windows Logon Types (from Event 4624):**
- **Type 2:** Interactive (local keyboard/mouse)
- **Type 3:** Network (file shares, network access)
- **Type 4:** Batch (scheduled tasks)
- **Type 5:** Service (service started)
- **Type 7:** Unlock (screen unlock)
- **Type 8:** NetworkCleartext (IIS auth)
- **Type 9:** NewCredentials (RunAs)
- **Type 10:** RemoteInteractive (RDP, Terminal Services)
- **Type 11:** CachedInteractive (cached domain creds)

**Suspicious Patterns:**
- **Type 10** from internal IP during incident = RDP lateral movement
- **Type 3** to admin shares (C$, ADMIN$) = SMB lateral movement
- **Type 9** + subsequent Type 3/10 = credential theft → lateral movement

### Decision Tree

```
For each Event 4624 (successful logon):
    │
    ├─→ Is Logon Type 10 (RDP)?
    │   └─→ YES:
    │       ├─→ Is source IP internal?
    │           └─→ YES: Check if source IP was previously compromised
    │               ├─→ YES: HIGH SUSPICIOUS (lateral movement chain)
    │               └─→ NO: MEDIUM SUSPICIOUS (initial RDP)
    │
    ├─→ Is Logon Type 3 (Network)?
    │   └─→ YES: Check target share
    │       ├─→ Is it C$, ADMIN$, IPC$?
    │           └─→ YES: HIGH SUSPICIOUS (admin share access)
    │       └─→ Normal share access: LOW SUSPICIOUS
    │
    ├─→ Is account a service account?
    │   └─→ YES: Service accounts shouldn't do interactive logons
    │       └─→ HIGH SUSPICIOUS
    │
    └─→ Cross-validate with Jump Lists:
        └─→ Does Jump List show RDP to same IP?
            ├─→ YES: Increase confidence
            └─→ NO: May be automated connection
```

### Lateral Movement Chain Reconstruction

**Goal:** Build a timeline of how attackers moved machine-to-machine

**Example Chain:**
```
1. WORKSTATION-01 (Patient Zero)
   ↓ RDP at 03:45:33
2. WORKSTATION-02 (credential theft)
   ↓ RDP at 03:50:15
3. DC01 (Domain Controller)
   ↓ Admin access achieved
```

**How we detect this:**
```python
# Pseudocode
compromised_machines = ["10.0.0.75"]  # Patient Zero
timeline = []

for event in authentication_events:
    if event.source_ip in compromised_machines:
        # This machine was already compromised, now accessing another
        timeline.append({
            "from": event.source_ip,
            "to": event.destination_ip,
            "timestamp": event.timestamp,
            "method": event.logon_type
        })
        
        # Add newly compromised machine to list
        compromised_machines.append(event.destination_ip)

return timeline
```

---

## Prompt Engineering

### System Prompt
```
You are the Lateral Movement Agent, a specialist in detecting how attackers spread across networks.

Your expertise:
- Windows authentication events (4624, 4648, 4672)
- Remote access protocols (RDP, SMB, WinRM, PSExec)
- Lateral movement patterns and chains
- Account misuse detection

You have access to:
- parse_event_logs(): Extract authentication events
- parse_jump_lists(): RDP connection history
- analyze_memory_network(): Active network connections
- parse_prefetch(): Remote tool execution evidence

Your analysis process:
1. Extract all authentication events from Security.evtx
2. Identify suspicious logon patterns:
   - Service accounts used interactively
   - RDP from internal IPs
   - Admin share access (C$, ADMIN$)
   - Explicit credential use (Event 4648)
3. Reconstruct lateral movement timeline
4. Cross-validate with Jump Lists and network connections
5. Map findings to MITRE ATT&CK techniques

Output format: JSON timeline of lateral movement with confidence scores.

Critical: Look for CHAINS of movement, not just individual events. Attackers hop from machine to machine.
```

### Example Interaction

**Input (from LangGraph state):**
```python
{
    "disk_image_path": "/evidence/rocba-cdrive.e01",
    "memory_dump_path": "/evidence/Rocba-Memory.raw",
    "os_info": {"type": "Windows", "version": "10"},
    "initial_compromise_time": "2020-12-19T03:40:00Z"
}
```

**Agent Reasoning:**
```
Step 1: Extract authentication events
  → Call parse_event_logs(..., event_ids=[4624, 4648, 4672])
  → Found 127 events, filter to timeframe after 03:40:00
  → Remaining: 15 events
  
Step 2: Identify RDP connections
  → Event 4624, Type 10 at 03:45:33
  → Source: 10.0.0.50, Target: this machine (10.0.0.75)
  → Account: admin_backup
  → SUSPICIOUS: Service account used for RDP
  
Step 3: Check for subsequent lateral movement
  → Event 4648 at 03:50:15
  → Account: admin_backup (same as RDP)
  → Target: DC01 (Domain Controller)
  → CRITICAL: Credential used to access DC
  
Step 4: Cross-validate with Jump Lists
  → Call parse_jump_lists(...)
  → Found: mstsc.exe → 10.0.0.100 at 03:45:30
  → Found: mstsc.exe → DC01.corp.local at 03:50:12
  → Confirms RDP timeline
  
Step 5: Check memory for active connections
  → Call analyze_memory_network(...)
  → Active RDP session from 10.0.0.50
  → Active SMB connection to 10.0.0.100
  → Confirms lateral movement was ongoing
  
Step 6: Reconstruct movement chain
  10.0.0.50 → 10.0.0.75 (this machine) → DC01
```

**Output:**
```json
{
    "lateral_movement_chain": [
        {
            "sequence": 1,
            "source": "10.0.0.50",
            "destination": "10.0.0.75",
            "timestamp": "2020-12-19T03:45:33Z",
            "method": "RDP",
            "account_used": "admin_backup",
            "evidence": [
                "Event 4624 Type 10",
                "Jump List mstsc.exe",
                "Active RDP session in memory"
            ],
            "confidence": 0.95,
            "mitre_technique": "T1021.001"
        },
        {
            "sequence": 2,
            "source": "10.0.0.75",
            "destination": "DC01 (10.0.0.100)",
            "timestamp": "2020-12-19T03:50:15Z",
            "method": "RDP with explicit credentials",
            "account_used": "Administrator",
            "evidence": [
                "Event 4648",
                "Jump List mstsc.exe → DC01",
                "Active SMB connection in memory"
            ],
            "confidence": 0.97,
            "mitre_technique": "T1021.001",
            "severity": "CRITICAL",
            "note": "Domain Controller compromised"
        }
    ],
    "summary": {
        "total_hops": 2,
        "compromised_machines": ["10.0.0.50", "10.0.0.75", "DC01"],
        "critical_assets_compromised": ["DC01 (Domain Controller)"],
        "primary_technique": "RDP lateral movement",
        "timespan_minutes": 5
    }
}
```

---

## Common Lateral Movement Patterns

### Pattern 1: RDP Chain
**Attack Flow:**
1. Compromise Workstation A
2. RDP to Workstation B using stolen credentials
3. RDP to Server C
4. RDP to Domain Controller

**Detection:**
- Event 4624 Type 10 chain
- Jump Lists showing progression
- Each hop increases network access

---

### Pattern 2: PSExec Spread
**Attack Flow:**
1. Download PSExec to compromised machine
2. Use PSExec to execute commands on remote machines
3. Spread malware/tools to multiple systems

**Detection:**
- Prefetch shows PSExec execution
- Event logs show network logons (Type 3)
- Multiple machines show same malware at similar times

---

### Pattern 3: SMB Admin Share
**Attack Flow:**
1. Access admin shares (C$, ADMIN$) on remote machines
2. Copy malware to remote system
3. Use scheduled tasks or services to execute

**Detection:**
- Event 5140 (share access) to C$ or ADMIN$
- Event 4624 Type 3 with elevated privileges
- Persistence mechanisms appear on multiple machines

---

### Pattern 4: Pass-the-Hash
**Attack Flow:**
1. Extract password hashes from memory (LSASS)
2. Use hash to authenticate to other systems (no password needed)
3. Spread without knowing plaintext passwords

**Detection:**
- Authentication events without corresponding password entry
- Credential Access Agent finds LSASS dump
- Lateral Movement shows rapid spread with same account

---

## Cross-Validation Strategy

### Multi-Artifact Validation

**Evidence Level 1: Event Logs (PRIMARY)**
- Event 4624/4648 = Authentication happened
- Confidence: 0.8

**Evidence Level 2: Jump Lists**
- Confirms RDP connection was initiated
- Confidence boost: +0.1

**Evidence Level 3: Memory**
- Active network connection confirms ongoing access
- Confidence boost: +0.1

**Evidence Level 4: Prefetch on Target Machine**
- If we have target machine's disk, check for remote tool execution
- Confidence boost: +0.05

**Total Confidence: 0.8 + 0.1 + 0.1 + 0.05 = 1.0 (CONFIRMED)**

### Timeline Consistency Check

```python
# Example validation
rdp_event_time = "03:45:33"
jump_list_time = "03:45:30"
memory_connection_time = "03:46:00"

# Times should be close (within 5 minutes)
if all_within_5_minutes(rdp_event, jump_list, memory):
    confidence = 1.0  # Timeline consistent
else:
    confidence = 0.7  # Timeline mismatch, may be separate events
```

---

## Performance Optimization

### Speed Targets
- Event log parsing (4624/4648): <15 seconds
- Jump list parsing: <5 seconds
- Memory network analysis: <10 seconds
- Timeline reconstruction: <5 seconds
- **Total analysis time: <35 seconds**

### Optimization Strategies

**1. Targeted Event Filtering**
```python
# Don't parse ALL events (could be millions)
# Filter to incident timeframe + relevant event IDs

event_ids = [4624, 4648, 4672, 5140]
start_time = incident_start - timedelta(hours=1)
end_time = incident_end + timedelta(hours=1)

events = parse_event_logs(
    image_path,
    event_ids=event_ids,
    start_time=start_time,
    end_time=end_time
)
```

**2. Parallel Artifact Processing**
```python
# Parse event logs, jump lists, memory simultaneously
results = await asyncio.gather(
    parse_event_logs(...),
    parse_jump_lists(...),
    analyze_memory_network(...)
)
```

**3. Smart Caching**
```python
# Event logs don't change, cache parsed results
cache_key = f"{image_hash}:event_logs:4624"
if cached := redis.get(cache_key):
    return cached
else:
    result = parse_event_logs(...)
    redis.setex(cache_key, 3600, result)
    return result
```

---

## Integration with Other Agents

### Data Shared with Credential Access Agent

```python
# If Lateral Movement finds account misuse:
{
    "account_compromised": "admin_backup",
    "evidence": "Used for interactive RDP (service account)",
    "timestamp": "2020-12-19T03:45:33Z"
}

# Credential Access Agent investigates:
# - When was this account's password stolen?
# - Is there LSASS dump evidence?
# - Are credentials cached somewhere?
```

### Data Shared with Persistence Agent

```python
# If Lateral Movement finds machine B was accessed from A:
{
    "target_machine": "10.0.0.100",
    "access_time": "2020-12-19T03:50:15Z"
}

# Persistence Agent checks:
# - Did attacker create persistence on machine B?
# - Is there Registry/Service evidence on that machine?
```

### Data Shared with Synthesis Agent

```python
# Lateral Movement provides timeline events:
{
    "timeline_events": [
        {
            "timestamp": "2020-12-19T03:45:33Z",
            "event_type": "lateral_movement",
            "description": "RDP from 10.0.0.50 to this machine",
            "source": "Event 4624",
            "confidence": 0.95
        },
        {
            "timestamp": "2020-12-19T03:50:15Z",
            "event_type": "lateral_movement",
            "description": "Credential used to access Domain Controller",
            "source": "Event 4648",
            "confidence": 0.97,
            "severity": "CRITICAL"
        }
    ]
}
```

---

## False Positive Handling

### Legitimate Remote Access

**Problem:** Not all RDP is malicious

**Legitimate Scenarios:**
- IT admin doing maintenance
- User accessing work computer from home
- Automated system management tools

**How to Distinguish:**
```python
def is_legitimate_rdp(event):
    # Check time of day
    if is_business_hours(event.timestamp):
        # More likely legitimate
        confidence_penalty = 0.0
    else:
        # After hours RDP is more suspicious
        confidence_penalty = 0.2
    
    # Check account type
    if event.account_name.startswith("admin"):
        # Admin accounts doing RDP is normal
        confidence_penalty -= 0.1
    elif event.account_name.endswith("_svc"):
        # Service accounts doing RDP is VERY suspicious
        confidence_penalty += 0.3
    
    # Check frequency
    if event.account_name in frequent_rdp_users:
        # This account RDPs regularly
        confidence_penalty -= 0.2
    
    return confidence_penalty
```

### Automated Tools

**Problem:** Some legitimate software uses RDP/SMB

**Examples:**
- SCCM (System Center Configuration Manager)
- Monitoring tools
- Backup software

**Detection:**
```python
LEGITIMATE_TOOLS = {
    "SCCM": "C:\\Program Files\\Microsoft Configuration Manager\\",
    "Veeam": "C:\\Program Files\\Veeam\\",
}

def is_legitimate_tool(process_path):
    for tool, path in LEGITIMATE_TOOLS.items():
        if process_path.startswith(path):
            return True, tool
    return False, None
```

---

## Example Scenarios

### Scenario 1: APT Lateral Movement
```
Timeline:
03:40:00 - Workstation compromised (phishing)
03:45:33 - RDP to second workstation
03:50:15 - RDP to Domain Controller
03:55:00 - Domain admin credentials stolen
04:00:00 - Access to all servers achieved

Detection:
- 3 RDP hops in 20 minutes
- Service account misuse
- DC compromise
Confidence: 0.98
Severity: CRITICAL
```

### Scenario 2: Ransomware Spread
```
Timeline:
02:15:00 - Initial infection on Workstation A
02:20:00 - SMB connections to 50+ machines
02:25:00 - Encryption starts on all machines

Detection:
- Rapid SMB spread pattern
- Abnormal network activity
- Multiple machines affected simultaneously
Confidence: 0.95
Severity: CRITICAL
```

### Scenario 3: False Positive (IT Admin)
```
Timeline:
14:30:00 - RDP from admin workstation to server
14:35:00 - Software update installed
14:40:00 - RDP session closed

Detection:
- Business hours access
- Admin account (expected)
- Clean process (Windows Update)
Confidence: 0.3 (likely benign)
Severity: LOW
```

---

## Code Structure

```python
# agents/lateral_movement_agent.py

from typing import List, Dict
import asyncio
from datetime import datetime, timedelta

class LateralMovementAgent:
    def __init__(self, mcp_client, llm):
        self.mcp_client = mcp_client
        self.llm = llm
        self.system_prompt = """You are the Lateral Movement Agent..."""
    
    async def analyze(self, state: Dict) -> Dict:
        """
        Main lateral movement analysis
        
        Args:
            state: LangGraph state with evidence paths
            
        Returns:
            Lateral movement findings and timeline
        """
        image_path = state["disk_image_path"]
        memory_path = state.get("memory_dump_path")
        incident_time = state.get("initial_compromise_time")
        
        # Define analysis timeframe
        start_time = incident_time - timedelta(hours=1)
        end_time = incident_time + timedelta(hours=24)
        
        # Run all analyses in parallel
        results = await asyncio.gather(
            self._analyze_authentication_events(
                image_path, start_time, end_time
            ),
            self._analyze_rdp_connections(image_path),
            self._analyze_network_connections(memory_path) if memory_path else None
        )
        
        # Flatten results
        auth_events = results[0]
        rdp_connections = results[1]
        network_conns = results[2] if results[2] else []
        
        # Cross-validate and build timeline
        validated_findings = self._cross_validate(
            auth_events,
            rdp_connections,
            network_conns
        )
        
        # Reconstruct lateral movement chain
        movement_chain = self._reconstruct_chain(validated_findings)
        
        return {
            "lateral_movement_findings": validated_findings,
            "movement_chain": movement_chain,
            "summary": self._generate_summary(movement_chain)
        }
    
    async def _analyze_authentication_events(
        self,
        image_path: str,
        start_time: datetime,
        end_time: datetime
    ) -> List[Dict]:
        """Parse authentication events from Security.evtx"""
        
        event_ids = [4624, 4648, 4672, 5140]
        
        result = await self.mcp_client.call(
            "parse_event_logs",
            {
                "image_path": image_path,
                "event_ids": event_ids,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat()
            }
        )
        
        # Evaluate each event
        findings = []
        for event in result["events"]:
            if self._is_suspicious_auth(event):
                findings.append({
                    **event,
                    "suspicious": True,
                    "confidence": self._calculate_auth_confidence(event)
                })
        
        return findings
    
    def _is_suspicious_auth(self, event: Dict) -> bool:
        """Determine if authentication event is suspicious"""
        
        # RDP from internal IP
        if event["event_id"] == 4624 and event["logon_type"] == 10:
            if self._is_internal_ip(event["source_ip"]):
                return True
        
        # Explicit credential use
        if event["event_id"] == 4648:
            return True
        
        # Admin share access
        if event["event_id"] == 5140:
            if event["share_name"] in ["C$", "ADMIN$", "IPC$"]:
                return True
        
        # Service account used interactively
        if "_svc" in event["account_name"] or "_service" in event["account_name"]:
            if event["logon_type"] in [2, 10]:  # Interactive or RDP
                return True
        
        return False
    
    def _reconstruct_chain(self, findings: List[Dict]) -> List[Dict]:
        """
        Reconstruct the lateral movement chain
        """
        # Sort findings by timestamp
        sorted_findings = sorted(findings, key=lambda x: x["timestamp"])
        
        chain = []
        compromised_ips = set()
        
        for finding in sorted_findings:
            source_ip = finding.get("source_ip")
            dest_ip = finding.get("destination_ip", "this_machine")
            
            # If source was already compromised, this is lateral movement
            if source_ip in compromised_ips or len(chain) == 0:
                chain.append({
                    "sequence": len(chain) + 1,
                    "source": source_ip,
                    "destination": dest_ip,
                    "timestamp": finding["timestamp"],
                    "method": self._get_method(finding),
                    "account_used": finding.get("account_name"),
                    "confidence": finding["confidence"],
                    "mitre_technique": finding.get("mitre_technique")
                })
                
                # Add destination to compromised set
                if dest_ip != "this_machine":
                    compromised_ips.add(dest_ip)
        
        return chain
    
    def _get_method(self, finding: Dict) -> str:
        """Determine lateral movement method from finding"""
        if finding["event_id"] == 4624:
            logon_types = {
                2: "Interactive",
                3: "Network/SMB",
                10: "RDP"
            }
            return logon_types.get(finding["logon_type"], "Unknown")
        elif finding["event_id"] == 4648:
            return "Explicit Credentials"
        return "Unknown"
```

---

## Testing Strategy

### Unit Tests
```python
def test_rdp_detection():
    """Test detection of RDP lateral movement"""
    event = {
        "event_id": 4624,
        "logon_type": 10,
        "source_ip": "10.0.0.50",
        "account_name": "admin"
    }
    assert lateral_agent._is_suspicious_auth(event) == True

def test_service_account_misuse():
    """Test detection of service account interactive use"""
    event = {
        "event_id": 4624,
        "logon_type": 2,
        "account_name": "backup_svc"
    }
    assert lateral_agent._is_suspicious_auth(event) == True
```

### Integration Tests
```python
def test_chain_reconstruction():
    """Test lateral movement chain reconstruction"""
    findings = [
        {"source_ip": "10.0.0.50", "dest_ip": "10.0.0.75", "timestamp": "03:45"},
        {"source_ip": "10.0.0.75", "dest_ip": "10.0.0.100", "timestamp": "03:50"}
    ]
    
    chain = lateral_agent._reconstruct_chain(findings)
    
    assert len(chain) == 2
    assert chain[0]["source"] == "10.0.0.50"
    assert chain[1]["source"] == "10.0.0.75"
```

---

This Lateral Movement Agent is critical for understanding how far the breach spread and what other systems might be compromised.
