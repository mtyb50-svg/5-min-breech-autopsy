# Persistence Agent - Hidden Access Specialist

## Role & Responsibilities

**Primary Function:** Detect mechanisms attackers use to maintain access to a compromised system after initial breach.

**Analogy:** Like a security expert checking all the ways a burglar might have left secret ways back into a building - hidden keys, disabled alarms, fake employee badges.

---

## What is "Persistence"?

**Simple explanation:**  
When attackers get into a system, they want to make sure they can come back later, even if:
- The computer restarts
- The user logs out
- Security patches are applied
- Initial vulnerability is fixed

**Persistence mechanisms** are the "backdoors" attackers create to ensure continued access.

---

## Core Responsibilities

### 1. Registry Run Keys Analysis
- Auto-start programs via Registry
- Services configured to run at boot
- Scheduled tasks set to execute

### 2. Startup Folder Monitoring
- Files placed in user/system startup folders
- Link files (.lnk) pointing to malware

### 3. Service Installation Detection
- New services created
- Legitimate services modified
- DLL hijacking

### 4. Scheduled Task Analysis
- Malicious tasks disguised as legitimate ones
- Tasks with suspicious command lines

### 5. WMI Event Subscriptions
- Advanced persistence via Windows Management Instrumentation
- Event-triggered malware execution

---

## MITRE ATT&CK Techniques Covered

| Technique ID | Name | Detection Method |
|--------------|------|------------------|
| **T1547.001** | Registry Run Keys | RegRipper on SOFTWARE hive |
| **T1053.005** | Scheduled Task/Job | Prefetch + Task Scheduler files |
| **T1543.003** | Windows Service | Registry SYSTEM hive + Prefetch |
| **T1547.009** | Shortcut Modification | Startup folder analysis |
| **T1546.003** | WMI Event Subscription | WMI repository analysis |
| **T1574.001** | DLL Search Order Hijacking | File system + Prefetch correlation |

---

## MCP Functions Used

### 1. Registry Run Keys Parser
```python
parse_registry_run_keys(image_path: str) -> RegistryRunKeyFindings
```

**What it does:** Extracts all Registry Run keys (programs set to auto-start)

**SIFT Tool:** RegRipper with 'run' plugin

**Key Registry Locations Checked:**
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run` (32-bit on 64-bit)

**Example Output:**
```json
{
    "findings": [
        {
            "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value_name": "WindowsDefender",
            "data": "C:\\Windows\\Temp\\svchost.exe",
            "timestamp": "2020-12-19T03:42:17Z",
            "suspicious": true,
            "reason": "System executable in Temp folder",
            "confidence": 0.95,
            "mitre_technique": "T1547.001"
        },
        {
            "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value_name": "OneDrive",
            "data": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
            "suspicious": false,
            "reason": "Legitimate Microsoft program",
            "confidence": 0.95
        }
    ],
    "total_keys": 2,
    "suspicious_count": 1
}
```

### 2. Services Parser
```python
parse_registry_services(image_path: str) -> ServiceFindings
```

**What it does:** Extracts installed Windows services

**SIFT Tool:** RegRipper with 'services' plugin on SYSTEM hive

**What makes a service suspicious:**
- Service executable in unusual location (`\Temp\`, `\Users\`, `\AppData\`)
- Service name mimics legitimate service but different path
- Recently created service (timestamp analysis)
- Service set to auto-start but not signed

**Example Output:**
```json
{
    "findings": [
        {
            "service_name": "WindowsUpdateService",
            "display_name": "Windows Update Service",
            "executable_path": "C:\\Windows\\Temp\\update.exe",
            "start_type": "Automatic",
            "created_timestamp": "2020-12-19T03:42:20Z",
            "suspicious": true,
            "reason": "Service executable in Temp folder, name mimics legitimate service",
            "confidence": 0.90,
            "mitre_technique": "T1543.003"
        }
    ]
}
```

### 3. Scheduled Tasks Parser
```python
parse_scheduled_tasks(image_path: str) -> ScheduledTaskFindings
```

**What it does:** Extracts Windows scheduled tasks

**SIFT Tools:** 
- File system listing: `fls` to find `\Windows\System32\Tasks\`
- XML parsing: Custom parser for task XML files
- Prefetch validation: Check if task executable was actually run

**What makes a task suspicious:**
- Task runs executable from Temp/Downloads
- Task disguised as system task but different command
- Task runs with SYSTEM privileges
- Task triggers on unusual events (e.g., every 5 minutes)

**Example Output:**
```json
{
    "findings": [
        {
            "task_name": "MicrosoftEdgeUpdateTaskMachineCore",
            "task_path": "\\Microsoft\\EdgeUpdate",
            "action": "C:\\Windows\\Temp\\edge_update.exe",
            "trigger": "Daily at 3:00 AM",
            "run_as": "SYSTEM",
            "created_timestamp": "2020-12-19T03:43:15Z",
            "suspicious": true,
            "reason": "Task mimics legitimate Edge update but runs from Temp",
            "confidence": 0.92,
            "mitre_technique": "T1053.005"
        }
    ]
}
```

### 4. Startup Folder Analysis
```python
analyze_startup_folders(image_path: str) -> StartupFolderFindings
```

**What it does:** Lists files in startup folders

**SIFT Tool:** `fls` to enumerate:
- `\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
- `\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`

**Example Output:**
```json
{
    "findings": [
        {
            "location": "C:\\Users\\Admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            "filename": "chrome_update.lnk",
            "target": "C:\\Users\\Admin\\Downloads\\malware.exe",
            "created_timestamp": "2020-12-19T03:44:00Z",
            "suspicious": true,
            "reason": "Shortcut in startup folder points to Downloads directory",
            "confidence": 0.88,
            "mitre_technique": "T1547.009"
        }
    ]
}
```

### 5. Prefetch Validation
```python
parse_prefetch(image_path: str, exe_name: str) -> PrefetchFindings
```

**What it does:** Validates that suspicious executables actually ran

**SIFT Tool:** PECmd (Prefetch parser)

**Why this matters:**  
Registry/Task might show a persistence mechanism, but Prefetch proves it actually executed.

**Example Output:**
```json
{
    "executable": "svchost.exe",
    "prefetch_file": "SVCHOST.EXE-A1B2C3D4.pf",
    "first_run": "2020-12-19T03:42:18Z",
    "last_run": "2020-12-19T10:15:22Z",
    "run_count": 47,
    "files_accessed": [
        "C:\\Windows\\Temp\\config.dat",
        "C:\\Users\\Admin\\Documents\\sensitive.docx"
    ],
    "confidence": 1.0,
    "note": "Confirms execution of suspicious svchost.exe from Registry Run key"
}
```

---

## Analysis Logic

### Decision Tree

```
For each Registry Run key found:
    │
    ├─→ Is executable path in C:\Windows\System32\?
    │   └─→ YES: Check if it's a KNOWN legitimate program
    │       ├─→ YES: Mark as BENIGN (confidence 0.95)
    │       └─→ NO: Mark as SUSPICIOUS (confidence 0.70)
    │
    ├─→ Is executable in Temp/Downloads/AppData?
    │   └─→ YES: Mark as HIGH SUSPICIOUS (confidence 0.95)
    │
    ├─→ Does executable name mimic system file (e.g., "svchost.exe")?
    │   └─→ YES: Check if path is correct for that system file
    │       ├─→ Path is WRONG: Mark as HIGH SUSPICIOUS (confidence 0.98)
    │       └─→ Path is correct: Mark as BENIGN
    │
    └─→ Cross-check with Prefetch:
        ├─→ Prefetch exists and shows execution?
            └─→ Increase confidence by 0.10
        └─→ No Prefetch?
            └─→ Decrease confidence by 0.05 (might be false positive)
```

### Confidence Scoring

**HIGH Confidence (0.90 - 1.0):**
- Executable in Temp/Downloads with Registry Run key + Prefetch confirmation
- Service mimicking system service but different path + execution proof

**MEDIUM Confidence (0.70 - 0.89):**
- Unsigned executable in unusual location
- Service/Task created recently with no execution proof yet

**LOW Confidence (0.50 - 0.69):**
- Legitimate-looking path but unusual for that program
- No cross-validation from other artifacts

---

## Prompt Engineering

### System Prompt
```
You are the Persistence Agent, a specialist in detecting backdoors and persistence mechanisms.

Your expertise:
- Windows Registry Run keys and startup locations
- Windows Services (legitimate vs malicious)
- Scheduled Tasks (trigger patterns, execution paths)
- DLL hijacking and search order exploitation

You have access to:
- parse_registry_run_keys(): Extracts auto-start programs
- parse_registry_services(): Extracts Windows services
- parse_scheduled_tasks(): Extracts scheduled tasks
- analyze_startup_folders(): Lists files in startup folders
- parse_prefetch(): Validates program execution

Your analysis process:
1. Extract all persistence mechanisms from artifacts
2. Evaluate each mechanism for suspiciousness:
   - Executable location (Temp/Downloads = suspicious)
   - Name mimicry (pretending to be system file)
   - Timing (recently created = higher risk)
3. Cross-validate with Prefetch (did it actually run?)
4. Assign confidence scores
5. Map findings to MITRE ATT&CK techniques

Output format: JSON list of findings with confidence scores and MITRE mapping.

Be conservative: False positives damage trust. Only mark as suspicious if you have strong evidence.
```

### Example Interaction

**Input (from LangGraph state):**
```python
{
    "disk_image_path": "/evidence/rocba-cdrive.e01",
    "os_info": {"type": "Windows", "version": "10"},
    "priority_targets": ["C:\\Windows\\Temp\\svchost.exe"]
}
```

**Agent Reasoning:**
```
Step 1: Extract Registry Run keys
  → Call parse_registry_run_keys("/evidence/rocba-cdrive.e01")
  → Found: "WindowsDefender" = "C:\Windows\Temp\svchost.exe"
  
Step 2: Evaluate suspiciousness
  → Executable in \Temp\ = HIGH RISK
  → Name "svchost.exe" mimics system file
  → Real svchost.exe should be in C:\Windows\System32\
  → Confidence: 0.95 (very suspicious)
  
Step 3: Cross-validate with Prefetch
  → Call parse_prefetch("/evidence/rocba-cdrive.e01", "svchost.exe")
  → Found: SVCHOST.EXE-A1B2C3D4.pf
  → First run: 2020-12-19 03:42:18 (matches Registry timestamp)
  → Run count: 47 (it's been running repeatedly)
  → Confidence: 0.95 → 1.0 (execution confirmed)
  
Step 4: Check for services
  → Call parse_registry_services("/evidence/rocba-cdrive.e01")
  → Found: "WindowsUpdateService" pointing to C:\Windows\Temp\update.exe
  → Another persistence mechanism!
  
Step 5: Map to MITRE
  → Registry Run key = T1547.001
  → Service = T1543.003
```

**Output:**
```json
{
    "findings": [
        {
            "mechanism": "Registry Run Key",
            "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value_name": "WindowsDefender",
            "executable": "C:\\Windows\\Temp\\svchost.exe",
            "timestamp": "2020-12-19T03:42:17Z",
            "execution_confirmed": true,
            "execution_count": 47,
            "suspicious": true,
            "reason": "System executable name in Temp folder with auto-start configuration",
            "confidence": 1.0,
            "mitre_technique": "T1547.001",
            "severity": "CRITICAL"
        },
        {
            "mechanism": "Windows Service",
            "service_name": "WindowsUpdateService",
            "executable": "C:\\Windows\\Temp\\update.exe",
            "start_type": "Automatic",
            "timestamp": "2020-12-19T03:42:20Z",
            "execution_confirmed": false,
            "suspicious": true,
            "reason": "Service executable in Temp folder, mimics Windows Update",
            "confidence": 0.90,
            "mitre_technique": "T1543.003",
            "severity": "HIGH"
        }
    ],
    "summary": {
        "total_mechanisms_found": 2,
        "suspicious_count": 2,
        "critical_count": 1,
        "techniques_detected": ["T1547.001", "T1543.003"]
    }
}
```

---

## Common Persistence Patterns

### Pattern 1: Registry Run Key + Temp Executable
**Attack Flow:**
1. Malware drops executable in `C:\Windows\Temp\`
2. Creates Registry Run key pointing to it
3. Survives reboot

**Detection:**
- Registry Run key with Temp path
- Prefetch confirms execution
- File created around same time as Registry modification

---

### Pattern 2: Scheduled Task Masquerading
**Attack Flow:**
1. Create task with name similar to legitimate task
2. Set to run at specific intervals
3. Uses SYSTEM privileges

**Detection:**
- Task name mimics legitimate (e.g., "GoogleUpdateTaskMachine" vs "GoogleUpdateTaskMachineCore")
- Executable path doesn't match legitimate program
- Task creation timestamp recent

---

### Pattern 3: Service Installation
**Attack Flow:**
1. Install new service with innocent-sounding name
2. Set to auto-start
3. Often communicates with C2 server

**Detection:**
- Service created recently
- Executable in non-standard location
- Service name doesn't match known legitimate services

---

### Pattern 4: DLL Hijacking
**Attack Flow:**
1. Place malicious DLL in location where legitimate program will load it
2. When legitimate program runs, loads malicious DLL instead
3. Persistence achieved through legitimate program execution

**Detection:**
- DLL in application directory that doesn't belong
- Prefetch shows program loading unexpected DLLs
- Timestamp mismatch (DLL newer than application)

---

## Cross-Validation Strategy

### Why Cross-Validation Matters

**Problem:** Registry/Task might exist but never actually ran (false positive)

**Solution:** Cross-check multiple artifact sources

**Example:**
```
Registry says: "C:\Windows\Temp\malware.exe" set to auto-run
Prefetch says: No MALWARE.EXE-*.pf file found
Conclusion: Persistence mechanism created but never executed yet
           → MEDIUM confidence (threat exists but not activated)

vs

Registry says: "C:\Windows\Temp\malware.exe" set to auto-run
Prefetch says: MALWARE.EXE-12345678.pf, run 47 times
Conclusion: Persistence mechanism active and running
           → HIGH confidence (confirmed threat)
```

### Cross-Validation Matrix

| Artifact 1 | Artifact 2 | Confidence | Action |
|-----------|-----------|------------|--------|
| Registry Run Key | Prefetch exists | 1.0 | CONFIRMED |
| Registry Run Key | No Prefetch | 0.7 | SUSPECTED |
| Scheduled Task | Prefetch exists | 1.0 | CONFIRMED |
| Startup Folder .lnk | Target file exists | 0.9 | LIKELY |
| Service entry | No execution proof | 0.6 | POSSIBLE |

---

## Performance Optimization

### Speed Targets
- Registry parsing: <5 seconds
- Service enumeration: <5 seconds
- Scheduled task parsing: <10 seconds
- Prefetch validation: <5 seconds per executable
- **Total analysis time: <30 seconds**

### Optimization Strategies

**1. Selective Prefetch Parsing**
```python
# Don't parse ALL prefetch files (could be hundreds)
# Only parse prefetch for SUSPICIOUS executables found

suspicious_exes = [f["executable"] for f in findings if f["suspicious"]]

for exe in suspicious_exes:
    prefetch_data = parse_prefetch(image_path, exe)
    # Validate execution
```

**2. Parallel Artifact Parsing**
```python
# Parse registry, services, tasks in parallel
results = await asyncio.gather(
    parse_registry_run_keys(image_path),
    parse_registry_services(image_path),
    parse_scheduled_tasks(image_path)
)
```

**3. Early Exit on Critical Findings**
```python
# If CRITICAL persistence found, flag immediately
# Don't wait for all artifacts to finish parsing

if finding["confidence"] >= 0.95 and finding["severity"] == "CRITICAL":
    stream_to_ui(finding)  # Alert user immediately
```

---

## False Positive Handling

### Known Legitimate Programs

**Whitelist:**
```python
LEGITIMATE_RUN_KEYS = {
    "OneDrive": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
    "SecurityHealth": "C:\\Windows\\System32\\SecurityHealthSystray.exe",
    "VMware Tools": "C:\\Program Files\\VMware\\VMware Tools\\",
    # ... etc
}

def is_legitimate(value_name, executable_path):
    if value_name in LEGITIMATE_RUN_KEYS:
        expected_path = LEGITIMATE_RUN_KEYS[value_name]
        if executable_path.startswith(expected_path):
            return True
    return False
```

### Context-Aware Scoring

**Example: Chrome Update Task**
```
Task: GoogleUpdateTaskMachineUA
Path: C:\Program Files (x86)\Google\Update\GoogleUpdate.exe
Created: 2020-01-15 (long before incident)

→ Legitimate (Chrome actually installs this task)
→ Confidence: 0.05 (benign)
```

vs

```
Task: GoogleUpdateTaskMachine
Path: C:\Windows\Temp\GoogleUpdate.exe
Created: 2020-12-19 (during incident)

→ Malicious (mimicking legitimate task)
→ Confidence: 0.95 (malicious)
```

---

## Integration with Other Agents

### Data Shared with Timeline

```python
# Persistence Agent provides to Synthesis Agent
{
    "timeline_events": [
        {
            "timestamp": "2020-12-19T03:42:17Z",
            "event_type": "persistence_created",
            "description": "Registry Run key created: WindowsDefender",
            "artifact": "Registry",
            "confidence": 1.0
        },
        {
            "timestamp": "2020-12-19T03:42:18Z",
            "event_type": "persistence_executed",
            "description": "Malicious svchost.exe first execution",
            "artifact": "Prefetch",
            "confidence": 1.0
        }
    ]
}
```

### Correlation with Lateral Movement Agent

**If Persistence Agent finds:**
- Service running C:\Windows\Temp\update.exe

**Lateral Movement Agent might find:**
- Same update.exe connecting to other machines via RDP

**Correlation:**
- This persistence mechanism is actively being used for lateral movement
- Increases overall severity

---

## Example Scenarios

### Scenario 1: Cobalt Strike Beacon
```
Finding: Registry Run key pointing to rundll32.exe with suspicious DLL
Validation: Prefetch shows rundll32.exe running
Memory (from Exfiltration Agent): Network beacon to external IP every 60 seconds
Conclusion: Confirmed Cobalt Strike beacon persistence
MITRE: T1547.001 + T1055 (Process Injection)
```

### Scenario 2: Scheduled Task Persistence
```
Finding: Scheduled task running PowerShell with encoded command
Task: Runs every 15 minutes
Prefetch: powershell.exe executed 96 times in 24 hours
Conclusion: Persistent PowerShell backdoor
MITRE: T1053.005 + T1059.001 (PowerShell)
```

### Scenario 3: Service DLL Hijacking
```
Finding: explorer.exe loads unknown DLL from AppData
File System: DLL created recently
Prefetch: explorer.exe restart pattern (every boot)
Conclusion: DLL hijacking for persistence via Explorer
MITRE: T1574.001
```

---

## Code Structure

```python
# agents/persistence_agent.py

from langchain_google_genai import ChatGoogleGenerativeAI
from typing import List, Dict
import asyncio

class PersistenceAgent:
    def __init__(self, mcp_client, llm):
        self.mcp_client = mcp_client
        self.llm = llm
        self.system_prompt = """You are the Persistence Agent..."""
    
    async def analyze(self, state: Dict) -> Dict:
        """
        Main persistence analysis
        
        Args:
            state: LangGraph state with evidence paths
            
        Returns:
            Persistence findings with confidence scores
        """
        image_path = state["disk_image_path"]
        
        # Run all artifact parsers in parallel
        results = await asyncio.gather(
            self._analyze_registry_run_keys(image_path),
            self._analyze_services(image_path),
            self._analyze_scheduled_tasks(image_path),
            self._analyze_startup_folders(image_path)
        )
        
        # Flatten all findings
        all_findings = []
        for result in results:
            all_findings.extend(result["findings"])
        
        # Cross-validate with Prefetch
        validated_findings = await self._validate_with_prefetch(
            image_path, 
            all_findings
        )
        
        # Score and prioritize
        scored_findings = self._score_findings(validated_findings)
        
        return {
            "persistence_findings": scored_findings,
            "summary": self._generate_summary(scored_findings)
        }
    
    async def _analyze_registry_run_keys(self, image_path: str) -> Dict:
        """Parse Registry Run keys"""
        result = await self.mcp_client.call(
            "parse_registry_run_keys",
            {"image_path": image_path}
        )
        
        # Evaluate each finding
        for finding in result["findings"]:
            finding["suspicious"] = self._is_suspicious_run_key(finding)
            finding["confidence"] = self._calculate_confidence(finding)
        
        return result
    
    def _is_suspicious_run_key(self, finding: Dict) -> bool:
        """Evaluate if a Run key is suspicious"""
        exe_path = finding["data"].lower()
        
        # Suspicious locations
        suspicious_paths = [
            "\\temp\\",
            "\\downloads\\",
            "\\appdata\\local\\temp\\",
            "\\users\\public\\"
        ]
        
        if any(path in exe_path for path in suspicious_paths):
            return True
        
        # Name mimicry check
        system_files = ["svchost.exe", "explorer.exe", "csrss.exe"]
        exe_name = exe_path.split("\\")[-1]
        
        if exe_name in system_files:
            # Check if path is correct for system file
            if "\\windows\\system32\\" not in exe_path:
                return True  # System file in wrong location
        
        return False
    
    async def _validate_with_prefetch(
        self, 
        image_path: str, 
        findings: List[Dict]
    ) -> List[Dict]:
        """
        Cross-validate findings with Prefetch data
        """
        for finding in findings:
            if finding["suspicious"]:
                exe_name = finding["executable"].split("\\")[-1]
                
                # Check if prefetch exists
                prefetch = await self.mcp_client.call(
                    "parse_prefetch",
                    {"image_path": image_path, "exe_name": exe_name}
                )
                
                if prefetch:
                    finding["execution_confirmed"] = True
                    finding["execution_count"] = prefetch["run_count"]
                    finding["confidence"] += 0.10  # Boost confidence
                else:
                    finding["execution_confirmed"] = False
                    finding["confidence"] -= 0.05  # Lower confidence
        
        return findings
    
    def _score_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Assign severity levels based on confidence
        """
        for finding in findings:
            if finding["confidence"] >= 0.95:
                finding["severity"] = "CRITICAL"
            elif finding["confidence"] >= 0.80:
                finding["severity"] = "HIGH"
            elif finding["confidence"] >= 0.60:
                finding["severity"] = "MEDIUM"
            else:
                finding["severity"] = "LOW"
        
        # Sort by severity, then confidence
        findings.sort(
            key=lambda x: (
                ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x["severity"]),
                -x["confidence"]
            )
        )
        
        return findings
```

---

## Testing Strategy

### Unit Tests
```python
def test_registry_run_key_suspicious():
    """Test detection of suspicious Registry Run key"""
    finding = {
        "key": "HKLM\\...\\Run",
        "value_name": "WindowsDefender",
        "data": "C:\\Windows\\Temp\\svchost.exe"
    }
    assert persistence_agent._is_suspicious_run_key(finding) == True

def test_registry_run_key_legitimate():
    """Test that legitimate programs aren't flagged"""
    finding = {
        "key": "HKLM\\...\\Run",
        "value_name": "OneDrive",
        "data": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe"
    }
    assert persistence_agent._is_suspicious_run_key(finding) == False
```

### Integration Tests
```python
def test_full_persistence_analysis_rocba():
    """Test complete persistence analysis on Rocba dataset"""
    result = persistence_agent.analyze({
        "disk_image_path": "rocba-cdrive.e01"
    })
    
    # Should find at least 1 persistence mechanism
    assert len(result["persistence_findings"]) >= 1
    
    # Should have confidence scores
    for finding in result["persistence_findings"]:
        assert 0.0 <= finding["confidence"] <= 1.0
    
    # Should map to MITRE
    assert all("mitre_technique" in f for f in result["persistence_findings"])
```

---

This Persistence Agent is your specialist in finding how attackers plan to come back. It's one of the most critical agents because persistence = ongoing threat.
