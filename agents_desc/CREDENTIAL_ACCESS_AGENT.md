# Credential Access Agent - Password Theft Specialist

## Role & Responsibilities

**Primary Function:** Detect how attackers stole usernames and passwords, and identify which credentials were compromised.

**Analogy:** Like a security investigator checking if the burglar stole the key safe, copied keys, or found passwords written down - and figuring out which locks those stolen keys can open.

---

## What is "Credential Access"?

**Simple explanation:**  
When attackers break into a system, they often want to **steal passwords** because:
- Passwords let them access more systems
- Passwords let them come back later (even if vulnerability is fixed)
- Passwords for admin accounts = full control

**Credential Access** is the process of stealing usernames, passwords, password hashes, or authentication tokens.

---

## Core Responsibilities

### 1. LSASS Memory Dump Detection
- Check if LSASS process was dumped (contains passwords in memory)
- Detect tools like Mimikatz, ProcDump
- Identify credential harvesting

### 2. Password File Detection
- Find files containing passwords (passwords.txt, creds.xlsx)
- Detect password managers being dumped
- Browser saved password extraction

### 3. Credential Harvesting Tool Detection
- Mimikatz execution
- LaZagne execution
- Custom credential dumpers

### 4. Authentication Failure Analysis
- Brute force attempts (many failed logins)
- Password spraying
- Kerberos ticket attacks

### 5. Credential Storage Analysis
- SAM database access
- NTDS.dit extraction (Domain Controller)
- Cached credentials

---

## MITRE ATT&CK Techniques Covered

| Technique ID | Name | Detection Method |
|--------------|------|------------------|
| **T1003.001** | LSASS Memory Dumping | Process memory access + tool detection |
| **T1003.002** | Security Account Manager (SAM) | Registry SAM hive access |
| **T1003.003** | NTDS (Domain Credentials) | NTDS.dit file access |
| **T1555.003** | Credentials from Web Browsers | Browser database access |
| **T1552.001** | Credentials in Files | Password files in common locations |
| **T1110.001** | Password Guessing | Multiple failed logon events |
| **T1110.003** | Password Spraying | Failed logons across many accounts |
| **T1558** | Kerberos Ticket Theft | Event log analysis |

---

## MCP Functions Used

### 1. Memory Process Analysis (LSASS Dump Detection)
```python
analyze_memory_processes(memory_path: str) -> ProcessList
```

**What it does:** Lists all running processes from memory dump

**SIFT Tool:** Volatility `windows.pslist` + `windows.malfind`

**What to look for:**
- LSASS process being accessed by unusual process
- ProcDump.exe or Mimikatz.exe running
- Processes with LSASS memory handles

**Example Output:**
```json
{
    "processes": [
        {
            "pid": 1234,
            "name": "procdump64.exe",
            "command_line": "procdump64.exe -ma lsass.exe lsass.dmp",
            "ppid": 2345,
            "parent_name": "powershell.exe",
            "create_time": "2020-12-19T03:48:15Z",
            "suspicious": true,
            "reason": "ProcDump dumping LSASS process (credential theft)",
            "confidence": 0.98,
            "mitre_technique": "T1003.001",
            "severity": "CRITICAL"
        },
        {
            "pid": 3456,
            "name": "mimikatz.exe",
            "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
            "create_time": "2020-12-19T03:50:22Z",
            "suspicious": true,
            "reason": "Mimikatz credential dumping tool detected",
            "confidence": 1.0,
            "mitre_technique": "T1003.001",
            "severity": "CRITICAL"
        }
    ]
}
```

### 2. Event Log Analysis (Authentication Failures)
```python
parse_event_logs(
    image_path: str,
    event_ids: List[int],
    start_time: Optional[str]
) -> EventLogData
```

**What it does:** Extracts failed authentication events

**SIFT Tool:** python-evtx parser

**Critical Event IDs:**
- **4625:** Failed logon attempt
- **4771:** Kerberos pre-authentication failed
- **4776:** Credential validation failed
- **4768:** Kerberos ticket requested (can indicate ticket attacks)

**Example Output:**
```json
{
    "events": [
        {
            "event_id": 4625,
            "timestamp": "2020-12-19T03:35:10Z",
            "account_name": "administrator",
            "failure_reason": "Bad password",
            "source_ip": "10.0.0.50",
            "logon_type": 3,
            "suspicious": false,
            "reason": "Single failed attempt (normal user error)",
            "confidence": 0.2
        },
        {
            "event_id": 4625,
            "timestamp": "2020-12-19T03:35:11Z",
            "account_name": "administrator",
            "failure_reason": "Bad password",
            "source_ip": "10.0.0.50",
            "attempts_in_window": 47,
            "suspicious": true,
            "reason": "47 failed attempts in 60 seconds (brute force)",
            "confidence": 0.95,
            "mitre_technique": "T1110.001",
            "severity": "HIGH"
        }
    ]
}
```

### 3. File System Search (Password Files)
```python
search_password_files(image_path: str) -> PasswordFileFindings
```

**What it does:** Searches for files likely to contain passwords

**SIFT Tools:** `fls` (file listing) + `grep` for file content search

**Common locations to check:**
- `C:\Users\*\Desktop\passwords.txt`
- `C:\Users\*\Documents\creds.xlsx`
- `C:\Users\*\Downloads\*.txt` (containing "password")
- `C:\Windows\Temp\*` (dumped credentials)

**Common filenames:**
- `passwords.txt`, `pass.txt`, `credentials.txt`
- `logins.xlsx`, `accounts.csv`
- `kdbx` (KeePass database files)
- `lsass.dmp` (memory dump)

**Example Output:**
```json
{
    "findings": [
        {
            "file_path": "C:\\Users\\Admin\\Desktop\\passwords.txt",
            "file_size_bytes": 2048,
            "created": "2019-05-10T14:20:00Z",
            "modified": "2020-12-19T03:30:00Z",
            "suspicious": true,
            "reason": "Password file accessed during incident",
            "confidence": 0.90,
            "mitre_technique": "T1552.001",
            "content_preview": "Gmail: admin@company.com / P@ssw0rd123..."
        },
        {
            "file_path": "C:\\Windows\\Temp\\lsass.dmp",
            "file_size_bytes": 52428800,
            "created": "2020-12-19T03:48:20Z",
            "suspicious": true,
            "reason": "LSASS memory dump in Temp folder",
            "confidence": 1.0,
            "mitre_technique": "T1003.001",
            "severity": "CRITICAL"
        }
    ]
}
```

### 4. Browser Credential Database Access
```python
analyze_browser_credentials(image_path: str) -> BrowserCredentialFindings
```

**What it does:** Checks if browser saved password databases were accessed

**Browser database locations:**
- Chrome: `Login Data` (SQLite database)
- Firefox: `logins.json`
- Edge: Similar to Chrome

**SIFT Tools:** `sqlitebrowser` or `sqlite3` command-line

**Example Output:**
```json
{
    "browsers": [
        {
            "browser": "Google Chrome",
            "database_path": "C:\\Users\\Admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            "last_accessed": "2020-12-19T03:49:30Z",
            "credential_count": 47,
            "suspicious": true,
            "reason": "Browser credential database accessed during incident",
            "confidence": 0.85,
            "mitre_technique": "T1555.003"
        }
    ]
}
```

### 5. Prefetch Validation (Credential Tools)
```python
parse_prefetch(image_path: str, exe_name: str) -> PrefetchFindings
```

**What it does:** Checks for execution of credential dumping tools

**Tools to check:**
- `mimikatz.exe` - Most common credential dumper
- `procdump.exe` / `procdump64.exe` - Microsoft tool (legitimate but used for LSASS dumping)
- `lazagne.exe` - Password recovery tool
- `pwdump.exe` - SAM dumper
- `fgdump.exe` - Credential dumper

**Example Output:**
```json
{
    "executable": "mimikatz.exe",
    "prefetch_file": "MIMIKATZ.EXE-A1B2C3D4.pf",
    "first_run": "2020-12-19T03:50:22Z",
    "last_run": "2020-12-19T03:50:25Z",
    "run_count": 1,
    "files_accessed": [
        "lsass.exe",
        "C:\\Windows\\Temp\\passwords.txt"
    ],
    "suspicious": true,
    "reason": "Mimikatz execution detected",
    "confidence": 1.0,
    "mitre_technique": "T1003.001",
    "severity": "CRITICAL"
}
```

### 6. Registry SAM Database Analysis
```python
analyze_sam_database(image_path: str) -> SAMFindings
```

**What it does:** Checks if SAM database (local password hashes) was accessed

**SIFT Tool:** RegRipper on SAM hive

**What to look for:**
- SAM hive accessed/copied
- Password hashes extracted
- Accounts with blank passwords

**Example Output:**
```json
{
    "sam_accessed": true,
    "access_time": "2020-12-19T03:51:00Z",
    "accounts_found": [
        {
            "username": "Administrator",
            "rid": 500,
            "password_hash": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
            "hash_type": "NTLM"
        },
        {
            "username": "Guest",
            "rid": 501,
            "enabled": false
        }
    ],
    "suspicious": true,
    "reason": "SAM database accessed, password hashes extracted",
    "confidence": 0.95,
    "mitre_technique": "T1003.002"
}
```

---

## Analysis Logic

### Credential Theft Pattern Detection

**Pattern 1: LSASS Dump + Exfiltration**
```
1. ProcDump/Mimikatz runs
2. LSASS.dmp file created
3. File exfiltrated or deleted
4. Subsequent lateral movement with stolen credentials
```

**Detection:**
```python
def detect_lsass_dump_pattern(memory, filesystem, lateral):
    # Check for LSASS dumping tool
    lsass_dumper = [p for p in memory.processes 
                    if "procdump" in p.name.lower() 
                    or "mimikatz" in p.name.lower()]
    
    if lsass_dumper:
        # Check if dump file was created
        dump_file = [f for f in filesystem.files
                    if "lsass.dmp" in f.path.lower()]
        
        if dump_file:
            # Check if followed by lateral movement
            if lateral.movements_after(dump_file.timestamp):
                return {
                    "pattern": "lsass_dump_and_use",
                    "confidence": 1.0,
                    "severity": "CRITICAL"
                }
```

### Brute Force Detection

**Threshold-based detection:**
```python
def detect_brute_force(failed_logons):
    # Group by source IP and target account
    grouped = group_by(failed_logons, ["source_ip", "account_name"])
    
    for group in grouped:
        attempts = len(group.events)
        timespan = group.last_timestamp - group.first_timestamp
        
        # Thresholds
        if attempts >= 10 and timespan <= timedelta(minutes=5):
            return {
                "type": "brute_force",
                "account": group.account_name,
                "source": group.source_ip,
                "attempts": attempts,
                "confidence": 0.95 if attempts > 50 else 0.85
            }
```

### Password Spraying Detection

**Different from brute force:**
- Brute force: Many attempts on ONE account
- Password spraying: Few attempts on MANY accounts

```python
def detect_password_spraying(failed_logons):
    # Group by source IP
    by_source = group_by(failed_logons, "source_ip")
    
    for source_group in by_source:
        unique_accounts = set(e.account_name for e in source_group.events)
        attempts_per_account = len(source_group.events) / len(unique_accounts)
        
        # Password spraying: Many accounts, few attempts each
        if len(unique_accounts) >= 10 and attempts_per_account <= 3:
            return {
                "type": "password_spraying",
                "source": source_group.source_ip,
                "accounts_targeted": len(unique_accounts),
                "confidence": 0.90,
                "mitre": "T1110.003"
            }
```

---

## Prompt Engineering

### System Prompt
```
You are the Credential Access Agent, a specialist in detecting password theft and credential compromise.

Your expertise:
- LSASS memory dumping detection (Mimikatz, ProcDump)
- Password file identification
- Browser credential extraction
- Brute force and password spraying detection
- SAM database access

You have access to:
- analyze_memory_processes(): Detect credential dumping tools
- parse_event_logs(): Failed authentication analysis
- search_password_files(): Find password-containing files
- analyze_browser_credentials(): Browser saved password access
- parse_prefetch(): Credential tool execution
- analyze_sam_database(): Local password hash access

Your analysis process:
1. Check memory for credential dumping tools (Mimikatz, ProcDump)
2. Check filesystem for password files and LSASS dumps
3. Analyze authentication failures (brute force, spraying)
4. Check browser credential database access
5. Cross-validate with lateral movement (stolen creds used?)
6. Identify which accounts were compromised

Output format: JSON findings with compromised accounts and theft method.

Critical: Credential theft often ENABLES lateral movement. Look for theft → subsequent unauthorized access pattern.
```

### Example Interaction

**Input (from LangGraph state):**
```python
{
    "disk_image_path": "/evidence/rocba-cdrive.e01",
    "memory_dump_path": "/evidence/Rocba-Memory.raw",
    "incident_timeframe": {
        "start": "2020-12-19T03:40:00Z",
        "end": "2020-12-19T04:30:00Z"
    },
    "lateral_movement_findings": [
        {
            "account_used": "admin_backup",
            "timestamp": "2020-12-19T03:45:33Z"
        }
    ]
}
```

**Agent Reasoning:**
```
Step 1: Check memory for credential tools
  → Call analyze_memory_processes(...)
  → Found: procdump64.exe running at 03:48:15
  → Command line: "procdump64.exe -ma lsass.exe lsass.dmp"
  → CRITICAL: LSASS memory being dumped
  
Step 2: Check if dump file exists
  → Call search_password_files(...)
  → Found: C:\Windows\Temp\lsass.dmp at 03:48:20
  → File size: 50MB (contains credential hashes)
  → CONFIRMS: LSASS dump successful
  
Step 3: Check for password files
  → Found: C:\Users\Admin\Desktop\passwords.txt
  → Modified: 03:30:00 (accessed during incident)
  → Content: "admin_backup: P@ssw0rd123"
  → CRITICAL: Plaintext password file
  
Step 4: Check authentication failures
  → Call parse_event_logs(..., event_ids=[4625])
  → Found: 47 failed attempts on "administrator" at 03:35
  → Source: 10.0.0.50
  → Pattern: Brute force attack
  
Step 5: Correlate with lateral movement
  → Lateral Movement used "admin_backup" account at 03:45
  → Password file contains "admin_backup" credentials
  → Timeline: Password file accessed (03:30) → Lateral movement (03:45)
  → CORRELATION: Stolen password used for lateral movement
  
Step 6: Check browser credentials
  → Call analyze_browser_credentials(...)
  → Chrome Login Data accessed at 03:49:30
  → Contains 47 saved passwords
  → ADDITIONAL THEFT: Browser passwords stolen
```

**Output:**
```json
{
    "credential_theft_detected": true,
    "compromised_accounts": [
        {
            "account_name": "admin_backup",
            "theft_method": "Plaintext password file",
            "evidence": "passwords.txt on Desktop",
            "timestamp": "2020-12-19T03:30:00Z",
            "confidence": 1.0,
            "mitre_technique": "T1552.001",
            "used_for_lateral_movement": true,
            "lateral_movement_timestamp": "2020-12-19T03:45:33Z"
        },
        {
            "account_name": "administrator",
            "theft_method": "Brute force attack",
            "evidence": "47 failed logon attempts in Event Log",
            "timestamp": "2020-12-19T03:35:00Z",
            "confidence": 0.95,
            "mitre_technique": "T1110.001",
            "success": "Unknown (no successful logon Event 4624)"
        }
    ],
    "credential_dumping_tools": [
        {
            "tool": "ProcDump64",
            "target": "LSASS process",
            "timestamp": "2020-12-19T03:48:15Z",
            "output_file": "C:\\Windows\\Temp\\lsass.dmp",
            "confidence": 1.0,
            "mitre_technique": "T1003.001",
            "severity": "CRITICAL"
        }
    ],
    "additional_theft": [
        {
            "type": "Browser saved passwords",
            "browser": "Google Chrome",
            "credential_count": 47,
            "timestamp": "2020-12-19T03:49:30Z",
            "confidence": 0.85,
            "mitre_technique": "T1555.003"
        }
    ],
    "summary": {
        "total_accounts_compromised": 2,
        "critical_accounts": ["admin_backup"],
        "theft_methods": ["Plaintext file", "LSASS dump", "Browser credentials", "Brute force"],
        "impact": "CRITICAL - Admin credentials stolen and used for lateral movement"
    }
}
```

---

## Common Credential Theft Patterns

### Pattern 1: Mimikatz Execution
**Attack Flow:**
1. Download Mimikatz to compromised system
2. Run with admin privileges
3. Execute `sekurlsa::logonpasswords` command
4. Extract plaintext passwords from memory
5. Use stolen credentials for lateral movement

**Detection:**
- Mimikatz.exe in Prefetch
- Memory shows Mimikatz process
- LSASS access in Event Logs
- Subsequent lateral movement with new credentials

---

### Pattern 2: LSASS Dump with ProcDump
**Attack Flow:**
1. Use legitimate Microsoft ProcDump tool
2. Dump LSASS process memory
3. Exfiltrate dump file
4. Extract credentials offline (outside network)

**Detection:**
- ProcDump execution (Prefetch)
- lsass.dmp file created
- File exfiltrated (Exfiltration Agent correlation)
- May NOT see immediate lateral movement (extracted offline)

---

### Pattern 3: Password File Theft
**Attack Flow:**
1. Search filesystem for password files
2. Find passwords.txt, credentials.xlsx, etc.
3. Read plaintext credentials
4. Use for access

**Detection:**
- Password files accessed during incident
- File content contains credentials
- Credentials used in lateral movement
- Simple but effective

---

### Pattern 4: Browser Credential Dump
**Attack Flow:**
1. Locate browser credential databases
2. Use tools like LaZagne to decrypt
3. Extract saved passwords
4. Use for lateral movement or external access

**Detection:**
- Browser database files accessed
- LaZagne or similar tool execution
- Multiple accounts from different services

---

### Pattern 5: Brute Force Attack
**Attack Flow:**
1. Try many password combinations
2. Usually automated tool
3. Eventually guess correct password
4. Use for access

**Detection:**
- Many Event 4625 (failed logons)
- From same source IP
- Targeting same account
- Eventually successful logon (Event 4624)

---

## Cross-Validation Strategy

### Credential Theft → Usage Correlation

**Goal:** Prove stolen credentials were actually used

**Example:**
```python
# Credential Access Agent finds:
{
    "account": "admin_backup",
    "password": "P@ssw0rd123",
    "theft_time": "03:30:00"
}

# Lateral Movement Agent finds:
{
    "account_used": "admin_backup",
    "access_time": "03:45:33",
    "source": "10.0.0.50"
}

# Correlation:
if credential_theft.account == lateral_movement.account_used:
    if lateral_movement.time > credential_theft.time:
        confidence = 1.0  # Stolen creds were used
```

### Multi-Source Validation

**Evidence Stack:**
1. **Memory:** Mimikatz process running
2. **Prefetch:** MIMIKATZ.EXE-*.pf exists
3. **Filesystem:** lsass.dmp file created
4. **Event Logs:** No LSASS access denials (successful dump)
5. **Lateral Movement:** New account usage afterward

**Confidence:** 1.0 (all evidence confirms)

---

## Performance Optimization

### Speed Targets
- Memory process analysis: <10 seconds
- Event log parsing (4625): <15 seconds
- Password file search: <10 seconds
- Browser credential check: <5 seconds
- **Total analysis time: <40 seconds**

### Optimization Strategies

**1. Targeted Process Filtering**
```python
# Don't analyze ALL processes in memory
# Filter to suspicious names first

CREDENTIAL_TOOLS = [
    "mimikatz", "procdump", "lazagne", "pwdump",
    "fgdump", "gsecdump", "wce"
]

processes = memory.processes
suspicious = [p for p in processes 
              if any(tool in p.name.lower() for tool in CREDENTIAL_TOOLS)]
```

**2. Smart Event Log Filtering**
```python
# Don't parse ALL failed logons (could be thousands)
# Group and count, only detailed analysis on suspicious patterns

failed_logons = parse_event_logs(4625, incident_timeframe)

# Quick grouping
grouped = group_by(failed_logons, ["source_ip", "account"])
suspicious_groups = [g for g in grouped if len(g) >= 10]

# Only analyze suspicious groups in detail
```

---

## Integration with Other Agents

### Data to Lateral Movement Agent
```python
# If Credential Access finds stolen passwords:
{
    "compromised_accounts": ["admin_backup", "administrator"],
    "theft_time": "2020-12-19T03:30:00Z"
}

# Lateral Movement Agent checks:
# - Were these accounts used for lateral movement?
# - When? (should be AFTER theft time)
```

### Data from Persistence Agent
```python
# If Persistence found malware:
{
    "malware_location": "C:\\Windows\\Temp\\malware.exe"
}

# Credential Access Agent checks:
# - Did this malware access LSASS?
# - Did it create password dumps?
```

---

## False Positive Handling

### Legitimate Administrative Tools

**Problem:** Some legitimate tools can dump LSASS

**Examples:**
- ProcDump (Microsoft Sysinternals)
- Task Manager (can create dumps)
- Windows Error Reporting

**Mitigation:**
```python
def is_legitimate_dump(process, context):
    # Check parent process
    if process.parent == "taskmgr.exe":
        # User manually created dump via Task Manager
        return True, "Legitimate administrative action"
    
    # Check context
    if context.user_is_admin and context.is_business_hours:
        # IT admin during work hours
        return True, "Likely legitimate admin activity"
    
    # Check if followed by lateral movement
    if context.lateral_movement_after(process.timestamp):
        # Dump followed by malicious activity
        return False, "Suspicious despite legitimate tool"
    
    return False, "Requires investigation"
```

---

## Code Structure

```python
# agents/credential_access_agent.py

class CredentialAccessAgent:
    def __init__(self, mcp_client, llm):
        self.mcp_client = mcp_client
        self.llm = llm
        self.system_prompt = """You are the Credential Access Agent..."""
    
    async def analyze(self, state: Dict) -> Dict:
        """Main credential access analysis"""
        
        image_path = state["disk_image_path"]
        memory_path = state.get("memory_dump_path")
        timeframe = state["incident_timeframe"]
        lateral_findings = state.get("lateral_movement_findings", [])
        
        # Run analyses in parallel
        results = await asyncio.gather(
            self._analyze_credential_tools(memory_path),
            self._analyze_password_files(image_path),
            self._analyze_authentication_failures(image_path, timeframe),
            self._analyze_browser_credentials(image_path)
        )
        
        # Flatten results
        tool_findings = results[0]
        file_findings = results[1]
        auth_failures = results[2]
        browser_findings = results[3]
        
        # Identify compromised accounts
        compromised = self._identify_compromised_accounts(
            tool_findings,
            file_findings,
            auth_failures,
            browser_findings
        )
        
        # Correlate with lateral movement
        validated = self._correlate_with_lateral_movement(
            compromised,
            lateral_findings
        )
        
        return {
            "credential_access_findings": validated,
            "compromised_accounts": self._extract_account_list(validated),
            "summary": self._generate_summary(validated)
        }
    
    async def _analyze_credential_tools(self, memory_path: str) -> List[Dict]:
        """Detect credential dumping tools in memory"""
        
        processes = await self.mcp_client.call(
            "analyze_memory_processes",
            {"memory_path": memory_path}
        )
        
        CREDENTIAL_TOOLS = [
            "mimikatz", "procdump", "lazagne", "pwdump", "fgdump"
        ]
        
        findings = []
        for process in processes["processes"]:
            if any(tool in process["name"].lower() for tool in CREDENTIAL_TOOLS):
                findings.append({
                    **process,
                    "type": "credential_tool",
                    "suspicious": True,
                    "confidence": 1.0 if "mimikatz" in process["name"].lower() else 0.95,
                    "mitre_technique": "T1003.001"
                })
        
        return findings
    
    def _correlate_with_lateral_movement(
        self,
        cred_findings: List[Dict],
        lateral_findings: List[Dict]
    ) -> List[Dict]:
        """
        Check if stolen credentials were used for lateral movement
        """
        for cred in cred_findings:
            if "account_name" in cred:
                # Look for lateral movement with this account
                matching_lateral = [
                    lat for lat in lateral_findings
                    if lat.get("account_used") == cred["account_name"]
                    and lat["timestamp"] > cred["timestamp"]
                ]
                
                if matching_lateral:
                    cred["used_for_lateral_movement"] = True
                    cred["lateral_movement_timestamp"] = matching_lateral[0]["timestamp"]
                    cred["confidence"] = min(1.0, cred["confidence"] + 0.10)
        
        return cred_findings
```

---

## Testing Strategy

### Unit Tests
```python
def test_lsass_dump_detection():
    """Test detection of LSASS dumping"""
    process = {
        "name": "procdump64.exe",
        "command_line": "procdump64.exe -ma lsass.exe lsass.dmp"
    }
    assert credential_agent._is_credential_tool(process) == True

def test_brute_force_detection():
    """Test brute force pattern detection"""
    events = [
        {"event_id": 4625, "account": "admin", "timestamp": "03:00:00"},
        {"event_id": 4625, "account": "admin", "timestamp": "03:00:01"},
        # ... 48 more
    ]
    result = credential_agent._detect_brute_force(events)
    assert result["type"] == "brute_force"
    assert result["confidence"] >= 0.90
```

---

This Credential Access Agent identifies the critical question: **Which passwords were stolen and how?** This directly enables understanding of lateral movement capabilities.
