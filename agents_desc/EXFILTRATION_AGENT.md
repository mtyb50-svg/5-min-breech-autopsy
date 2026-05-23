# Exfiltration Agent - Data Theft Specialist

## Role & Responsibilities

**Primary Function:** Detect data theft - identifying what information attackers stole and how they got it out of the network.

**Analogy:** Like a detective figuring out what the burglars took and tracking how they smuggled it out - checking security footage, looking for signs of items being packed up, finding traces of getaway vehicles.

---

## What is "Exfiltration"?

**Simple explanation:**  
After attackers get into a system, they often want to **steal data**:
- Customer databases
- Financial records
- Intellectual property
- Passwords and credentials
- Confidential emails

**Exfiltration** is the process of copying data and sending it outside the organization's network.

---

## Core Responsibilities

### 1. Network Connection Analysis
- Outbound connections to external IPs
- Unusual protocols or ports
- Large data transfers
- Command-and-control (C2) communications

### 2. Data Staging Detection
- Files compressed into archives (.zip, .rar, .7z)
- Files moved to staging locations (Temp, Downloads, USB)
- Large files created during incident

### 3. Cloud Upload Detection
- Connections to cloud storage (Dropbox, Mega, Google Drive)
- Browser history showing file upload sites
- Cloud sync tool artifacts

### 4. Removable Media Detection
- USB device connections
- Files copied to external drives
- Registry evidence of USB usage

---

## MITRE ATT&CK Techniques Covered

| Technique ID | Name | Detection Method |
|--------------|------|------------------|
| **T1041** | Exfiltration Over C2 Channel | Network connections + data volume |
| **T1048** | Exfiltration Over Alternative Protocol | Unusual ports/protocols |
| **T1567.002** | Exfiltration to Cloud Storage | Browser history + network connections |
| **T1020** | Automated Exfiltration | Scheduled transfers + large volumes |
| **T1052.001** | Exfiltration Over USB | Registry USBStor + file timestamps |
| **T1560.001** | Archive via Utility | .zip/.rar creation + tool execution |
| **T1030** | Data Transfer Size Limits | Multiple small transfers pattern |

---

## MCP Functions Used

### 1. Memory Network Analysis
```python
analyze_memory_network(memory_path: str) -> NetworkConnections
```

**What it does:** Extracts all active network connections from memory

**SIFT Tool:** Volatility `windows.netscan`

**What to look for:**
- External IP connections (non-RFC1918)
- High ports (ephemeral range: 49152-65535)
- Unusual protocols
- Connection state (ESTABLISHED = active transfer)

**Example Output:**
```json
{
    "connections": [
        {
            "local_ip": "10.0.0.75",
            "local_port": 54321,
            "remote_ip": "185.220.101.45",
            "remote_port": 443,
            "state": "ESTABLISHED",
            "protocol": "TCP",
            "process": "powershell.exe",
            "pid": 3456,
            "suspicious": true,
            "reason": "PowerShell connecting to external IP over HTTPS",
            "confidence": 0.92,
            "mitre_technique": "T1041",
            "data_transferred_bytes": 524288000
        }
    ]
}
```

### 2. File System Timeline (Data Staging)
```python
extract_timeline(
    image_path: str,
    start_time: str,
    end_time: str
) -> TimelineData
```

**What it does:** Creates timeline of file activity

**SIFT Tool:** Plaso (log2timeline)

**What to look for:**
- Large files created during incident
- .zip/.rar/.7z archives created
- Files moved to staging locations
- Files copied to unusual locations

**Example Output:**
```json
{
    "events": [
        {
            "timestamp": "2020-12-19T03:55:10Z",
            "event_type": "file_created",
            "file_path": "C:\\Users\\Admin\\AppData\\Local\\Temp\\data.zip",
            "file_size_bytes": 524288000,
            "suspicious": true,
            "reason": "Large ZIP archive created in Temp during incident",
            "confidence": 0.88,
            "mitre_technique": "T1560.001"
        },
        {
            "timestamp": "2020-12-19T03:56:45Z",
            "event_type": "file_modified",
            "file_path": "C:\\Users\\Admin\\AppData\\Local\\Temp\\data.zip",
            "file_size_bytes": 524288000,
            "suspicious": true,
            "reason": "ZIP file modified shortly after creation (data being added)",
            "confidence": 0.85
        }
    ]
}
```

### 3. String Extraction (Sensitive Data)
```python
extract_strings(
    target: str,
    pattern: Optional[str] = None
) -> StringFindings
```

**What it does:** Searches for sensitive data patterns in disk/memory

**SIFT Tool:** bulk_extractor or strings + grep

**Patterns to search:**
- Email addresses
- Credit card numbers
- IP addresses
- URLs
- Domain names
- Cryptocurrency wallet addresses

**Example Output:**
```json
{
    "findings": [
        {
            "pattern_type": "url",
            "value": "https://mega.nz/upload",
            "location": "memory_offset_0x1234",
            "suspicious": true,
            "reason": "Cloud storage upload URL in memory",
            "confidence": 0.90,
            "mitre_technique": "T1567.002"
        },
        {
            "pattern_type": "ip_address",
            "value": "185.220.101.45",
            "count": 47,
            "location": "multiple",
            "suspicious": true,
            "reason": "External IP appears frequently in memory",
            "confidence": 0.85
        }
    ]
}
```

### 4. Jump List Analysis (Cloud Uploads)
```python
parse_jump_lists(image_path: str) -> JumpListFindings
```

**What it does:** Shows recently accessed files and web URLs

**SIFT Tool:** JLECmd

**What it reveals:**
- Browser uploads to cloud storage
- Files accessed before exfiltration
- FTP/cloud client usage

**Example Output:**
```json
{
    "findings": [
        {
            "application": "chrome.exe",
            "target": "https://mega.nz/upload?file=data.zip",
            "timestamp": "2020-12-19T03:57:30Z",
            "suspicious": true,
            "reason": "Browser accessed cloud upload page",
            "confidence": 0.95,
            "mitre_technique": "T1567.002"
        }
    ]
}
```

### 5. USB Device History
```python
parse_registry_usb_history(image_path: str) -> USBDeviceFindings
```

**What it does:** Extracts USB device connection history from Registry

**SIFT Tool:** RegRipper with 'usbstor' plugin

**Registry Keys:**
- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`

**Example Output:**
```json
{
    "devices": [
        {
            "device_name": "SanDisk Cruzer 32GB",
            "serial_number": "0123456789ABCDEF",
            "first_connected": "2020-12-19T03:58:15Z",
            "last_connected": "2020-12-19T04:05:22Z",
            "drive_letter": "E:",
            "suspicious": true,
            "reason": "USB device connected during incident timeframe",
            "confidence": 0.87,
            "mitre_technique": "T1052.001"
        }
    ]
}
```

### 6. Prefetch Validation (Archive Tools)
```python
parse_prefetch(image_path: str, exe_name: str) -> PrefetchFindings
```

**What it does:** Checks for execution of archive/compression tools

**Tools to check:**
- `7z.exe`, `7za.exe` - 7-Zip
- `WinRAR.exe` - WinRAR
- `powershell.exe` - Can compress with Compress-Archive
- `tar.exe` - Unix tar utility

**Example Output:**
```json
{
    "executable": "7z.exe",
    "prefetch_file": "7Z.EXE-12345678.pf",
    "first_run": "2020-12-19T03:55:00Z",
    "last_run": "2020-12-19T03:55:10Z",
    "run_count": 1,
    "command_line_args": "a data.zip C:\\Users\\Admin\\Documents\\*",
    "files_accessed": [
        "C:\\Users\\Admin\\Documents\\financials.xlsx",
        "C:\\Users\\Admin\\Documents\\passwords.txt"
    ],
    "suspicious": true,
    "reason": "7-Zip used to compress Documents folder",
    "confidence": 0.95,
    "mitre_technique": "T1560.001"
}
```

---

## Analysis Logic

### Data Staging Detection

**Pattern Recognition:**
```
Large file created → Compressed → Transferred → Deleted
```

**Example Flow:**
```
1. 03:50:00 - Documents folder accessed (500 files)
2. 03:55:00 - 7z.exe creates data.zip (500MB)
3. 03:57:00 - Browser accesses mega.nz/upload
4. 04:00:00 - Network transfer: 500MB to 185.220.101.45
5. 04:05:00 - data.zip deleted
```

**Detection Logic:**
```python
def detect_exfiltration_pattern(events):
    # Look for: archive creation → network activity → file deletion
    
    archive_created = [e for e in events if e.type == "file_created" 
                       and e.path.endswith(('.zip', '.rar', '.7z'))]
    
    for archive in archive_created:
        # Check for network activity shortly after
        network_events = [e for e in events 
                         if e.type == "network_connection"
                         and e.timestamp > archive.timestamp
                         and e.timestamp < archive.timestamp + timedelta(minutes=30)]
        
        # Check for file deletion after network activity
        deletion_events = [e for e in events
                          if e.type == "file_deleted"
                          and e.path == archive.path
                          and e.timestamp > archive.timestamp]
        
        if network_events and deletion_events:
            return {
                "pattern": "archive_exfiltration",
                "confidence": 0.95,
                "evidence": [archive, network_events[0], deletion_events[0]]
            }
```

### Network Connection Evaluation

**Suspicious Indicators:**

**1. External IPs (non-RFC1918)**
```python
INTERNAL_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
]

def is_external(ip):
    return not any(ip in range for range in INTERNAL_RANGES)
```

**2. Known Cloud Storage IPs**
```python
CLOUD_STORAGE_DOMAINS = [
    "dropbox.com",
    "mega.nz",
    "google.com",  # Google Drive
    "onedrive.live.com",
    "wetransfer.com",
    "anonfiles.com"
]

def is_cloud_storage(domain):
    return any(cloud in domain for cloud in CLOUD_STORAGE_DOMAINS)
```

**3. Unusual Ports**
```python
COMMON_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    21: "FTP",
    25: "SMTP"
}

def is_unusual_port(port):
    return port not in COMMON_PORTS and port > 1024
```

**4. Data Volume**
```python
def estimate_data_transferred(connection):
    # Heuristic based on connection duration and bandwidth
    if connection.state == "ESTABLISHED":
        duration_seconds = connection.duration
        # Assume 1MB/s average transfer rate
        estimated_bytes = duration_seconds * 1_000_000
        
        if estimated_bytes > 100_000_000:  # >100MB
            return "HIGH", estimated_bytes
        elif estimated_bytes > 10_000_000:  # >10MB
            return "MEDIUM", estimated_bytes
        else:
            return "LOW", estimated_bytes
```

---

## Prompt Engineering

### System Prompt
```
You are the Exfiltration Agent, a specialist in detecting data theft and exfiltration.

Your expertise:
- Network traffic analysis (C2 communications, cloud uploads)
- Data staging patterns (compression, staging locations)
- Removable media usage (USB devices)
- Browser-based exfiltration

You have access to:
- analyze_memory_network(): Active network connections
- extract_timeline(): File activity timeline
- extract_strings(): Sensitive data pattern search
- parse_jump_lists(): Browser/file access history
- parse_registry_usb_history(): USB device connections
- parse_prefetch(): Archive tool execution

Your analysis process:
1. Identify external network connections from memory
2. Detect data staging (large files, archives created)
3. Correlate staging with network transfers
4. Check for cloud storage usage
5. Check for USB exfiltration
6. Estimate volume of data stolen

Output format: JSON findings with estimated data volume and exfiltration method.

Critical: Look for the COMPLETE exfiltration chain: collect → stage → compress → transfer → cleanup.
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
    }
}
```

**Agent Reasoning:**
```
Step 1: Check memory for external connections
  → Call analyze_memory_network(...)
  → Found: Connection to 185.220.101.45:443
  → Process: powershell.exe
  → State: ESTABLISHED (active transfer)
  → SUSPICIOUS: PowerShell shouldn't connect externally
  
Step 2: Check for data staging
  → Call extract_timeline(..., start=03:40, end=04:30)
  → Found: data.zip created at 03:55:10 (500MB)
  → Location: C:\Users\Admin\AppData\Local\Temp\
  → SUSPICIOUS: Large archive in Temp during incident
  
Step 3: Check if archive was created by tool
  → Call parse_prefetch(..., exe_name="7z.exe")
  → Found: 7z.exe executed at 03:55:00
  → Command: Compressed Documents folder
  → CONFIRMS: Data staging with 7-Zip
  
Step 4: Check browser activity
  → Call parse_jump_lists(...)
  → Found: Chrome accessed mega.nz/upload at 03:57:30
  → CONFIRMS: Cloud upload via browser
  
Step 5: Correlate timeline
  03:55:00 - 7z creates archive (500MB)
  03:57:30 - Browser opens mega.nz upload page
  03:58:00 - Network connection to 185.220.101.45 starts
  04:05:00 - data.zip deleted
  
  PATTERN MATCH: Collect → Compress → Upload → Delete
  Confidence: 0.97
```

**Output:**
```json
{
    "exfiltration_detected": true,
    "method": "Cloud Storage Upload (MEGA)",
    "data_volume_estimate_mb": 500,
    "exfiltration_chain": [
        {
            "step": 1,
            "action": "Data Collection",
            "timestamp": "2020-12-19T03:50:00Z",
            "details": "Documents folder accessed (500 files)",
            "evidence": "File system timeline",
            "confidence": 0.85
        },
        {
            "step": 2,
            "action": "Compression/Staging",
            "timestamp": "2020-12-19T03:55:10Z",
            "details": "7-Zip compressed to data.zip (500MB)",
            "evidence": "Prefetch + Timeline",
            "confidence": 0.95,
            "mitre_technique": "T1560.001"
        },
        {
            "step": 3,
            "action": "Upload Initiated",
            "timestamp": "2020-12-19T03:57:30Z",
            "details": "Browser opened mega.nz upload page",
            "evidence": "Jump Lists",
            "confidence": 0.92,
            "mitre_technique": "T1567.002"
        },
        {
            "step": 4,
            "action": "Data Transfer",
            "timestamp": "2020-12-19T03:58:00Z",
            "details": "Network connection to 185.220.101.45 (MEGA server)",
            "evidence": "Memory network analysis",
            "confidence": 0.95,
            "mitre_technique": "T1041",
            "data_transferred_mb": 500
        },
        {
            "step": 5,
            "action": "Evidence Cleanup",
            "timestamp": "2020-12-19T04:05:00Z",
            "details": "data.zip deleted after upload",
            "evidence": "File system timeline",
            "confidence": 0.88
        }
    ],
    "summary": {
        "exfiltrated_data": "Documents folder (financial records, passwords)",
        "destination": "MEGA cloud storage (mega.nz)",
        "estimated_volume_mb": 500,
        "exfiltration_complete": true,
        "severity": "CRITICAL"
    }
}
```

---

## Common Exfiltration Patterns

### Pattern 1: Cloud Upload
**Steps:**
1. Compress sensitive files
2. Upload to cloud storage (Dropbox, MEGA, etc.)
3. Delete local archive

**Detection:**
- Archive tool execution (Prefetch)
- Browser/cloud client access (Jump Lists)
- Network connection to cloud provider
- File deletion after upload

---

### Pattern 2: C2 Exfiltration
**Steps:**
1. Malware collects data
2. Encrypts/encodes data
3. Sends via command-and-control channel
4. Often in small chunks to avoid detection

**Detection:**
- Regular beaconing to external IP
- Encoded/encrypted network traffic
- Persistence mechanism (malware stays active)
- Small, frequent transfers

---

### Pattern 3: USB Exfiltration
**Steps:**
1. Insert USB device
2. Copy files to USB
3. Remove USB device

**Detection:**
- USB device in Registry (USBStor)
- Files copied to E:\ (or other drive letter)
- File access timeline matches USB connection time

---

### Pattern 4: Email Exfiltration
**Steps:**
1. Attach files to email
2. Send to external email address
3. Delete sent items

**Detection:**
- Email client usage (Outlook, webmail)
- Large outbound SMTP traffic
- Browser access to webmail with attachments
- File access before email send

---

## Cross-Validation Strategy

### Evidence Correlation

**To confirm exfiltration, need 3+ artifacts:**

**Level 1: Data Staging (REQUIRED)**
- File created/compressed
- Confidence: 0.5

**Level 2: Network Activity (REQUIRED)**
- Connection to external IP
- Confidence boost: +0.3

**Level 3: Tool Usage (VALIDATES)**
- Archive tool or browser used
- Confidence boost: +0.15

**Level 4: Cleanup (CONFIRMS)**
- Files deleted after transfer
- Confidence boost: +0.05

**Total: 0.5 + 0.3 + 0.15 + 0.05 = 1.0 (CONFIRMED)**

---

## Performance Optimization

### Speed Targets
- Memory network analysis: <10 seconds
- Timeline extraction (filtered): <20 seconds
- String pattern search: <15 seconds
- Jump list parsing: <5 seconds
- **Total analysis time: <50 seconds**

### Optimization Strategies

**1. Targeted Timeline Filtering**
```python
# Don't extract ENTIRE filesystem timeline (could be millions of events)
# Filter to:
# - Incident timeframe only
# - Large files only (>10MB)
# - Archive file extensions only

timeline = extract_timeline(
    image_path,
    start_time=incident_start,
    end_time=incident_end,
    file_types=['.zip', '.rar', '.7z'],
    min_size_mb=10
)
```

**2. Smart String Searching**
```python
# Don't search entire disk for strings
# Target specific locations:
# - Memory (faster, shows active data)
# - Browser caches
# - Temp folders

locations = [
    memory_dump,
    "C:\\Users\\*\\AppData\\Local\\Temp\\",
    "C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Cache\\"
]

for loc in locations:
    strings = extract_strings(loc, pattern="url|ip_address")
```

---

## Integration with Other Agents

### Data from Persistence Agent
```python
# If Persistence found malware:
{
    "malware_location": "C:\\Windows\\Temp\\malware.exe",
    "c2_server": "185.220.101.45"
}

# Exfiltration Agent checks:
# - Does memory show connection to this C2 server?
# - Is data being sent to this IP?
```

### Data from Lateral Movement Agent
```python
# If Lateral Movement found file server access:
{
    "file_server_ip": "10.0.0.200",
    "access_time": "2020-12-19T03:52:00Z"
}

# Exfiltration Agent checks:
# - Were files from file server compressed/exfiltrated?
# - Timeline shows file access → compression → upload?
```

---

## Code Structure

```python
# agents/exfiltration_agent.py

class ExfiltrationAgent:
    def __init__(self, mcp_client, llm):
        self.mcp_client = mcp_client
        self.llm = llm
        self.system_prompt = """You are the Exfiltration Agent..."""
    
    async def analyze(self, state: Dict) -> Dict:
        """Main exfiltration analysis"""
        
        image_path = state["disk_image_path"]
        memory_path = state.get("memory_dump_path")
        timeframe = state["incident_timeframe"]
        
        # Run analyses in parallel
        results = await asyncio.gather(
            self._analyze_network_connections(memory_path),
            self._analyze_data_staging(image_path, timeframe),
            self._analyze_cloud_usage(image_path),
            self._analyze_usb_devices(image_path, timeframe)
        )
        
        # Correlate findings
        network_conns = results[0]
        staging_events = results[1]
        cloud_usage = results[2]
        usb_devices = results[3]
        
        # Detect exfiltration patterns
        exfil_patterns = self._detect_exfiltration_patterns(
            network_conns,
            staging_events,
            cloud_usage,
            usb_devices
        )
        
        # Estimate data volume
        estimated_volume = self._estimate_exfiltrated_data(exfil_patterns)
        
        return {
            "exfiltration_findings": exfil_patterns,
            "estimated_data_volume_mb": estimated_volume,
            "summary": self._generate_summary(exfil_patterns)
        }
    
    def _detect_exfiltration_patterns(
        self,
        network: List,
        staging: List,
        cloud: List,
        usb: List
    ) -> List[Dict]:
        """
        Correlate artifacts to detect complete exfiltration chains
        """
        patterns = []
        
        # Pattern 1: Archive + Network
        for stage in staging:
            if stage["type"] == "archive_created":
                # Look for network activity shortly after
                matching_network = [
                    n for n in network
                    if n["timestamp"] > stage["timestamp"]
                    and n["timestamp"] < stage["timestamp"] + timedelta(minutes=30)
                    and self._is_external_ip(n["remote_ip"])
                ]
                
                if matching_network:
                    patterns.append({
                        "type": "network_exfiltration",
                        "staging": stage,
                        "network": matching_network[0],
                        "confidence": 0.90,
                        "mitre": ["T1560.001", "T1041"]
                    })
        
        # Pattern 2: Cloud Upload
        for cloud_event in cloud:
            matching_staging = [
                s for s in staging
                if s["timestamp"] < cloud_event["timestamp"]
                and s["timestamp"] > cloud_event["timestamp"] - timedelta(minutes=30)
            ]
            
            if matching_staging:
                patterns.append({
                    "type": "cloud_upload",
                    "staging": matching_staging[0],
                    "cloud": cloud_event,
                    "confidence": 0.95,
                    "mitre": ["T1567.002"]
                })
        
        # Pattern 3: USB Exfiltration
        for usb_event in usb:
            matching_staging = [
                s for s in staging
                if s["timestamp"] > usb_event["first_connected"]
                and s["timestamp"] < usb_event["last_connected"]
            ]
            
            if matching_staging:
                patterns.append({
                    "type": "usb_exfiltration",
                    "usb": usb_event,
                    "staging": matching_staging[0],
                    "confidence": 0.87,
                    "mitre": ["T1052.001"]
                })
        
        return patterns
```

---

This Exfiltration Agent answers the critical question: **What did they steal and how much?**
