# MCP Server - Safe SIFT Tool Wrapper

## Overview

**Purpose:** Provide a secure, type-safe interface between AI agents and SIFT forensic tools.

**Critical Principle:** The MCP server is the **architectural safety boundary** that physically prevents AI agents from destroying evidence, regardless of what prompts instruct them to do.

---

## Why MCP Server?

### The Problem with Direct Shell Access

**Bad approach (what NOT to do):**
```python
# DANGEROUS - AI has unrestricted shell access
def execute_shell(command: str):
    result = subprocess.run(command, shell=True, capture_output=True)
    return result.stdout
```

**Why this is dangerous:**
- AI could run: `rm -rf /evidence/*` (deletes all evidence)
- AI could run: `dd if=/dev/zero of=/evidence/disk.dd` (overwrites evidence)
- AI could modify evidence files
- Prompt injection could bypass restrictions

---

### The MCP Approach (Correct)

**MCP server exposes ONLY safe, typed functions:**
```python
# SAFE - AI can only call pre-defined, read-only functions
@mcp_server.tool()
def parse_registry_run_keys(image_path: str) -> RegistryRunKeyFindings:
    """Extract Windows Run keys - READ ONLY"""
    # MCP server handles:
    # 1. Mount image read-only
    # 2. Run RegRipper
    # 3. Parse output
    # 4. Return structured data
    # 5. Unmount image
    
    # AI CANNOT run arbitrary commands
    # AI CANNOT modify evidence
    # AI CANNOT access filesystem directly
```

**Benefits:**
1. ✅ **Evidence integrity guaranteed** - physically impossible to modify
2. ✅ **Type safety** - functions return structured data, not raw text
3. ✅ **Error isolation** - tool failures don't crash the entire system
4. ✅ **Audit trail** - every function call logged
5. ✅ **Context window management** - server parses massive outputs into concise JSON

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│            AI AGENT (LangGraph)                 │
│  "I want to check Registry Run keys"           │
└────────────────┬────────────────────────────────┘
                 │
                 ▼ MCP Function Call
┌─────────────────────────────────────────────────┐
│           MCP SERVER (FastAPI)                  │
│                                                 │
│  @tool parse_registry_run_keys(image_path)     │
│    ├─ Validate inputs                          │
│    ├─ Mount image read-only                    │
│    ├─ Execute SIFT tool                        │
│    ├─ Parse raw output                         │
│    ├─ Structure into JSON                      │
│    ├─ Unmount image                            │
│    └─ Return typed data                        │
│                                                 │
│  🔒 SAFETY BOUNDARY - NO SHELL ACCESS          │
└────────────────┬────────────────────────────────┘
                 │
                 ▼ Subprocess (controlled)
┌─────────────────────────────────────────────────┐
│         SIFT TOOLS (Ubuntu VM)                  │
│                                                 │
│  RegRipper, Volatility, Plaso, etc.            │
│  Evidence mounted READ-ONLY at OS level        │
└─────────────────────────────────────────────────┘
```

---

## Technology Stack

### MCP Server
- **Framework:** FastAPI (Python)
- **MCP SDK:** `mcp` Python package from Anthropic
- **Validation:** Pydantic models
- **Async:** AsyncIO for parallel tool execution

### Tool Execution
- **Subprocess:** Python `subprocess` module (NOT `shell=True`)
- **Image Mounting:** `ewfmount`, `mount` commands
- **Parsing:** Custom parsers for each tool

---

## Implementation Guide

### Step 1: Basic MCP Server Setup

```python
# mcp_server/server.py

from fastapi import FastAPI
from mcp import MCPServer
from typing import Optional, List, Dict
from pydantic import BaseModel
import subprocess
import json

# Initialize MCP server
app = FastAPI()
mcp = MCPServer("sift-forensics-server")

# Data models for type safety
class RegistryRunKeyFinding(BaseModel):
    key: str
    value_name: str
    data: str
    timestamp: str
    suspicious: bool
    confidence: float
    mitre_technique: Optional[str]

class RegistryRunKeyFindings(BaseModel):
    findings: List[RegistryRunKeyFinding]
    total_keys: int
    suspicious_count: int

# Register with FastAPI
@app.on_event("startup")
async def startup():
    await mcp.start()

@app.on_event("shutdown")
async def shutdown():
    await mcp.stop()
```

---

### Step 2: Implement Safe Tool Function

```python
# mcp_server/tools/registry.py

import subprocess
import tempfile
import os
from pathlib import Path

@mcp.tool()
async def parse_registry_run_keys(
    image_path: str
) -> RegistryRunKeyFindings:
    """
    Extract Windows Registry Run keys from disk image
    
    Args:
        image_path: Path to disk image (E01 or DD format)
    
    Returns:
        Structured findings with suspicious indicators
    
    Safety:
        - Mounts image READ-ONLY
        - Cannot modify evidence
        - Validates all inputs
    """
    
    # Step 1: Validate input
    if not os.path.exists(image_path):
        raise ValueError(f"Image not found: {image_path}")
    
    if not image_path.endswith(('.e01', '.E01', '.dd', '.raw')):
        raise ValueError(f"Unsupported image format: {image_path}")
    
    # Step 2: Create temporary mount point
    mount_point = tempfile.mkdtemp(prefix="evidence_mount_")
    
    try:
        # Step 3: Mount image READ-ONLY
        if image_path.endswith(('.e01', '.E01')):
            # E01 format - use ewfmount
            ewf_mount = tempfile.mkdtemp(prefix="ewf_mount_")
            
            subprocess.run([
                "ewfmount",
                image_path,
                ewf_mount
            ], check=True)
            
            # Mount the EWF virtual file
            subprocess.run([
                "mount",
                "-o", "ro,loop,noexec,nosuid",
                f"{ewf_mount}/ewf1",
                mount_point
            ], check=True)
        else:
            # DD/RAW format - direct mount
            subprocess.run([
                "mount",
                "-o", "ro,loop,noexec,nosuid",
                image_path,
                mount_point
            ], check=True)
        
        # Step 4: Locate registry hive
        software_hive = Path(mount_point) / "Windows/System32/config/SOFTWARE"
        
        if not software_hive.exists():
            raise FileNotFoundError("SOFTWARE registry hive not found")
        
        # Step 5: Copy hive to temp location (RegRipper needs local file)
        temp_hive = tempfile.NamedTemporaryFile(delete=False, suffix=".reg")
        subprocess.run([
            "cp",
            str(software_hive),
            temp_hive.name
        ], check=True)
        
        # Step 6: Run RegRipper
        result = subprocess.run([
            "rip.pl",
            "-r", temp_hive.name,
            "-p", "run"
        ], capture_output=True, text=True, check=True)
        
        # Step 7: Parse RegRipper output
        findings = parse_regripper_output(result.stdout)
        
        # Step 8: Evaluate suspiciousness
        for finding in findings:
            finding["suspicious"] = is_suspicious_run_key(finding)
            finding["confidence"] = calculate_confidence(finding)
        
        # Step 9: Return structured results
        return RegistryRunKeyFindings(
            findings=findings,
            total_keys=len(findings),
            suspicious_count=sum(1 for f in findings if f["suspicious"])
        )
    
    finally:
        # Step 10: Cleanup - ALWAYS unmount and remove temp files
        subprocess.run(["umount", mount_point], check=False)
        if 'ewf_mount' in locals():
            subprocess.run(["umount", ewf_mount], check=False)
            os.rmdir(ewf_mount)
        os.rmdir(mount_point)
        if 'temp_hive' in locals():
            os.unlink(temp_hive.name)
```

---

### Step 3: Output Parsing

```python
# mcp_server/parsers/regripper.py

import re
from typing import List, Dict
from datetime import datetime

def parse_regripper_output(output: str) -> List[Dict]:
    """
    Parse RegRipper 'run' plugin output into structured findings
    
    RegRipper output format:
    ------------
    Run
    
    HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    LastWrite: 2020-12-19 03:42:17Z
    
    WindowsDefender -> C:\Windows\Temp\svchost.exe
    OneDrive -> C:\Program Files\Microsoft OneDrive\OneDrive.exe
    """
    
    findings = []
    current_key = None
    current_timestamp = None
    
    for line in output.split('\n'):
        line = line.strip()
        
        # Parse registry key path
        if line.startswith("HKLM") or line.startswith("HKCU"):
            current_key = line
            continue
        
        # Parse LastWrite timestamp
        if line.startswith("LastWrite:"):
            timestamp_str = line.split("LastWrite:")[1].strip()
            current_timestamp = timestamp_str
            continue
        
        # Parse value entries (name -> data)
        if " -> " in line and current_key:
            value_name, data = line.split(" -> ", 1)
            
            findings.append({
                "key": current_key,
                "value_name": value_name.strip(),
                "data": data.strip(),
                "timestamp": current_timestamp,
                "suspicious": False,  # Will be evaluated later
                "confidence": 0.0,
                "mitre_technique": "T1547.001"
            })
    
    return findings

def is_suspicious_run_key(finding: Dict) -> bool:
    """Evaluate if a Run key is suspicious"""
    
    data = finding["data"].lower()
    
    # Suspicious locations
    suspicious_paths = [
        "\\temp\\",
        "\\tmp\\",
        "\\downloads\\",
        "\\appdata\\local\\temp\\",
        "\\users\\public\\"
    ]
    
    if any(path in data for path in suspicious_paths):
        return True
    
    # System file in wrong location
    system_files = ["svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe"]
    file_name = data.split("\\")[-1]
    
    if file_name in system_files:
        if "\\windows\\system32\\" not in data:
            return True  # System file not in System32
    
    return False

def calculate_confidence(finding: Dict) -> float:
    """Calculate confidence score for finding"""
    
    base_confidence = 0.5
    
    # Boost for suspicious location
    if finding["suspicious"]:
        base_confidence += 0.4
    
    # Boost for known legitimate programs (negative boost for unknowns)
    legitimate_programs = [
        "onedrive.exe",
        "dropbox.exe",
        "chrome.exe",
        "teams.exe"
    ]
    
    file_name = finding["data"].lower().split("\\")[-1]
    if file_name in legitimate_programs:
        base_confidence -= 0.3  # Likely legitimate
    
    return max(0.0, min(1.0, base_confidence))
```

---

### Step 4: Additional Tool Functions

#### Prefetch Parser
```python
@mcp.tool()
async def parse_prefetch(
    image_path: str,
    exe_name: Optional[str] = None
) -> PrefetchFindings:
    """
    Parse Windows Prefetch files
    
    Args:
        image_path: Path to disk image
        exe_name: Optional - specific executable to search for
    
    Returns:
        Prefetch data with execution timestamps and file access
    """
    
    mount_point = mount_image_readonly(image_path)
    
    try:
        prefetch_dir = Path(mount_point) / "Windows/Prefetch"
        
        if not prefetch_dir.exists():
            return PrefetchFindings(findings=[], total_files=0)
        
        # Run PECmd to parse prefetch
        result = subprocess.run([
            "PECmd.exe",
            "-d", str(prefetch_dir),
            "--csv", "/tmp/",
            "--csvf", "prefetch_output.csv"
        ], capture_output=True, check=True)
        
        # Parse CSV output
        findings = parse_prefetch_csv("/tmp/prefetch_output.csv")
        
        # Filter by exe_name if provided
        if exe_name:
            findings = [f for f in findings if exe_name.lower() in f["executable"].lower()]
        
        return PrefetchFindings(
            findings=findings,
            total_files=len(findings)
        )
    
    finally:
        unmount_image(mount_point)
```

#### Memory Network Analysis
```python
@mcp.tool()
async def analyze_memory_network(
    memory_path: str
) -> NetworkConnections:
    """
    Extract network connections from memory dump
    
    Args:
        memory_path: Path to memory dump file
    
    Returns:
        Active network connections with process info
    """
    
    # Volatility doesn't need mounting, works directly on dump
    result = subprocess.run([
        "volatility",
        "-f", memory_path,
        "windows.netscan"
    ], capture_output=True, text=True, check=True)
    
    # Parse Volatility output
    connections = parse_volatility_netscan(result.stdout)
    
    # Evaluate suspiciousness
    for conn in connections:
        conn["suspicious"] = is_suspicious_connection(conn)
    
    return NetworkConnections(connections=connections)

def is_suspicious_connection(conn: Dict) -> bool:
    """Evaluate if network connection is suspicious"""
    
    # External IP (not RFC1918)
    if is_external_ip(conn["remote_ip"]):
        # External connection is suspicious
        return True
    
    # Unusual process making connection
    suspicious_processes = [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "regsvr32.exe"
    ]
    
    if conn["process"].lower() in suspicious_processes:
        return True
    
    return False
```

#### Event Log Parser
```python
@mcp.tool()
async def parse_event_logs(
    image_path: str,
    event_ids: List[int],
    start_time: Optional[str] = None,
    end_time: Optional[str] = None
) -> EventLogData:
    """
    Parse Windows Event Logs for specific event IDs
    
    Args:
        image_path: Path to disk image
        event_ids: List of event IDs to extract (e.g., [4624, 4648])
        start_time: Optional start time filter (ISO format)
        end_time: Optional end time filter (ISO format)
    
    Returns:
        Filtered event log entries
    """
    
    mount_point = mount_image_readonly(image_path)
    
    try:
        evtx_dir = Path(mount_point) / "Windows/System32/winevt/Logs"
        security_log = evtx_dir / "Security.evtx"
        
        if not security_log.exists():
            return EventLogData(events=[], total_events=0)
        
        # Parse EVTX with python-evtx
        result = subprocess.run([
            "evtx_dump.py",
            str(security_log)
        ], capture_output=True, text=True, check=True)
        
        # Parse XML output
        events = parse_evtx_xml(result.stdout)
        
        # Filter by event IDs
        events = [e for e in events if e["event_id"] in event_ids]
        
        # Filter by time range if provided
        if start_time:
            events = [e for e in events if e["timestamp"] >= start_time]
        if end_time:
            events = [e for e in events if e["timestamp"] <= end_time]
        
        return EventLogData(
            events=events,
            total_events=len(events)
        )
    
    finally:
        unmount_image(mount_point)
```

---

## Safety Features

### 1. Input Validation

```python
def validate_image_path(path: str):
    """Validate evidence path before processing"""
    
    # Must be absolute path
    if not os.path.isabs(path):
        raise ValueError("Image path must be absolute")
    
    # Must exist
    if not os.path.exists(path):
        raise FileNotFoundError(f"Image not found: {path}")
    
    # Must be supported format
    valid_extensions = ['.e01', '.E01', '.dd', '.raw', '.001']
    if not any(path.endswith(ext) for ext in valid_extensions):
        raise ValueError(f"Unsupported format: {path}")
    
    # Must not be a symlink (prevent path traversal)
    if os.path.islink(path):
        raise ValueError("Symlinks not allowed")
    
    return True
```

### 2. Read-Only Mounting

```python
def mount_image_readonly(image_path: str) -> str:
    """Mount image with maximum safety"""
    
    mount_point = tempfile.mkdtemp(prefix="evidence_")
    
    # Critical flags:
    # ro = read-only
    # noexec = cannot execute binaries from mounted image
    # nosuid = cannot use setuid binaries
    # nodev = cannot use device files
    
    subprocess.run([
        "mount",
        "-o", "ro,noexec,nosuid,nodev",
        image_path,
        mount_point
    ], check=True)
    
    return mount_point
```

### 3. Error Handling

```python
@mcp.tool()
async def parse_registry_run_keys(image_path: str) -> RegistryRunKeyFindings:
    """Error handling example"""
    
    try:
        # Validate input
        validate_image_path(image_path)
        
        # Mount and process
        mount_point = mount_image_readonly(image_path)
        
        # ... processing ...
        
    except subprocess.CalledProcessError as e:
        # Tool execution failed
        logging.error(f"RegRipper failed: {e.stderr}")
        raise ToolExecutionError(f"RegRipper execution failed: {e}")
    
    except FileNotFoundError as e:
        # Registry hive not found
        logging.warning(f"Registry hive missing: {e}")
        return RegistryRunKeyFindings(findings=[], total_keys=0)
    
    except Exception as e:
        # Unexpected error
        logging.exception("Unexpected error in parse_registry_run_keys")
        raise
    
    finally:
        # ALWAYS cleanup
        if 'mount_point' in locals():
            unmount_image(mount_point)
```

---

## Configuration

```python
# mcp_server/config.py

from pydantic import BaseSettings

class Settings(BaseSettings):
    # Server
    MCP_SERVER_HOST: str = "127.0.0.1"
    MCP_SERVER_PORT: int = 8000
    
    # Evidence paths
    EVIDENCE_BASE_PATH: str = "/mnt/user-data/uploads"
    MOUNT_BASE_PATH: str = "/mnt/evidence"
    
    # Tool paths
    REGRIPPER_PATH: str = "/usr/local/bin/rip.pl"
    PECMD_PATH: str = "/usr/local/bin/PECmd.exe"
    VOLATILITY_PATH: str = "/usr/local/bin/volatility"
    PLASO_PATH: str = "/usr/local/bin/log2timeline.py"
    
    # Safety
    MAX_MOUNT_TIME_SECONDS: int = 3600  # Auto-unmount after 1 hour
    ALLOW_WRITE_OPERATIONS: bool = False  # NEVER set to True
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "/var/log/mcp-server.log"
    
    class Config:
        env_file = ".env"

settings = Settings()
```

---

## Deployment

### Docker Container (Recommended)

```dockerfile
# Dockerfile

FROM ubuntu:22.04

# Install SIFT Workstation tools
RUN apt-get update && apt-get install -y \
    python3.11 \
    python3-pip \
    ewftools \
    sleuthkit \
    volatility \
    && rm -rf /var/lib/apt/lists/*

# Install MCP server dependencies
COPY requirements.txt /app/
RUN pip3 install -r /app/requirements.txt

# Copy MCP server code
COPY mcp_server/ /app/mcp_server/

# Create evidence directories
RUN mkdir -p /mnt/evidence /mnt/user-data/uploads

# Run as non-root user
RUN useradd -m -u 1000 forensics
USER forensics

# Start MCP server
CMD ["uvicorn", "mcp_server.server:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## Testing

### Unit Tests
```python
# tests/test_registry_parser.py

import pytest
from mcp_server.tools.registry import parse_registry_run_keys

@pytest.mark.asyncio
async def test_parse_registry_run_keys():
    """Test registry parsing with known sample"""
    
    # Use test disk image
    result = await parse_registry_run_keys("tests/data/test_image.dd")
    
    # Verify structure
    assert isinstance(result, RegistryRunKeyFindings)
    assert len(result.findings) > 0
    
    # Verify suspicious detection
    suspicious = [f for f in result.findings if f.suspicious]
    assert len(suspicious) >= 1  # Test image has known suspicious key

def test_is_suspicious_run_key():
    """Test suspicious detection logic"""
    
    # Suspicious: System file in Temp
    finding = {
        "data": "C:\\Windows\\Temp\\svchost.exe"
    }
    assert is_suspicious_run_key(finding) == True
    
    # Legitimate: OneDrive in Program Files
    finding = {
        "data": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe"
    }
    assert is_suspicious_run_key(finding) == False
```

---

## Performance Monitoring

```python
# mcp_server/middleware/metrics.py

import time
import logging
from functools import wraps

def measure_execution_time(func):
    """Decorator to measure tool execution time"""
    
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        
        try:
            result = await func(*args, **kwargs)
            duration = time.time() - start_time
            
            logging.info(f"{func.__name__} completed in {duration:.2f}s")
            
            return result
        
        except Exception as e:
            duration = time.time() - start_time
            logging.error(f"{func.__name__} failed after {duration:.2f}s: {e}")
            raise
    
    return wrapper

# Apply to all tools
@mcp.tool()
@measure_execution_time
async def parse_registry_run_keys(image_path: str):
    # ... implementation ...
```

---

## Security Checklist

**Before deploying MCP server, verify:**

- [ ] All image mounts use `ro` (read-only) flag
- [ ] No functions expose shell execution
- [ ] All inputs are validated
- [ ] Subprocess calls use list arguments (not `shell=True`)
- [ ] Evidence base path is restricted
- [ ] Temp files are cleaned up in `finally` blocks
- [ ] All errors are logged
- [ ] Function calls are audited
- [ ] SHA-256 hash verification is implemented
- [ ] Max execution time limits are set

---

This MCP server is the **architectural guarantee** of evidence integrity. Get this right, and you win on technical merit.
