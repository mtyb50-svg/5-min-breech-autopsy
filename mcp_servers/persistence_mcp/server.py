#!/usr/bin/env python3
"""
Persistence Agent MCP Server — built with FastMCP
==================================================
Tools:
  1. parse_registry_run_keys   — auto-start programs via Registry
  2. parse_registry_services   — installed Windows services
  3. parse_scheduled_tasks     — scheduled task analysis
  4. analyze_startup_folders   — startup folder file listing
  5. parse_prefetch            — validate executable execution via Prefetch

Evidence dir : ~/lab/
Logs         : ~/mcp_server/logs/persistence_mcp.log
"""

import hashlib
import logging
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from fastmcp import FastMCP

LAB_DIR = Path.home() / "lab"
LOG_DIR = Path.home() / "mcp_server" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "persistence_mcp.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("persistence_mcp")

mcp = FastMCP(
    name="persistence-mcp-server",
    instructions=(
        "Persistence specialist MCP server. Detects Registry Run keys, "
        "Windows services, scheduled tasks, startup folders, and Prefetch "
        "evidence of malicious persistence mechanisms. "
        "Evidence files must be placed in ~/lab/."
    ),
)

LEGITIMATE_RUN_KEYS = {
    "OneDrive": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
    "SecurityHealth": "C:\\Windows\\System32\\SecurityHealthSystray.exe",
    "VMware Tools": "C:\\Program Files\\VMware\\VMware Tools\\",
    "Teams": "C:\\Users",
    "Discord": "C:\\Users",
}

SUSPICIOUS_PATHS = [
    "\\temp\\",
    "\\downloads\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\recycle",
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
]

SUSPICIOUS_EXE_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
    "explorer.exe", "services.exe", "smss.exe",
}


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timed out after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -1, "", f"Tool not found: {cmd[0]}"


def _resolve(file_path: str) -> Path:
    """Resolve a path to ~/lab/ sandbox with symlink rejection."""
    p = Path(file_path)
    if p.is_absolute():
        if p.is_symlink():
            raise PermissionError(f"Symlink rejected (evidence integrity): {p}")
        if p.exists():
            return p
        raise FileNotFoundError(f"Not found: {p}")
    candidate = LAB_DIR / p
    if candidate.is_symlink():
        raise PermissionError(f"Symlink rejected (evidence integrity): {candidate}")
    if candidate.exists():
        return candidate
    raise FileNotFoundError(f"Not found: {file_path} (checked {LAB_DIR})")


def _get_partition_offset(image: Path) -> int | None:
    rc, out, _ = _run(["mmls", str(image)], timeout=30)
    if rc != 0:
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and re.match(r"^\d+:", parts[0]):
            if parts[1] not in ("Meta", "-----"):
                try:
                    return int(parts[2])
                except ValueError:
                    continue
    return None


def _fls_lines(image: Path) -> list[str]:
    offset = _get_partition_offset(image)
    cmd = ["fls", "-r", "-p", str(image)]
    if offset:
        cmd = ["fls", "-r", "-p", "-o", str(offset), str(image)]
    rc, out, _ = _run(cmd, timeout=60)
    return out.splitlines() if rc == 0 else []


def _is_suspicious_path(exe_path: str) -> bool:
    low = exe_path.lower()
    return any(p in low for p in SUSPICIOUS_PATHS)


def _is_masquerading(value_name: str, exe_path: str) -> bool:
    exe_name = Path(exe_path).name.lower()
    return exe_name in SUSPICIOUS_EXE_NAMES and _is_suspicious_path(exe_path)


def _confidence_run_key(value_name: str, exe_path: str) -> tuple[bool, str, float]:
    if _is_masquerading(value_name, exe_path):
        return True, f"System file name '{Path(exe_path).name}' in suspicious location", 0.98
    if _is_suspicious_path(exe_path):
        return True, "Executable in suspicious location (Temp/Downloads/AppData)", 0.92
    for legit_name, legit_path in LEGITIMATE_RUN_KEYS.items():
        if legit_name.lower() in value_name.lower() and exe_path.lower().startswith(legit_path.lower()):
            return False, f"Legitimate program: {legit_name}", 0.95
    return False, "No obvious indicators", 0.40


@mcp.tool()
async def parse_registry_run_keys(image_path: str) -> dict[str, Any]:
    """
    Extract all Registry Run keys (programs configured to auto-start).

    Checks HKLM and HKCU Run/RunOnce keys using RegRipper.
    Returns findings with suspicion scores and MITRE ATT&CK mapping.
    Pass a filename relative to ~/lab/ or an absolute path.
    """
    t0 = time.time()
    log.info(f"[parse_registry_run_keys] {image_path}")

    try:
        fp = _resolve(image_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    lines = _fls_lines(fp)

    findings = []

    rc, rip_out, _ = _run(["regripper", "-r", str(fp), "-p", "run"], timeout=30)
    if rc == 0 and rip_out.strip():
        for line in rip_out.splitlines():
            m = re.match(r"^\s*(.+?)\s*=\s*(.+)$", line)
            if m:
                value_name, data = m.group(1).strip(), m.group(2).strip()
                suspicious, reason, confidence = _confidence_run_key(value_name, data)
                findings.append({
                    "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "value_name": value_name,
                    "data": data,
                    "suspicious": suspicious,
                    "reason": reason,
                    "confidence": confidence,
                    "mitre_technique": "T1547.001" if suspicious else None,
                    "severity": "HIGH" if suspicious else "INFO",
                })
    else:
        for line in lines:
            if "currentversion\\run" in line.lower() or "currentversion/run" in line.lower():
                m = re.search(r":\s+(.+)$", line)
                if m:
                    path = m.group(1).strip()
                    suspicious, reason, confidence = _confidence_run_key("unknown", path)
                    findings.append({
                        "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "value_name": Path(path).name,
                        "data": path,
                        "suspicious": suspicious,
                        "reason": reason,
                        "confidence": confidence,
                        "mitre_technique": "T1547.001" if suspicious else None,
                        "severity": "HIGH" if suspicious else "INFO",
                    })

    if not findings:
        for line in lines:
            line_lower = line.lower()
            if "\\run\\" in line_lower or "/run/" in line_lower:
                m = re.search(r":\s+(.+)$", line)
                if m:
                    path = m.group(1).strip()
                    if any(ext in path.lower() for ext in [".exe", ".dll", ".bat", ".ps1", ".vbs"]):
                        suspicious, reason, confidence = _confidence_run_key(Path(path).name, path)
                        findings.append({
                            "key": "Registry\\Run (filesystem scan)",
                            "value_name": Path(path).name,
                            "data": path,
                            "suspicious": suspicious,
                            "reason": reason,
                            "confidence": confidence,
                            "mitre_technique": "T1547.001" if suspicious else None,
                            "severity": "HIGH" if suspicious else "INFO",
                        })

    suspicious_count = sum(1 for f in findings if f["suspicious"])
    return {
        "status": "OK",
        "image_path": str(fp),
        "findings": findings,
        "total_keys": len(findings),
        "suspicious_count": suspicious_count,
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def parse_registry_services(image_path: str) -> dict[str, Any]:
    """
    Extract installed Windows services from the SYSTEM registry hive.

    Uses RegRipper 'services' plugin. Flags services with executables in
    unusual locations or that mimic legitimate service names.
    Pass a filename relative to ~/lab/ or an absolute path.
    """
    t0 = time.time()
    log.info(f"[parse_registry_services] {image_path}")

    try:
        fp = _resolve(image_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    lines = _fls_lines(fp)
    findings = []

    rc, rip_out, _ = _run(["regripper", "-r", str(fp), "-p", "services"], timeout=30)
    if rc == 0 and rip_out.strip():
        current_service: dict[str, Any] = {}
        for line in rip_out.splitlines():
            if line.startswith("Service Name:") or line.startswith("ServiceName:"):
                if current_service:
                    findings.append(current_service)
                name = line.split(":", 1)[-1].strip()
                current_service = {"service_name": name, "suspicious": False}
            elif "ImagePath:" in line or "Executable:" in line:
                exe = line.split(":", 1)[-1].strip()
                current_service["executable_path"] = exe
                suspicious = _is_suspicious_path(exe)
                masq = _is_masquerading(current_service.get("service_name", ""), exe)
                if suspicious or masq:
                    current_service["suspicious"] = True
                    current_service["reason"] = (
                        "Service executable in Temp/Downloads folder" if suspicious
                        else "Service name mimics system binary"
                    )
                    current_service["confidence"] = 0.90
                    current_service["mitre_technique"] = "T1543.003"
                    current_service["severity"] = "HIGH"
                else:
                    current_service["reason"] = "Standard service location"
                    current_service["confidence"] = 0.20
            elif "Start:" in line:
                current_service["start_type"] = line.split(":", 1)[-1].strip()
        if current_service:
            findings.append(current_service)
    else:
        for line in lines:
            if "system32\\drivers\\" in line.lower() or "services" in line.lower():
                m = re.search(r":\s+(.+\.sys|.+\.exe)$", line, re.IGNORECASE)
                if m:
                    exe_path = m.group(1).strip()
                    suspicious = _is_suspicious_path(exe_path)
                    findings.append({
                        "service_name": Path(exe_path).name,
                        "executable_path": exe_path,
                        "suspicious": suspicious,
                        "reason": "Driver/service found via filesystem scan",
                        "confidence": 0.60 if suspicious else 0.15,
                        "mitre_technique": "T1543.003" if suspicious else None,
                        "severity": "MEDIUM" if suspicious else "INFO",
                    })

    suspicious_count = sum(1 for f in findings if f["suspicious"])
    return {
        "status": "OK",
        "image_path": str(fp),
        "findings": findings[:50],
        "total_services": len(findings),
        "suspicious_count": suspicious_count,
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def parse_scheduled_tasks(image_path: str) -> dict[str, Any]:
    """
    Extract Windows Scheduled Tasks from the disk image.

    Scans System32/Tasks directory via fls, then uses icat to extract
    and parse each task XML for Action, Trigger, RunAs, and Arguments.
    Flags tasks running from Temp/Downloads or using SYSTEM privileges.
    Pass a filename relative to ~/lab/ or an absolute path.
    """
    t0 = time.time()
    log.info(f"[parse_scheduled_tasks] {image_path}")

    try:
        fp = _resolve(image_path)
    except (FileNotFoundError, PermissionError) as e:
        return {"status": "ERROR", "message": str(e)}

    offset = _get_partition_offset(fp)
    lines = _fls_lines(fp)

    # fls output includes inode number before the colon: "r/r 12345-128-1: path/to/file"
    inode_re = re.compile(r"^[dr]/.\s+(\d+)(?:-\d+)*:\s+(.+)$")

    task_lines = [
        l for l in lines
        if "system32/tasks" in l.lower() or "system32\\tasks" in l.lower()
    ]

    findings = []
    for line in task_lines:
        inode_m = inode_re.match(line)
        path_m = re.search(r":\s+(.+)$", line)
        if not path_m:
            continue

        task_path = path_m.group(1).strip()
        task_name = Path(task_path).name
        inode = inode_m.group(1) if inode_m else None

        suspicious = False
        reason = "Standard scheduled task"
        confidence = 0.15
        mitre = None
        severity = "INFO"
        xml_action = None
        xml_run_as = None
        xml_trigger = None
        xml_arguments = None

        # --- icat XML extraction ---
        if inode:
            icat_cmd = ["icat"]
            if offset:
                icat_cmd += ["-o", str(offset)]
            icat_cmd += [str(fp), inode]
            rc_icat, xml_out, _ = _run(icat_cmd, timeout=10)
            if rc_icat == 0 and xml_out.strip():
                # Parse key XML fields
                action_m = re.search(r"<Command>([^<]+)</Command>", xml_out, re.IGNORECASE)
                args_m = re.search(r"<Arguments>([^<]+)</Arguments>", xml_out, re.IGNORECASE)
                run_as_m = re.search(r"<UserId>([^<]+)</UserId>", xml_out, re.IGNORECASE) or \
                           re.search(r"<RunLevel>([^<]+)</RunLevel>", xml_out, re.IGNORECASE)
                trigger_m = re.search(r"<(CalendarTrigger|TimeTrigger|LogonTrigger|BootTrigger|EventTrigger)", xml_out, re.IGNORECASE)

                xml_action = action_m.group(1).strip() if action_m else None
                xml_arguments = args_m.group(1).strip() if args_m else None
                xml_run_as = run_as_m.group(1).strip() if run_as_m else None
                xml_trigger = trigger_m.group(1).strip() if trigger_m else None

                # Override path-based heuristics with actual XML action
                if xml_action:
                    task_path = xml_action

        known_legit = [
            "googleupdate", "microsoftedgeupdate", "adobeacrobat",
            "windowsdefender", "maintainer", "diagnostics",
        ]
        is_known = any(k in task_name.lower() for k in known_legit)

        check_path = xml_action or task_path
        has_system_privs = xml_run_as and "system" in xml_run_as.lower()

        if not is_known and re.search(r"\.(ps1|bat|vbs|js|hta)$", check_path, re.IGNORECASE):
            suspicious = True
            reason = "Scheduled task runs script file"
            confidence = 0.80
            mitre = "T1053.005"
            severity = "HIGH"
        elif not is_known and _is_suspicious_path(check_path):
            suspicious = True
            reason = "Task action executable in suspicious location"
            confidence = 0.85
            mitre = "T1053.005"
            severity = "HIGH"

        if suspicious and has_system_privs:
            confidence = min(1.0, confidence + 0.10)
            reason += " (runs as SYSTEM)"
            severity = "CRITICAL"

        findings.append({
            "task_name": task_name,
            "task_path": task_path,
            "xml_action": xml_action,
            "xml_arguments": xml_arguments,
            "xml_run_as": xml_run_as,
            "xml_trigger": xml_trigger,
            "runs_as_system": has_system_privs,
            "suspicious": suspicious,
            "reason": reason,
            "confidence": confidence,
            "mitre_technique": mitre,
            "severity": severity,
        })

    suspicious_count = sum(1 for f in findings if f["suspicious"])
    return {
        "status": "OK",
        "image_path": str(fp),
        "findings": findings[:50],
        "total_tasks": len(findings),
        "suspicious_count": suspicious_count,
        "note": "XML fields (action/trigger/run_as) extracted via icat where inode available",
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def analyze_startup_folders(image_path: str) -> dict[str, Any]:
    """
    List files in Windows Startup folders.

    Checks user and system startup folders for unexpected executables
    or shortcut files (.lnk) pointing to malicious targets.
    Pass a filename relative to ~/lab/ or an absolute path.
    """
    t0 = time.time()
    log.info(f"[analyze_startup_folders] {image_path}")

    try:
        fp = _resolve(image_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    lines = _fls_lines(fp)

    startup_lines = [
        l for l in lines
        if "startup" in l.lower() and re.search(r":\s+.+\.(lnk|exe|bat|ps1|vbs|js|hta)$", l, re.IGNORECASE)
    ]

    findings = []
    for line in startup_lines:
        m = re.search(r":\s+(.+)$", line)
        if not m:
            continue
        file_path = m.group(1).strip()
        ext = Path(file_path).suffix.lower()

        is_lnk = ext == ".lnk"
        is_exe = ext in {".exe", ".bat", ".ps1", ".vbs", ".js", ".hta"}
        suspicious = is_exe or (is_lnk and _is_suspicious_path(file_path))

        findings.append({
            "location": str(Path(file_path).parent),
            "filename": Path(file_path).name,
            "full_path": file_path,
            "file_type": ext,
            "suspicious": suspicious,
            "reason": (
                "Executable in startup folder" if is_exe
                else "Shortcut pointing to suspicious location" if suspicious
                else "Shortcut file — target unknown without extraction"
            ),
            "confidence": 0.85 if is_exe else 0.70 if suspicious else 0.55,
            "mitre_technique": "T1547.009" if suspicious else None,
            "severity": "HIGH" if is_exe else "MEDIUM" if suspicious else "LOW",
        })

    suspicious_count = sum(1 for f in findings if f["suspicious"])
    return {
        "status": "OK",
        "image_path": str(fp),
        "findings": findings,
        "total_startup_items": len(findings),
        "suspicious_count": suspicious_count,
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def parse_prefetch(image_path: str, exe_name: str) -> dict[str, Any]:
    """
    Validate whether a suspicious executable actually ran via Prefetch files.

    Searches the Windows Prefetch directory for a .pf file matching the
    given executable name. Confirms execution and provides run count.

    Args:
        image_path: Path to disk image (relative to ~/lab/ or absolute)
        exe_name:   Executable filename to search for (e.g. 'svchost.exe')
    """
    t0 = time.time()
    log.info(f"[parse_prefetch] {image_path} / {exe_name}")

    try:
        fp = _resolve(image_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    lines = _fls_lines(fp)

    exe_base = Path(exe_name).stem.upper()
    pf_lines = [
        l for l in lines
        if "prefetch" in l.lower() and exe_base in l.upper() and l.upper().endswith(".PF")
    ]

    if not pf_lines:
        return {
            "status": "NOT_FOUND",
            "executable": exe_name,
            "image_path": str(fp),
            "execution_confirmed": False,
            "note": f"No Prefetch file found for {exe_name}. May not have run, or Prefetch is disabled.",
            "confidence_impact": -0.05,
            "duration_ms": round((time.time() - t0) * 1000),
        }

    pf_file = re.search(r":\s+(.+\.pf)$", pf_lines[0], re.IGNORECASE)
    pf_filename = pf_file.group(1).strip() if pf_file else pf_lines[0]

    rc, pecmd_out, _ = _run(["PECmd.exe", "-f", str(fp), "--csv", "/tmp"], timeout=30)
    run_count = 1
    first_run = "Unknown"
    last_run = "Unknown"
    files_accessed: list[str] = []

    if rc == 0 and pecmd_out:
        for line in pecmd_out.splitlines():
            if "Run count" in line:
                m = re.search(r"(\d+)", line)
                if m:
                    run_count = int(m.group(1))
            elif "Last run" in line or "Run time" in line:
                last_run = line.split(":", 1)[-1].strip()
            elif exe_base in line.upper() and "Files loaded" in pecmd_out:
                files_accessed.append(line.strip())

    suspicious_files = [f for f in files_accessed if _is_suspicious_path(f)]

    return {
        "status": "FOUND",
        "executable": exe_name,
        "prefetch_file": Path(pf_filename).name,
        "image_path": str(fp),
        "execution_confirmed": True,
        "first_run": first_run,
        "last_run": last_run,
        "run_count": run_count,
        "files_accessed": files_accessed[:20],
        "suspicious_files_accessed": suspicious_files,
        "confidence_impact": 0.10,
        "note": "Execution confirmed — increases confidence in associated persistence findings",
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def analyze_wmi_subscriptions(image_path: str) -> dict[str, Any]:
    """
    Detect WMI Event Subscription persistence (T1546.003).

    Extracts the WMI repository (OBJECTS.DATA) via fls/icat and uses
    strings to identify EventFilter, EventConsumer, and FilterToConsumerBinding
    objects that indicate malicious WMI subscriptions.
    Pass a filename relative to ~/lab/ or an absolute path.
    """
    t0 = time.time()
    log.info(f"[analyze_wmi_subscriptions] {image_path}")

    try:
        fp = _resolve(image_path)
    except (FileNotFoundError, PermissionError) as e:
        return {"status": "ERROR", "message": str(e)}

    offset = _get_partition_offset(fp)
    lines = _fls_lines(fp)

    # Locate WMI repository files
    wmi_repo_patterns = ["objects.data", "index.btr", "mapping1.map"]
    wmi_lines = [
        l for l in lines
        if any(p in l.lower() for p in wmi_repo_patterns)
        and "wbem" in l.lower()
    ]

    findings: list[dict[str, Any]] = []
    wmi_strings_output = ""

    # Extract strings from WMI repository via icat (preferred) or direct strings
    inode_re = re.compile(r"^[dr]/.\s+(\d+)(?:-\d+)*:\s+(.+)$")
    for wmi_line in wmi_lines[:3]:
        inode_m = inode_re.match(wmi_line)
        if inode_m:
            icat_cmd = ["icat"]
            if offset:
                icat_cmd += ["-o", str(offset)]
            icat_cmd += [str(fp), inode_m.group(1)]
            rc_icat, icat_out, _ = _run(icat_cmd, timeout=20)
            if rc_icat == 0 and icat_out:
                rc_str, str_out, _ = _run(["strings", "-n", "8"], timeout=15)
                # pipe icat -> strings inline
                try:
                    proc = __import__("subprocess").Popen(
                        ["strings", "-n", "8"],
                        stdin=__import__("subprocess").PIPE,
                        stdout=__import__("subprocess").PIPE,
                        stderr=__import__("subprocess").DEVNULL,
                    )
                    str_out_bytes, _ = proc.communicate(input=icat_out.encode(errors="replace"), timeout=15)
                    wmi_strings_output += str_out_bytes.decode(errors="replace")
                except Exception:
                    wmi_strings_output += icat_out

    # Fallback: run strings directly on the image (slower)
    if not wmi_strings_output:
        rc_s, wmi_strings_output, _ = _run(["strings", "-n", "8", str(fp)], timeout=30)

    # Detect WMI persistence indicators in strings output
    KNOWN_LEGIT_CONSUMERS = {
        "BVTConsumer", "SCM Event Log Consumer", "NTEventLogEventConsumer",
    }

    SUSPICIOUS_CONSUMER_PATTERNS = [
        (r"CommandLineEventConsumer", "CommandLineEventConsumer — executes arbitrary commands", 0.90),
        (r"ActiveScriptEventConsumer", "ActiveScriptEventConsumer — runs VBScript/JScript", 0.95),
        (r"CommandLineTemplate\s*=\s*[\"']([^\"']{10,})[\"']", "Command template in WMI consumer", 0.85),
        (r"ScriptText\s*=\s*[\"']([^\"']{10,})[\"']", "Script embedded in WMI consumer", 0.95),
        (r"SELECT.*FROM.*Win32_ProcessStartTrace", "Process creation event filter", 0.75),
        (r"SELECT.*FROM.*__InstanceModificationEvent.*TargetInstance.*Win32_LocalTime",
         "Timer-based WMI event filter (persistence timer)", 0.85),
    ]

    for pattern, description, confidence in SUSPICIOUS_CONSUMER_PATTERNS:
        matches = re.findall(pattern, wmi_strings_output, re.IGNORECASE | re.DOTALL)
        if matches:
            sample = matches[0] if isinstance(matches[0], str) else str(matches[0])
            # Skip known-legitimate consumers
            if any(legit.lower() in sample.lower() for legit in KNOWN_LEGIT_CONSUMERS):
                continue
            findings.append({
                "indicator": pattern.split("(")[0].strip(),
                "description": description,
                "sample_value": sample[:300],
                "match_count": len(matches),
                "suspicious": True,
                "reason": f"WMI persistence indicator: {description}",
                "confidence": confidence,
                "mitre_technique": "T1546.003",
                "severity": "HIGH" if confidence < 0.90 else "CRITICAL",
            })

    # Check for FilterToConsumerBinding (links filter to consumer — completes the triad)
    binding_count = len(re.findall(r"FilterToConsumerBinding", wmi_strings_output, re.IGNORECASE))
    if binding_count > 0:
        findings.append({
            "indicator": "FilterToConsumerBinding",
            "description": "WMI subscription binding found — filter linked to consumer (persistence triad complete)",
            "match_count": binding_count,
            "suspicious": True,
            "reason": "Complete WMI subscription triad detected (Filter + Consumer + Binding)",
            "confidence": 0.95,
            "mitre_technique": "T1546.003",
            "severity": "CRITICAL",
        })

    suspicious_count = sum(1 for f in findings if f["suspicious"])
    return {
        "status": "OK" if wmi_lines else "WARNING",
        "image_path": str(fp),
        "wmi_repository_files_found": len(wmi_lines),
        "findings": findings,
        "total_indicators": len(findings),
        "suspicious_count": suspicious_count,
        "note": (
            "WMI repository parsed via strings. Use python-wmi-forensics or "
            "wbemtest for interactive analysis."
            if wmi_lines else
            "WMI repository (wbem/objects.data) not found in fls output — "
            "may be stored in alternate location or image type."
        ),
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def detect_dll_hijacking(image_path: str) -> dict[str, Any]:
    """
    Detect DLL Search Order Hijacking persistence (T1574.001).

    Scans the disk image for DLLs placed in locations that take precedence
    over the legitimate system DLL location. Checks:
      - Application directories containing DLLs with system DLL names
      - Writable directories earlier in the DLL search order
      - Known vulnerable application paths
    Pass a filename relative to ~/lab/ or an absolute path.
    """
    t0 = time.time()
    log.info(f"[detect_dll_hijacking] {image_path}")

    try:
        fp = _resolve(image_path)
    except (FileNotFoundError, PermissionError) as e:
        return {"status": "ERROR", "message": str(e)}

    lines = _fls_lines(fp)

    # System DLL names commonly targeted for hijacking
    HIJACKABLE_DLLS = {
        "version.dll", "dwmapi.dll", "uxtheme.dll", "cryptbase.dll",
        "cryptsp.dll", "wtsapi32.dll", "profapi.dll", "wbemcomn.dll",
        "linkinfo.dll", "ntshrui.dll", "apphelp.dll", "ntmarta.dll",
        "netutils.dll", "srvcli.dll", "wkscli.dll", "msasn1.dll",
        "userenv.dll", "gpapi.dll", "mpr.dll",
    }

    SYSTEM_DLL_PATHS = [
        "\\windows\\system32\\",
        "\\windows\\syswow64\\",
        "\\windows\\system\\",
    ]

    # Paths where hijacking DLLs are commonly planted
    HIJACK_STAGING_PATHS = [
        "\\program files\\",
        "\\program files (x86)\\",
        "\\users\\public\\",
        "\\appdata\\local\\",
        "\\appdata\\roaming\\",
        "\\temp\\",
        "\\downloads\\",
    ]

    findings: list[dict[str, Any]] = []
    seen_dlls: set[str] = set()

    for line in lines:
        path_m = re.search(r":\s+(.+\.dll)$", line, re.IGNORECASE)
        if not path_m:
            continue
        dll_path = path_m.group(1).strip()
        dll_name = Path(dll_path).name.lower()

        if dll_name not in HIJACKABLE_DLLS:
            continue

        dll_path_lower = dll_path.lower()

        # Skip DLLs in their legitimate system locations
        if any(sys_path in dll_path_lower for sys_path in SYSTEM_DLL_PATHS):
            continue

        # DLL with a system name found outside system32 — suspicious
        if dll_name in seen_dlls:
            continue
        seen_dlls.add(dll_name)

        is_staging = any(p in dll_path_lower for p in HIJACK_STAGING_PATHS)
        in_app_dir = "\\program files" in dll_path_lower

        confidence = 0.90 if is_staging else 0.75 if in_app_dir else 0.65
        severity = "HIGH" if is_staging else "MEDIUM"
        reason = (
            f"System DLL '{dll_name}' found in staging location — classic hijack placement"
            if is_staging else
            f"System DLL '{dll_name}' found in application directory — possible DLL hijack"
            if in_app_dir else
            f"System DLL '{dll_name}' found outside System32"
        )

        findings.append({
            "dll_name": dll_name,
            "dll_path": dll_path,
            "in_staging_location": is_staging,
            "in_application_dir": in_app_dir,
            "suspicious": True,
            "reason": reason,
            "confidence": confidence,
            "mitre_technique": "T1574.001",
            "severity": severity,
            "note": (
                f"Legitimate {dll_name} should be in System32. "
                "Presence elsewhere may indicate hijacking."
            ),
        })

    suspicious_count = len(findings)
    return {
        "status": "OK",
        "image_path": str(fp),
        "findings": findings[:50],
        "total_suspicious_dlls": suspicious_count,
        "suspicious_count": suspicious_count,
        "checked_dll_names": sorted(HIJACKABLE_DLLS),
        "note": (
            "Checks for system DLL names outside System32. "
            "Cross-reference with Registry Run keys and process list for confirmation."
        ),
        "duration_ms": round((time.time() - t0) * 1000),
    }


if __name__ == "__main__":
    log.info("-" * 60)
    log.info("Persistence MCP Server (FastMCP) starting")
    log.info(f"  Lab dir : {LAB_DIR}")
    log.info(f"  Logs    : {LOG_DIR}")
    log.info("-" * 60)
    mcp.run()
